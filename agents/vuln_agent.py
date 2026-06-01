"""
Hati - Vuln Agent (漏洞扫描)
负责漏洞检测和 CVE 知识库查询
"""

import json
from typing import Dict, Any, Optional
from datetime import datetime

from state.pentest_state import PentestState, PentestPhase, TaskState, add_agent_message
from state.progress_tracker import get_progress_tracker
from config.minimax_config import get_llm, get_system_prompt
from security.audit_logger import AuditLogger
from agents.recon_agent import HexStrikeClient
from rag.vector_store import get_vector_store


# ===========================================
# Vuln Agent
# ===========================================
class VulnAgent:
    """
    漏洞扫描 Agent

    职责：
    - 基于信息收集结果进行漏洞检测
    - 使用 nuclei/nikto/sqlmap 等工具扫描
    - 查询 CVE 知识库获取漏洞详情
    - 评估漏洞风险等级
    """

    def __init__(
        self,
        hexstrike_url: str = None,
        audit_logger: AuditLogger = None,
    ):
        import os
        self.hexstrike = HexStrikeClient(hexstrike_url or os.getenv("HEXSTRIKE_SERVER_URL"))
        self.audit_logger = audit_logger
        self.vector_store = get_vector_store()
        self.llm = get_llm()
        self.progress_tracker = get_progress_tracker()

    def run(self, state: PentestState) -> PentestState:
        """
        执行漏洞扫描

        Args:
            state: 当前状态

        Returns:
            更新后的状态
        """
        target = state["target"]
        recon_result = state.get("recon_result")
        task_id = state["task_id"]

        print(f"[VulnAgent] 开始漏洞扫描: {target}")

        # 初始化进度追踪
        self.progress_tracker.update_phase(
            task_id, "vuln_scan", "初始化",
            f"开始漏洞扫描目标 {target}",
            reasoning=f"基于信息收集结果，我将对 {target} 进行漏洞扫描。首先使用Nuclei进行已知漏洞扫描，然后使用Nikto进行Web服务器扫描，最后联动PoC知识库进行漏洞匹配",
            tool="VulnAgent"
        )

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="VulnAgent",
                action="start_vuln_scan",
                task_id=task_id,
                target=target,
            )

        vulnerabilities = []
        scan_summary = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # 1. Nuclei 漏洞扫描
        print(f"[VulnAgent] 执行 Nuclei 扫描")
        self.progress_tracker.update_phase(
            task_id, "vuln_scan", "nuclei扫描",
            "正在调用 Nuclei 扫描漏洞...",
            reasoning="Nuclei是强大的漏洞扫描工具，使用已知PoC库对目标进行匹配扫描，重点扫描critical、high、medium级别漏洞",
            tool="nuclei",
            command=f"nuclei -u http://{target} -severity critical,high,medium -quiet -no-color"
        )
        nuclei_result = self.hexstrike.execute_command(
            f"nuclei -u http://{target} -severity critical,high,medium -quiet -no-color",
            category="vuln_scanning"
        )
        if nuclei_result.get("success"):
            nuclei_output = nuclei_result.get("stdout", "")
            # 解析 Nuclei 输出
            parsed = self._parse_nuclei_output(nuclei_output)
            vulnerabilities.extend(parsed)
            self.progress_tracker.add_finding(task_id, "nuclei_vulns", len(parsed))
            self.progress_tracker.update_phase(
                task_id, "vuln_scan", "nuclei扫描",
                f"Nuclei扫描完成: 发现 {len(parsed)} 个问题",
                reasoning=f"Nuclei扫描发现 {len(parsed)} 个潜在漏洞，将继续使用Nikto进行Web服务器扫描"
            )

        # 2. Nikto Web 服务器扫描
        print(f"[VulnAgent] 执行 Nikto 扫描")
        self.progress_tracker.update_phase(
            task_id, "vuln_scan", "nikto扫描",
            "正在调用 Nikto 扫描...",
            reasoning="Nikto是经典的Web服务器扫描工具，可以发现服务器配置问题、过期版本、潜在危险文件等",
            tool="nikto",
            command=f"nikto -h http://{target} -Format txt -nointeractive"
        )
        nikto_result = self.hexstrike.execute_command(
            f"nikto -h http://{target} -Format txt -nointeractive",
            category="web_security"
        )
        if nikto_result.get("success"):
            nikto_output = nikto_result.get("stdout", "")
            # 解析 Nikto 输出
            parsed = self._parse_nikto_output(nikto_output)
            vulnerabilities.extend(parsed)
            self.progress_tracker.add_finding(task_id, "nikto_vulns", len(parsed))
            self.progress_tracker.update_phase(
                task_id, "vuln_scan", "nikto扫描",
                f"Nikto扫描完成: 发现 {len(parsed)} 个问题",
                reasoning=f"Nikto扫描发现 {len(parsed)} 个问题，现在联动PoC知识库进行漏洞匹配"
            )

        # 3. 查询 PoC 知识库 (RAG)
        print(f"[VulnAgent] 查询 PoC 知识库")
        self.progress_tracker.update_phase(
            task_id, "vuln_scan", "PoC知识库查询",
            "正在查询PoC知识库...",
            reasoning="联动RAG知识库，根据识别到的技术栈查询相关的漏洞PoC和利用代码",
            tool="ChromaDB RAG"
        )
        technologies = []
        if recon_result and recon_result.get("technologies"):
            technologies = list(recon_result.get("technologies", {}).values())[0] if recon_result.get("technologies") else []

        cve_count = 0
        rag_results = []
        if technologies:
            for tech in technologies[:5]:  # 限制查询数量
                cves = self.vector_store.query_by_product(tech, n_results=5)
                rag_results.append({"tech": tech, "cves": cves})
                for cve in cves:
                    vuln = self._cve_to_vulnerability(cve, target)
                    vulnerabilities.append(vuln)
                    cve_count += 1
        self.progress_tracker.add_rag_result(task_id, f"技术栈: {technologies}", rag_results)
        self.progress_tracker.update_phase(
            task_id, "vuln_scan", "PoC知识库查询",
            f"PoC查询完成: 发现 {cve_count} 条相关漏洞信息",
            reasoning=f"PoC知识库查询完成，发现 {cve_count} 条相关漏洞信息，综合扫描结果生成漏洞报告"
        )

        # 更新扫描摘要
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in scan_summary:
                scan_summary[severity] += 1
            scan_summary["total"] += 1

        # 更新进度追踪
        self.progress_tracker.add_finding(task_id, "vulnerabilities", vulnerabilities)
        self.progress_tracker.complete_phase(task_id, "vuln_scan", f"漏洞扫描完成: 总计 {scan_summary['total']} 个漏洞")

        result = {
            "vulnerabilities": vulnerabilities,
            "scan_summary": scan_summary,
            "raw_output": {
                "nuclei": nuclei_result.get("stdout", ""),
                "nikto": nikto_result.get("stdout", ""),
            },
        }

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="VulnAgent",
                action="vuln_scan_complete",
                task_id=task_id,
                target=target,
                result_summary=f"发现 {scan_summary['total']} 个漏洞 (critical: {scan_summary['critical']})",
            )

        # 添加 Agent 消息
        state = add_agent_message(
            state=state,
            from_agent="VulnAgent",
            to_agent="Orchestrator",
            action="vulnerability_scan",
            reasoning=f"完成漏洞扫描，发现 {scan_summary['total']} 个漏洞",
            result=result,
            status="success",
        )

        # 更新状态
        from state.pentest_state import update_state, advance_phase

        state = update_state(
            state,
            vuln_result=result,
            status=TaskState.SUCCESS,
        )
        state = advance_phase(state, PentestPhase.VULN_SCAN)

        print(f"[VulnAgent] 漏洞扫描完成: {scan_summary['total']} 个漏洞")

        return state

    def _parse_nuclei_output(self, output: str) -> list:
        """解析 Nuclei 输出"""
        vulnerabilities = []
        for line in output.split("\n"):
            if not line.strip():
                continue
            # Nuclei 输出格式: [type] [severity] [name] [url]
            if "[" in line:
                parts = line.split("]")
                if len(parts) >= 3:
                    vuln = {
                        "id": f"nuclei-{len(vulnerabilities)}",
                        "cve_id": None,
                        "name": parts[2].strip() if len(parts) > 2 else "Unknown",
                        "severity": parts[1].strip() if len(parts) > 1 else "info",
                        "cvss_score": None,
                        "description": line,
                        "target": "",
                        "url": parts[-1].strip() if parts else "",
                        "evidence": {"source": "nuclei", "raw": line},
                        "poc_path": None,
                        "status": "potential",
                    }
                    vulnerabilities.append(vuln)
        return vulnerabilities

    def _parse_nikto_output(self, output: str) -> list:
        """解析 Nikto 输出"""
        vulnerabilities = []
        for line in output.split("\n"):
            if "+ " in line and ("vulnerability" in line.lower() or "issue" in line.lower()):
                vuln = {
                    "id": f"nikto-{len(vulnerabilities)}",
                    "cve_id": None,
                    "name": line.split("+ ")[-1][:100],
                    "severity": "medium",
                    "cvss_score": None,
                    "description": line,
                    "target": "",
                    "url": "",
                    "evidence": {"source": "nikto", "raw": line},
                    "poc_path": None,
                    "status": "potential",
                }
                vulnerabilities.append(vuln)
        return vulnerabilities

    def _cve_to_vulnerability(self, cve: dict, target: str) -> dict:
        """将 CVE 转换为漏洞格式"""
        metadata = cve.get("metadata", {})
        return {
            "id": f"cve-{metadata.get('cve_id', 'unknown')}",
            "cve_id": metadata.get("cve_id"),
            "name": metadata.get("cve_id", "Unknown"),
            "severity": metadata.get("severity", "unknown"),
            "cvss_score": metadata.get("cvss_score"),
            "description": cve.get("description", ""),
            "target": target,
            "url": None,
            "evidence": {"source": "cve_kb", "similarity": cve.get("similarity")},
            "poc_path": metadata.get("poc_path"),
            "status": "potential",
        }


# ===========================================
# Celery Task
# ===========================================
from config.celery_config import celery_app


@celery_app.task(name="agents.vuln_agent.run", queue="vuln")
def run_vuln_scan(task_id: str, target: str, scope: list, recon_result: dict) -> dict:
    """
    Celery Task: 执行漏洞扫描

    Args:
        task_id: 任务 ID
        target: 目标
        scope: 授权范围
        recon_result: 信息收集结果

    Returns:
        执行结果
    """
    from state.pentest_state import create_initial_state

    # 创建初始状态
    state = create_initial_state(
        task_id=task_id,
        target=target,
        scope=scope,
        authorized_by="system",
    )
    state["recon_result"] = recon_result

    # 执行 Vuln Agent
    agent = VulnAgent()
    result_state = agent.run(state)

    return {
        "task_id": task_id,
        "status": result_state["status"],
        "vuln_result": result_state["vuln_result"],
    }
