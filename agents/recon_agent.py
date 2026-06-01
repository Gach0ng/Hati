"""
Hati - Recon Agent (信息收集)
负责渗透测试前期的信息收集工作
"""

import json
import httpx
from typing import Dict, Any, Optional
from datetime import datetime

from state.pentest_state import PentestState, PentestPhase, TaskState, add_agent_message
from state.progress_tracker import get_progress_tracker
from config.minimax_config import get_llm, get_system_prompt
from security.audit_logger import AuditLogger


# ===========================================
# HexStrike API 客户端
# ===========================================
class HexStrikeClient:
    """HexStrike API 客户端封装"""

    def __init__(self, base_url: str = None):
        import os
        self.base_url = base_url or os.getenv("HEXSTRIKE_SERVER_URL", "http://localhost:9999")
        self.timeout = 60  # 60秒，masscan全端口扫描需要更长时间

    def execute_command(self, command: str, category: str = "essential") -> Dict[str, Any]:
        """
        执行 HexStrike 命令

        Args:
            command: 命令
            category: 工具类别

        Returns:
            执行结果
        """
        import requests

        try:
            response = requests.post(
                f"{self.base_url}/api/command",
                json={"command": command, "category": category},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": str(e),
            }

    def analyze_target(self, target: str, analysis_type: str = "quick") -> Dict[str, Any]:
        """
        分析目标

        Args:
            target: 目标
            analysis_type: 分析类型

        Returns:
            分析结果
        """
        import requests

        try:
            response = requests.post(
                f"{self.base_url}/api/intelligence/analyze-target",
                json={"target": target, "analysis_type": analysis_type},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}


# ===========================================
# Recon Agent
# ===========================================
class ReconAgent:
    """
    信息收集 Agent

    职责：
    - 目标基础信息收集
    - 子域名发现
    - 端口扫描
    - 服务识别
    - 技术栈检测
    """

    def __init__(
        self,
        hexstrike_url: str = None,
        audit_logger: AuditLogger = None,
    ):
        import os
        self.hexstrike = HexStrikeClient(hexstrike_url or os.getenv("HEXSTRIKE_SERVER_URL"))
        self.audit_logger = audit_logger
        self.progress_tracker = get_progress_tracker()

    def run(self, state: PentestState) -> PentestState:
        """
        执行信息收集

        Args:
            state: 当前状态

        Returns:
            更新后的状态
        """
        target = state["target"]
        task_id = state["task_id"]

        print(f"[ReconAgent] 开始信息收集: {target}")

        # 初始化进度追踪
        self.progress_tracker.update_phase(
            task_id, "recon", "初始化",
            f"开始信息收集目标 {target}",
            reasoning=f"用户需要对 {target} 进行信息收集，我将依次调用：目标分析、nmap主机发现、端口扫描、HTTP探测等工具",
            tool="HexStrike API"
        )

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="ReconAgent",
                action="start_recon",
                task_id=task_id,
                target=target,
            )

        # 执行信息收集
        result = {
            "hosts": [],
            "subdomains": [],
            "open_ports": {},
            "technologies": {},
            "screenshots": [],
            "fingerprints": {},
            "raw_output": {},
        }

        # 1. 基础目标分析
        print(f"[ReconAgent] 分析目标: {target}")
        self.progress_tracker.update_phase(
            task_id, "recon", "目标分析",
            "正在分析目标基础信息...",
            reasoning=f"首先调用目标分析API获取 {target} 的基础信息，包括IP、域名、DNS记录等",
            tool="HexStrike.analyze_target",
            command=f"analyze_target(target={target})"
        )
        analysis = self.hexstrike.analyze_target(target, "quick")
        if analysis.get("success"):
            profile = analysis.get("target_profile", {})
            result["fingerprints"]["basic"] = profile
            self.progress_tracker.add_finding(task_id, "analysis", profile)

        # 2. Nmap 主机发现
        print(f"[ReconAgent] 端口扫描: {target}")
        self.progress_tracker.update_phase(
            task_id, "recon", "nmap主机发现",
            f"正在扫描 {target} 的主机...",
            reasoning="使用nmap进行主机发现，探测21-23,80,443,8080,8443端口判断主机是否存活",
            tool="nmap",
            command=f"nmap -sn -PS21-23,80,443,8080,8443 {target}"
        )
        nmap_result = self.hexstrike.execute_command(
            f"nmap -sn -PS21-23,80,443,8080,8443 {target}",
            category="network"
        )
        if nmap_result.get("success"):
            output = nmap_result.get("stdout", "")
            result["raw_output"]["nmap_ping"] = output
            self.progress_tracker.add_finding(task_id, "nmap_ping", output[:500])
            self.progress_tracker.update_phase(
                task_id, "recon", "nmap主机发现",
                f"主机发现完成: {output[:100]}",
                reasoning="主机发现完成，判断目标存活状态"
            )

        # 3. 快速端口扫描
        print(f"[ReconAgent] 快速端口扫描")
        self.progress_tracker.update_phase(
            task_id, "recon", "nmap端口扫描",
            "正在扫描端口...",
            reasoning="使用nmap进行端口扫描，-F表示快速扫描常见端口，-sV探测服务版本",
            tool="nmap",
            command=f"nmap -F -sV --version-intensity 5 {target}"
        )
        port_result = self.hexstrike.execute_command(
            f"nmap -F -sV --version-intensity 5 {target}",
            category="network"
        )
        if port_result.get("success"):
            output = port_result.get("stdout", "")
            result["raw_output"]["nmap_ports"] = output
            # 解析端口信息
            ports = []
            for line in output.split("\n"):
                if "/tcp" in line and "open" in line:
                    ports.append(line.strip())
            self.progress_tracker.add_finding(task_id, "ports", ports)
            self.progress_tracker.update_phase(
                task_id, "recon", "nmap端口扫描",
                f"端口扫描完成: 发现 {len(ports)} 个开放端口",
                reasoning=f"端口扫描完成，发现 {len(ports)} 个开放端口，将进入漏洞扫描阶段"
            )

        # 4. HTTP 检测
        print(f"[ReconAgent] HTTP 服务检测")
        self.progress_tracker.update_phase(
            task_id, "recon", "httpx探测",
            "正在探测HTTP服务...",
            reasoning="使用httpx探测HTTP服务，获取网站标题、技术栈指纹等信息",
            tool="httpx",
            command=f"httpx -title -tech-detect -u http://{target}"
        )
        http_result = self.hexstrike.execute_command(
            f"httpx -title -tech-detect -u http://{target}",
            category="web_security"
        )
        if http_result.get("success"):
            output = http_result.get("stdout", "")
            result["raw_output"]["httpx"] = output
            self.progress_tracker.add_finding(task_id, "httpx", output[:500])
            self.progress_tracker.update_phase(
                task_id, "recon", "httpx探测",
                f"HTTP探测完成: {output[:100]}",
                reasoning="HTTP探测完成，获取到网站标题和技术栈信息"
            )

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="ReconAgent",
                action="recon_complete",
                task_id=task_id,
                target=target,
                result_summary=f"发现 {len(result.get('subdomains', []))} 个子域名",
            )

        # 标记阶段完成
        self.progress_tracker.complete_phase(task_id, "recon", f"信息收集完成")

        # 添加 Agent 消息
        state = add_agent_message(
            state=state,
            from_agent="ReconAgent",
            to_agent="Orchestrator",
            action="reconnaissance",
            reasoning="完成目标信息收集",
            result=result,
            status="success",
        )

        # 更新状态
        from state.pentest_state import update_state, advance_phase

        state = update_state(
            state,
            recon_result=result,
            status=TaskState.SUCCESS,
        )
        state = advance_phase(state, PentestPhase.RECON)

        print(f"[ReconAgent] 信息收集完成")

        return state


# ===========================================
# Celery Task
# ===========================================
from config.celery_config import celery_app


@celery_app.task(name="agents.recon_agent.run", queue="recon")
def run_recon(task_id: str, target: str, scope: list) -> dict:
    """
    Celery Task: 执行信息收集

    Args:
        task_id: 任务 ID
        target: 目标
        scope: 授权范围

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

    # 执行 Recon Agent
    agent = ReconAgent()
    result_state = agent.run(state)

    return {
        "task_id": task_id,
        "status": result_state["status"],
        "recon_result": result_state["recon_result"],
    }
