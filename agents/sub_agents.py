"""
Hati - 子智能体架构
独立执行子任务，减少主上下文污染

子智能体特点：
- 独立系统 Prompt（简洁）
- 只返回结构化报告（1-2k token）
- 不污染主上下文
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime


# ===========================================
# 子智能体结果结构
# ===========================================
@dataclass
class SubAgentResult:
    """子智能体返回结果"""
    agent_type: str
    target: str
    status: str  # success/failed/partial
    findings: Dict[str, Any]
    summary: str  # 1-2k token 的结构化摘要
    tokens_used: int = 0


# ===========================================
# 子智能体基类
# ===========================================
class BaseSubAgent:
    """子智能体基类"""

    SYSTEM_PROMPT = """你是一个专业的安全测试子智能体。
专注于特定任务，返回结构化结果。"""

    def __init__(self, llm=None):
        from config.minimax_config import get_llm
        self.llm = llm or get_llm()

    def run(self, target: str, **kwargs) -> SubAgentResult:
        """
        执行子智能体任务

        Returns:
            SubAgentResult 结构化结果
        """
        raise NotImplementedError

    def build_prompt(self, target: str, **kwargs) -> str:
        """构建执行提示"""
        raise NotImplementedError

    def parse_result(self, response: str) -> Dict[str, Any]:
        """解析 LLM 响应"""
        raise NotImplementedError


# ===========================================
# Recon 子智能体
# ===========================================
class ReconSubAgent(BaseSubAgent):
    """
    信息收集子智能体

    独立执行：
    - 子域名枚举
    - 端口扫描
    - 指纹识别

    返回结构化报告，不污染主上下文
    """

    SYSTEM_PROMPT = """你是一个专业的网络侦查子智能体。

职责：
1. 子域名发现与枚举
2. 端口扫描与服务识别
3. 技术栈指纹识别

输出格式（必须严格遵循）：
{
    "hosts": [{"ip": "", "hostname": "", "os": ""}],
    "open_ports": [{"port": 80, "service": "http", "version": "Apache/2.4.41"}],
    "subdomains": ["sub.example.com"],
    "technologies": ["Apache", "PHP"],
    "vulnerabilities": [],
    "summary": "发现X个主机，Y个端口，Z个技术栈"
}
"""

    def run(self, target: str, **kwargs) -> SubAgentResult:
        """
        执行信息收集

        Args:
            target: 目标 URL 或域名

        Returns:
            SubAgentResult
        """
        from tools.langchain_adapter import get_hexstrike_client
        from state.progress_tracker import get_progress_tracker

        client = get_hexstrike_client()
        tracker = get_progress_tracker()

        findings = {
            "hosts": [],
            "open_ports": [],
            "subdomains": [],
            "technologies": [],
            "vulnerabilities": []
        }

        # 1. 子域名枚举
        domain = self._extract_domain(target)
        if domain:
            print(f"[ReconSubAgent] 枚举子域名: {domain}")
            result = client.execute_command(
                f"subfinder -d {domain} -silent",
                category="network"
            )
            if result.get("success"):
                subdomains = result.get("stdout", "").strip().split("\n")
                findings["subdomains"] = [s for s in subdomains if s]

        # 2. 端口扫描
        print(f"[ReconSubAgent] 扫描端口: {target}")
        result = client.execute_command(
            f"nmap -sV -Pn -T4 -F {target}",
            category="network"
        )
        if result.get("success"):
            output = result.get("stdout", "")
            findings["open_ports"] = self._parse_ports(output)

        # 3. 指纹识别
        if findings["open_ports"]:
            print(f"[ReconSubAgent] 识别指纹")
            tech_stack = list(set(p.get("service", "") for p in findings["open_ports"]))
            findings["technologies"] = [t for t in tech_stack if t]

        # 生成摘要
        summary = self._generate_summary(findings)

        # 更新进度
        task_id = kwargs.get("task_id")
        if task_id:
            tracker.update_phase(
                task_id, "recon",
                f"子智能体完成: {summary}",
                details=summary
            )

        return SubAgentResult(
            agent_type="recon",
            target=target,
            status="success",
            findings=findings,
            summary=summary
        )

    def _extract_domain(self, target: str) -> Optional[str]:
        """提取域名"""
        import re
        # 从 URL 提取域名
        match = re.search(r'https?://([^/]+)', target)
        if match:
            domain = match.group(1)
            # 去除端口
            domain = domain.split(":")[0]
            return domain
        return target if "." in target else None

    def _parse_ports(self, output: str) -> List[Dict[str, Any]]:
        """解析端口扫描结果"""
        import re
        ports = []

        for line in output.split("\n"):
            match = re.search(r'(\d+)/(tcp|udp)\s+(open|closed)\s+(\S+)', line)
            if match:
                port, proto, state, service = match.groups()
                ports.append({
                    "port": int(port),
                    "protocol": proto,
                    "state": state,
                    "service": service
                })

        return ports

    def _generate_summary(self, findings: Dict[str, Any]) -> str:
        """生成摘要"""
        return (
            f"发现 {len(findings['subdomains'])} 个子域名，"
            f"{len(findings['open_ports'])} 个开放端口，"
            f"{len(findings['technologies'])} 种技术栈"
        )


# ===========================================
# Vuln Scan 子智能体
# ===========================================
class VulnScanSubAgent(BaseSubAgent):
    """
    漏洞扫描子智能体

    独立执行：
    - Nuclei CVE 扫描
    - 漏洞验证

    返回结构化报告
    """

    SYSTEM_PROMPT = """你是一个专业的漏洞扫描子智能体。

职责：
1. 基于目标指纹匹配 CVE
2. 使用 Nuclei 扫描已知漏洞
3. 验证漏洞有效性

输出格式：
{
    "vulnerabilities": [
        {
            "cve_id": "CVE-2021-12345",
            "name": "漏洞名称",
            "severity": "critical/high/medium/low",
            "target": "http://target.com/path",
            "status": "confirmed/potential"
        }
    ],
    "scan_summary": {"total": 0, "critical": 0, "high": 0},
    "recommendations": ["修复建议1", "修复建议2"]
}
"""

    def run(self, target: str, technologies: List[str] = None, **kwargs) -> SubAgentResult:
        """
        执行漏洞扫描

        Args:
            target: 目标 URL
            technologies: 已识别的技术栈

        Returns:
            SubAgentResult
        """
        from tools.langchain_adapter import get_hexstrike_client
        from state.progress_tracker import get_progress_tracker

        client = get_hexstrike_client()
        tracker = get_progress_tracker()
        task_id = kwargs.get("task_id")

        vulnerabilities = []
        summary_data = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

        # 1. Nuclei 扫描
        print(f"[VulnScanSubAgent] 执行 Nuclei 扫描: {target}")
        result = client.execute_command(
            f"nuclei -u {target} -severity critical,high,medium -quiet -silent",
            category="vuln_scanning"
        )

        if result.get("success"):
            output = result.get("stdout", "")
            vulnerabilities = self._parse_nuclei_results(output)

        # 2. 更新统计
        summary_data["total"] = len(vulnerabilities)
        for v in vulnerabilities:
            sev = v.get("severity", "low").lower()
            if sev in summary_data:
                summary_data[sev] += 1

        # 生成摘要
        summary = self._generate_summary(vulnerabilities, summary_data)

        # 更新进度
        if task_id:
            tracker.update_phase(
                task_id, "vuln_scan",
                f"子智能体完成: {summary}",
                details=summary
            )

        return SubAgentResult(
            agent_type="vuln_scan",
            target=target,
            status="success",
            findings={
                "vulnerabilities": vulnerabilities,
                "scan_summary": summary_data
            },
            summary=summary
        )

    def _parse_nuclei_results(self, output: str) -> List[Dict[str, Any]]:
        """解析 Nuclei 结果"""
        vulns = []
        import re

        for line in output.split("\n"):
            if not line.strip():
                continue

            # Nuclei 输出格式: [info/critical/high] [cve-2021-12345] [http://target.com/path]
            match = re.search(r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]', line)
            if match:
                severity, cve, url = match.groups()
                vulns.append({
                    "cve_id": cve,
                    "name": cve,
                    "severity": severity,
                    "target": url,
                    "status": "potential"
                })

        return vulns

    def _generate_summary(self, vulns: List[Dict], summary: Dict) -> str:
        """生成摘要"""
        return (
            f"扫描完成：共发现 {summary['total']} 个漏洞，"
            f"critical: {summary['critical']}, "
            f"high: {summary['high']}, "
            f"medium: {summary['medium']}"
        )


# ===========================================
# 并行执行多个子智能体
# ===========================================
async def parallel_recon(
    targets: List[str],
    task_id: str = None
) -> List[SubAgentResult]:
    """
    并行执行多个 Recon 子智能体

    Args:
        targets: 目标列表
        task_id: 任务 ID

    Returns:
        子智能体结果列表
    """
    import asyncio

    async def run_single(target: str) -> SubAgentResult:
        agent = ReconSubAgent()
        return agent.run(target, task_id=task_id)

    # 并行执行
    results = await asyncio.gather(*[run_single(t) for t in targets])

    return list(results)


def merge_recon_results(results: List[SubAgentResult]) -> Dict[str, Any]:
    """
    合并多个 Recon 结果

    Args:
        results: ReconSubAgent 结果列表

    Returns:
        合并后的结构化报告
    """
    merged = {
        "hosts": [],
        "open_ports": [],
        "subdomains": [],
        "technologies": [],
        "all_vulnerabilities": [],
        "summary": ""
    }

    seen_ports = set()
    seen_subdomains = set()

    for result in results:
        findings = result.findings

        # 合并子域名
        for sub in findings.get("subdomains", []):
            if sub not in seen_subdomains:
                seen_subdomains.add(sub)
                merged["subdomains"].append(sub)

        # 合并端口
        for port in findings.get("open_ports", []):
            port_key = f"{port.get('port')}-{port.get('service')}"
            if port_key not in seen_ports:
                seen_ports.add(port_key)
                merged["open_ports"].append(port)

        # 合并技术栈
        merged["technologies"].extend(findings.get("technologies", []))

    # 去重技术栈
    merged["technologies"] = list(set(merged["technologies"]))

    # 生成总摘要
    merged["summary"] = (
        f"多目标扫描完成："
        f"{len(results)} 个目标，"
        f"{len(merged['subdomains'])} 个子域名，"
        f"{len(merged['open_ports'])} 个开放端口"
    )

    return merged


# ===========================================
# 全局实例获取
# ===========================================
_recon_agent: Optional[ReconSubAgent] = None
_vuln_agent: Optional[VulnScanSubAgent] = None


def get_recon_subagent() -> ReconSubAgent:
    """获取 Recon 子智能体"""
    global _recon_agent
    if _recon_agent is None:
        _recon_agent = ReconSubAgent()
    return _recon_agent


def get_vuln_subagent() -> VulnScanSubAgent:
    """获取漏洞扫描子智能体"""
    global _vuln_agent
    if _vuln_agent is None:
        _vuln_agent = VulnScanSubAgent()
    return _vuln_agent
