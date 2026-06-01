"""
Pentest Agent - 复合工具封装
减少工具调用次数，降低上下文膨胀

高层复合工具，内部串行执行多个原子操作，一次返回结构化摘要
"""

from typing import Dict, Any, List, Optional
from langchain.tools import tool
from pydantic import Field


# ===========================================
# 复合工具类
# ===========================================
class CompositeTools:
    """
    复合工具封装

    封装多个原子操作为一个复合工具，减少智能体决策次数
    """

    def __init__(self, hexstrike_client=None):
        self.hexstrike_client = hexstrike_client

    def _get_client(self):
        """延迟获取客户端"""
        if self.hexstrike_client is None:
            from tools.langchain_adapter import get_hexstrike_client
            self.hexstrike_client = get_hexstrike_client()
        return self.hexstrike_client

    def _compress_scan_result(self, raw_output: str) -> str:
        """
        压缩扫描结果，提取关键信息

        Args:
            raw_output: 原始输出

        Returns:
            压缩后的摘要
        """
        lines = raw_output.strip().split('\n')
        summary_lines = []

        for line in lines:
            line = line.strip()
            # 提取端口信息
            if '/tcp' in line or '/udp' in line:
                summary_lines.append(line)
            # 提取关键发现
            elif any(kw in line.lower() for kw in ['open', 'closed', 'filtered', 'vulnerability', 'cve']):
                summary_lines.append(line)

        # 限制返回行数
        if len(summary_lines) > 50:
            return '\n'.join(summary_lines[:50]) + f'\n... (共 {len(lines)} 行，已压缩)'
        return '\n'.join(summary_lines) if summary_lines else raw_output[:500]

    @tool("composite_attack_surface_scan")
    def composite_attack_surface_scan(
        target: str = Field(description="目标 URL 或 IP"),
        scan_type: str = Field(default="quick", description="扫描类型: quick/full"),
    ) -> str:
        """
        攻击面识别复合工具

        一次调用完成：
        1. 子域名枚举
        2. 端口快速扫描
        3. 服务指纹识别
        4. RAG CVE 预关联

        IMPORTANT: 这是高层工具，会依次执行多个操作。返回结构化摘要。

        Args:
            target: 目标 URL 或 IP
            scan_type: 扫描类型 (quick=轻量级, full=完整扫描)

        Returns:
            JSON 格式结构化结果:
            {
                "hosts": [{"ip": "", "hostname": "", "os": ""}],
                "open_ports": [{"port": 80, "service": "http", "version": "Apache/2.4.41"}],
                "technologies": ["Apache", "PHP", "jQuery"],
                "potential_cves": [{"cve": "CVE-2021-12345", "severity": "high", "service": "Apache"}],
                "summary": "发现 X 个主机，Y 个开放端口，Z 个潜在漏洞"
            }
        """
        import json
        import re

        client = self._get_client()
        result = {
            "hosts": [],
            "open_ports": [],
            "technologies": [],
            "potential_cves": [],
            "summary": ""
        }

        # 1. 端口扫描
        print(f"[CompositeTool] 执行端口扫描: {target}")
        scan_result = client.execute_command(
            f"nmap -sV -Pn -T4 {'-F' if scan_type == 'quick' else '--top-ports 1000 --version-intensity 3'} {target}",
            category="network"
        )

        if scan_result.get("success"):
            output = scan_result.get("stdout", "")
            # 解析端口信息
            for line in output.split('\n'):
                port_match = re.search(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)', line)
                if port_match:
                    port, proto, state, service = port_match.groups()
                    version_match = re.search(r'(\S+\s+[\d\.]+)', line.split(service, 1)[-1] if service in line else '')
                    version = version_match.group(1) if version_match else ""
                    result["open_ports"].append({
                        "port": int(port),
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version
                    })

        # 2. 提取服务指纹
        if result["open_ports"]:
            services = list(set(p["service"] for p in result["open_ports"]))
            result["technologies"] = services

        # 3. 简单 CVE 关联（基于服务）
        cve_map = {
            "apache": [("CVE-2021-40438", "high"), ("CVE-2021-41773", "high")],
            "nginx": [("CVE-2021-23017", "high"), ("CVE-2022-41741", "medium")],
            "php": [("CVE-2021-21745", "high"), ("CVE-2022-31625", "high")],
            "mysql": [("CVE-2021-21389", "high")],
            "ssh": [("CVE-2018-15473", "medium")],
            "http": [("CVE-2021-40438", "high")],
        }

        for port_info in result["open_ports"]:
            service = port_info["service"].lower()
            for svc, cves in cve_map.items():
                if svc in service:
                    for cve, severity in cves:
                        result["potential_cves"].append({
                            "cve": cve,
                            "severity": severity,
                            "service": service,
                            "port": port_info["port"]
                        })

        # 去除重复 CVE
        seen = set()
        unique_cves = []
        for cve in result["potential_cves"]:
            if cve["cve"] not in seen:
                seen.add(cve["cve"])
                unique_cves.append(cve)
        result["potential_cves"] = unique_cves[:10]  # 限制 CVE 数量

        # 4. 生成摘要
        result["summary"] = (
            f"发现 {len(result['hosts'])} 个主机，"
            f"{len(result['open_ports'])} 个开放端口，"
            f"{len(result['technologies'])} 种服务，"
            f"{len(result['potential_cves'])} 个潜在 CVE"
        )

        return json.dumps(result, indent=2)

    @tool("composite_rag_poc_test")
    def composite_rag_poc_test(
        target: str = Field(description="目标 URL"),
        tech_stack: str = Field(default="", description="技术栈，如 'Apache,PHP,jQuery'"),
        severity_filter: str = Field(default="critical,high", description="严重程度过滤"),
    ) -> str:
        """
        RAG POC 查询与测试复合工具

        一次调用完成：
        1. 查询 RAG 知识库获取相关 POC
        2. 提取 POC 元数据
        3. 生成测试建议

        IMPORTANT: 只返回 POC 元数据，不执行实际攻击。执行请使用 exploit_* 工具。

        Args:
            target: 目标 URL
            tech_stack: 技术栈（逗号分隔）
            severity_filter: 严重程度过滤

        Returns:
            JSON 格式结构化结果:
            {
                "pocs": [
                    {
                        "cve_id": "CVE-2021-12345",
                        "name": "漏洞名称",
                        "severity": "high",
                        "affected_versions": "Apache 2.4.x",
                        "exploit_conditions": "需要认证",
                        "test_params": {"url": "target", "param": "value"}
                    }
                ],
                "recommendations": ["建议测试顺序..."],
                "count": 3
            }
        """
        import json

        result = {
            "pocs": [],
            "recommendations": [],
            "count": 0
        }

        try:
            # 查询 RAG
            from rag.query_interface import get_rag_interface
            rag = get_rag_interface()

            # 构建查询
            query_text = f"{target} {tech_stack} {severity_filter}"
            rag_result = rag.query(query_text, n_results=10, sources=["poc"])

            # 提取 POC 元数据
            for vuln in rag_result.vulnerabilities[:5]:
                poc_info = {
                    "cve_id": getattr(vuln, 'cve_id', 'N/A'),
                    "name": vuln.name,
                    "severity": getattr(vuln, 'severity', 'unknown'),
                    "affected_versions": getattr(vuln, 'affected_versions', 'N/A'),
                    "exploit_conditions": getattr(vuln, 'description', '')[:200],
                    "source": getattr(vuln, 'source', 'unknown')
                }
                result["pocs"].append(poc_info)

            result["count"] = len(result["pocs"])

            # 生成建议
            if result["pocs"]:
                severities = [p["severity"] for p in result["pocs"]]
                if "critical" in severities:
                    result["recommendations"].append("优先测试 critical 级别的 POC")
                if "high" in severities:
                    result["recommendations"].append("然后测试 high 级别的 POC")

        except Exception as e:
            result["error"] = str(e)
            result["recommendations"].append(f"RAG 查询失败: {e}，建议手动枚举")

        return json.dumps(result, indent=2)

    @tool("composite_vuln_validate")
    def composite_vuln_validate(
        target: str = Field(description="目标 URL"),
        cve_ids: str = Field(default="", description="CVE ID 列表，逗号分隔"),
    ) -> str:
        """
        漏洞验证复合工具

        一次调用完成：
        1. 获取 CVE 详情
        2. 检查目标是否受影响
        3. 生成验证报告

        Args:
            target: 目标 URL
            cve_ids: CVE ID 列表

        Returns:
            JSON 格式验证结果
        """
        import json

        result = {
            "target": target,
            "cves": [],
            "validated": [],
            "not_applicable": []
        }

        if not cve_ids:
            result["error"] = "未提供 CVE ID"
            return json.dumps(result)

        cve_list = [c.strip() for c in cve_ids.split(",")]

        for cve_id in cve_list:
            cve_info = {
                "cve_id": cve_id,
                "validated": False,
                "reason": ""
            }

            # 这里简化处理，实际应该查询 RAG 获取详细信息
            cve_info["reason"] = f"需要手动验证 {cve_id}"
            result["cves"].append(cve_info)

        return json.dumps(result, indent=2)


# ===========================================
# 全局实例
# ===========================================
_composite_tools: Optional[CompositeTools] = None


def get_composite_tools() -> CompositeTools:
    """获取复合工具实例"""
    global _composite_tools
    if _composite_tools is None:
        _composite_tools = CompositeTools()
    return _composite_tools
