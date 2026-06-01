"""
Pentest Agent - LangChain MCP 适配器
将 HexStrike MCP 工具转换为 LangChain Tool 对象
"""

import os
import sys
import json
from typing import Optional, Any, Callable
import requests

# Fix Unicode output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Celery worker: stdout/stderr is LoggingProxy

from dotenv import load_dotenv
load_dotenv()

from langchain.tools import tool
from pydantic import Field
from langchain_core.callbacks.manager import CallbackManagerForToolRun

# ===========================================
# HexStrike MCP 客户端
# ===========================================
class HexStrikeMCPClient:
    """
    HexStrike MCP 工具适配器

    将 HexStrike 的 API 工具转换为 LangChain Tool
    """

    def __init__(
        self,
        base_url: str = None,
        timeout: int = 300,
    ):
        """
        初始化 HexStrike MCP 客户端

        Args:
            base_url: HexStrike API 服务器地址
            timeout: 请求超时时间
        """
        self.base_url = base_url or os.getenv("HEXSTRIKE_SERVER_URL", "http://localhost:9999")
        self.timeout = timeout
        self.session = requests.Session()

        # 测试连接
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                self.health = response.json()
                print(f"✅ HexStrike MCP 连接成功: {self.base_url}")
                print(f"   版本: {self.health.get('version', 'unknown')}")
                print(f"   可用工具: {self.health.get('total_tools_available', 0)}")
            else:
                print(f"⚠️  HexStrike MCP 健康检查失败: {response.status_code}")
                self.health = None
        except Exception as e:
            print(f"⚠️  HexStrike MCP 连接失败: {e}")
            self.health = None

    def execute_command(self, command: str, category: str = "essential") -> dict:
        """
        执行 HexStrike 命令

        Args:
            command: 命令
            category: 工具类别

        Returns:
            执行结果
        """
        try:
            response = self.session.post(
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

    def analyze_target(self, target: str, analysis_type: str = "quick") -> dict:
        """
        分析目标

        Args:
            target: 目标
            analysis_type: 分析类型

        Returns:
            分析结果
        """
        try:
            response = self.session.post(
                f"{self.base_url}/api/intelligence/analyze-target",
                json={"target": target, "analysis_type": analysis_type},
                timeout=15,  # 快速分析不能等太久
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def select_tools(self, target: str, analysis_type: str = "reconnaissance") -> dict:
        """
        智能选择工具

        Args:
            target: 目标
            analysis_type: 分析类型

        Returns:
            工具选择结果
        """
        try:
            response = self.session.post(
                f"{self.base_url}/api/intelligence/select-tools",
                json={"target": target, "analysis_type": analysis_type},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}


# ===========================================
# LangChain Tool 封装
# ===========================================
class NetworkScanTool:
    """网络扫描工具 (LangChain Tool)"""

    def __init__(self, client: HexStrikeMCPClient = None):
        self.client = client or HexStrikeMCPClient()

    @tool("recon_nmap_scan")
    def recon_nmap_scan(
        target: str = Field(description="目标 IP 或域名"),
        options: str = Field(default="-sn -PS80,443", description="nmap 选项"),
    ) -> str:
        """
        执行 Nmap 端口扫描

        IMPORTANT: Use this for initial port discovery. NEVER use vuln_exploit before completing reconnaissance.

        Args:
            target: 目标 IP 或域名
            options: nmap 选项

        Returns:
            扫描结果
        """
        result = self.client.execute_command(
            f"nmap {options} {target}",
            category="network"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"扫描失败: {result.get('error', 'Unknown error')}"

    @tool("recon_masscan_scan")
    def recon_masscan_scan(
        target: str = Field(description="目标 IP 或 CIDR"),
        ports: str = Field(default="1-10000", description="端口范围"),
    ) -> str:
        """
        执行 Masscan 高速端口扫描

        Args:
            target: 目标
            ports: 端口范围

        Returns:
            扫描结果
        """
        result = self.client.execute_command(
            f"masscan -p{ports} {target} --rate=1000",
            category="network"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"扫描失败: {result.get('error', 'Unknown error')}"


class WebScanTool:
    """Web 扫描工具 (LangChain Tool)"""

    def __init__(self, client: HexStrikeMCPClient = None):
        self.client = client or HexStrikeMCPClient()

    @tool("vuln_nuclei_scan")
    def vuln_nuclei_scan(
        target: str = Field(description="目标 URL"),
        severity: str = Field(default="critical,high,medium", description="漏洞严重程度"),
    ) -> str:
        """
        执行 Nuclei 漏洞扫描

        Args:
            target: 目标 URL
            severity: 严重程度过滤

        Returns:
            扫描结果
        """
        result = self.client.execute_command(
            f"nuclei -u {target} -severity {severity} -quiet",
            category="vuln_scanning"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"扫描失败: {result.get('error', 'Unknown error')}"

    @tool("vuln_sqlmap_test")
    def vuln_sqlmap_test(
        target: str = Field(description="目标 URL"),
        options: str = Field(default="--batch --random-agent", description="sqlmap 选项"),
    ) -> str:
        """
        执行 SQLMap SQL 注入测试

        Args:
            target: 目标 URL
            options: sqlmap 选项

        Returns:
            扫描结果
        """
        result = self.client.execute_command(
            f"sqlmap -u {target} {options}",
            category="web_security"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"扫描失败: {result.get('error', 'Unknown error')}"

    @tool("vuln_nikto_scan")
    def vuln_nikto_scan(
        target: str = Field(description="目标 URL"),
    ) -> str:
        """
        执行 Nikto Web 服务器扫描

        Args:
            target: 目标 URL

        Returns:
            扫描结果
        """
        result = self.client.execute_command(
            f"nikto -h {target} -Format txt -nointeractive",
            category="web_security"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"扫描失败: {result.get('error', 'Unknown error')}"


class ReconTool:
    """信息收集工具 (LangChain Tool)"""

    def __init__(self, client: HexStrikeMCPClient = None):
        self.client = client or HexStrikeMCPClient()

    @tool("recon_httpx_probe")
    def recon_httpx_probe(
        targets: str = Field(description="目标 URL 或文件路径"),
        options: str = Field(default="-title -tech-detect", description="httpx 选项"),
    ) -> str:
        """
        使用 Httpx 探测 HTTP 服务

        Args:
            targets: 目标 URL 或 @file.txt
            options: httpx 选项

        Returns:
            探测结果
        """
        result = self.client.execute_command(
            f"httpx -{options} -u {targets}",
            category="web_security"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"探测失败: {result.get('error', 'Unknown error')}"

    @tool("recon_subfinder_enum")
    def recon_subfinder_enum(
        domain: str = Field(description="域名"),
    ) -> str:
        """
        使用 Subfinder 发现子域名

        Args:
            domain: 域名

        Returns:
            子域名列表
        """
        result = self.client.execute_command(
            f"subfinder -d {domain} -silent",
            category="network"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"枚举失败: {result.get('error', 'Unknown error')}"

    @tool("recon_amass_enum")
    def recon_amass_enum(
        domain: str = Field(description="域名"),
    ) -> str:
        """
        使用 Amass 进行子域名枚举

        Args:
            domain: 域名

        Returns:
            子域名列表
        """
        result = self.client.execute_command(
            f"amass enum -passive -d {domain}",
            category="network"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"枚举失败: {result.get('error', 'Unknown error')}"


class PasswordTool:
    """密码攻击工具 (LangChain Tool)"""

    def __init__(self, client: HexStrikeMCPClient = None):
        self.client = client or HexStrikeMCPClient()

    @tool("exploit_hydra_brute")
    def exploit_hydra_brute(
        target: str = Field(description="目标"),
        service: str = Field(description="服务类型 (ssh, ftp, http-post-form等)"),
        username: str = Field(default="admin", description="用户名"),
        wordlist: str = Field(description="密码字典路径"),
    ) -> str:
        """
        使用 Hydra 进行暴力破解

        ⚠️ IMPORTANT: This tool requires human approval before execution.

        Args:
            target: 目标地址
            service: 服务类型
            username: 用户名
            wordlist: 密码字典

        Returns:
            破解结果
        """
        result = self.client.execute_command(
            f"hydra -l {username} -P {wordlist} {target} {service}",
            category="password"
        )
        if result.get("success"):
            return result.get("stdout", "")
        return f"破解失败: {result.get('error', 'Unknown error')}"


# ===========================================
# 工具集合获取函数
# ===========================================
def get_all_tools() -> list:
    """
    获取所有 HexStrike 工具

    Returns:
        LangChain Tool 列表
    """
    client = HexStrikeMCPClient()

    tools = []

    # 网络扫描 (recon_*)
    network_tools = NetworkScanTool(client)
    tools.append(network_tools.recon_nmap_scan)
    tools.append(network_tools.recon_masscan_scan)

    # Web 扫描 (vuln_*)
    web_tools = WebScanTool(client)
    tools.append(web_tools.vuln_nuclei_scan)
    tools.append(web_tools.vuln_sqlmap_test)
    tools.append(web_tools.vuln_nikto_scan)

    # 信息收集 (recon_*)
    recon_tools = ReconTool(client)
    tools.append(recon_tools.recon_httpx_probe)
    tools.append(recon_tools.recon_subfinder_enum)
    tools.append(recon_tools.recon_amass_enum)

    # 密码攻击 (exploit_*)
    password_tools = PasswordTool(client)
    tools.append(password_tools.exploit_hydra_brute)

    return tools


def get_tools_by_category(category: str) -> list:
    """
    按类别获取工具

    Args:
        category: 工具类别 (network, web_security, password, recon, etc.)

    Returns:
        工具列表
    """
    client = HexStrikeMCPClient()

    if category == "network":
        tools = NetworkScanTool(client)
        return [tools.recon_nmap_scan, tools.recon_masscan_scan]
    elif category == "web_security":
        tools = WebScanTool(client)
        return [tools.vuln_nuclei_scan, tools.vuln_sqlmap_test, tools.vuln_nikto_scan]
    elif category == "recon":
        tools = ReconTool(client)
        return [tools.recon_httpx_probe, tools.recon_subfinder_enum, tools.recon_amass_enum]
    elif category == "password":
        tools = PasswordTool(client)
        return [tools.exploit_hydra_brute]

    return []


def get_tools_by_prefix(prefix: str) -> list:
    """
    按前缀获取工具（用于分层 Prompt 工具过滤）

    Args:
        prefix: 工具前缀 (recon_, vuln_, exploit_, report_)

    Returns:
        匹配前缀的工具列表
    """
    all_tools = get_all_tools()
    return [t for t in all_tools if t.name.startswith(prefix)]


# ===========================================
# 全局客户端实例
# ===========================================
_hexstrike_client: Optional[HexStrikeMCPClient] = None


def get_hexstrike_client() -> HexStrikeMCPClient:
    """获取全局 HexStrike 客户端"""
    global _hexstrike_client
    if _hexstrike_client is None:
        _hexstrike_client = HexStrikeMCPClient()
    return _hexstrike_client


# ===========================================
# 工具响应压缩
# ===========================================
def compress_tool_result(result: dict, format: str = "concise") -> dict:
    """
    压缩工具返回结果，减少 token 消耗

    Args:
        result: 原始工具结果
        format: 压缩格式 ("concise"=精简, "detailed"=完整)

    Returns:
        压缩后的结果
    """
    if format != "concise":
        return result  # detailed 保留原样

    if not isinstance(result, dict):
        return result

    # 去除技术噪声
    keys_to_remove = [
        "uuid", "request_id", "trace_id", "correlation_id",
        "base64_image", "raw_data", "full_output", "stack_trace",
        "_id", "__typename", "internal_id"
    ]

    compressed = {}
    for key, value in result.items():
        key_lower = key.lower()

        # 跳过噪声字段
        if any(noise in key_lower for noise in keys_to_remove):
            continue

        # 递归压缩
        if isinstance(value, dict):
            compressed[key] = compress_tool_result(value, format)
        elif isinstance(value, list):
            # 限制列表长度
            if len(value) > 20:
                compressed[key] = value[:20] + [f"... (共 {len(value)} 项)"]
            else:
                compressed[key] = [
                    compress_tool_result(v, format) if isinstance(v, dict) else v
                    for v in value
                ]
        elif isinstance(value, str) and len(value) > 1000:
            # 截断超长字符串
            compressed[key] = value[:1000] + f"\n... (共 {len(value)} 字符)"
        else:
            compressed[key] = value

    return compressed


def extract_key_info(result: dict) -> str:
    """
    从工具结果中提取关键信息，返回自然语言摘要

    Args:
        result: 工具结果

    Returns:
        关键信息摘要
    """
    if not isinstance(result, dict):
        return str(result)[:500]

    info_parts = []

    # 提取关键字段
    key_fields = ["ports", "open_ports", "vulnerabilities", "hosts",
                  "subdomains", "technologies", "services", "findings"]

    for field in key_fields:
        if field in result:
            value = result[field]
            if isinstance(value, list):
                if len(value) > 0:
                    info_parts.append(f"{field}: {len(value)} 项")
                    # 如果是简单对象列表，显示前几项
                    if len(value) <= 5:
                        info_parts.append(f"  {value}")
            elif isinstance(value, dict):
                info_parts.append(f"{field}: {len(value)} 个键")
            elif isinstance(value, str):
                info_parts.append(f"{field}: {value[:100]}")

    # 提取 success 和 error
    if result.get("success"):
        info_parts.append("状态: 成功")
    if result.get("error"):
        info_parts.append(f"错误: {result['error']}")

    # 提取 stdout
    if result.get("stdout"):
        stdout = result["stdout"]
        # 提取关键行
        key_lines = []
        for line in stdout.split("\n"):
            if any(kw in line.lower() for kw in ["open", "port", "service", "vuln", "cve", "error", "warning"]):
                key_lines.append(line.strip())
        if key_lines:
            info_parts.append(f"输出摘要: {' | '.join(key_lines[:5])}")

    return "\n".join(info_parts) if info_parts else str(result)[:500]
