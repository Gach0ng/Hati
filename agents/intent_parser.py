"""
Hati - 意图解析器
使用 LLM 将自然语言解析为结构化的 Intent
"""

import json
import re
from typing import List, Optional, Dict, Any


class Intent:
    """结构化意图"""

    def __init__(
        self,
        targets: List[str],
        attack_types: List[str],
        depth: str = "standard",
        scope: str = "web",
        hints: str = "",
        ports: List[int] = None,
        credentials: Optional[Dict] = None,
    ):
        self.targets = targets
        self.attack_types = attack_types
        self.depth = depth
        self.scope = scope
        self.hints = hints
        self.ports = ports or []
        self.credentials = credentials or {}

    def __repr__(self):
        return f"Intent(targets={self.targets}, attack_types={self.attack_types}, depth={self.depth})"


class IntentParser:
    """
    意图解析器

    使用 LLM 将自然语言解析为 Intent 结构化对象
    """

    def __init__(self, llm=None):
        from config.minimax_config import get_llm
        self.llm = llm or get_llm()
        self.system_prompt = """你是一个渗透测试任务解析器。分析用户输入，严格返回纯JSON。

【意图分类】

**1. 渗透测试任务**（有明确目标，且用户想执行安全测试）：
- targets: ["目标URL/IP/域名"]
- attack_types: 根据测试类型选择以下之一：
  full_pentest | port_scan | fingerprint | dir_scan | subdomain_enum |
  sqli | xss | rce | ssrf | cors | csrf | lfi | vuln_scan | auth_bypass | brute
- 示例："对 example.com 做渗透测试" → targets:["example.com"], attack_types:["full_pentest"]
- 示例："扫描 192.168.1.1 的端口" → targets:["192.168.1.1"], attack_types:["port_scan"]

**2. 漏洞知识库查询**（查CVE/POC/漏洞，不是渗透测试）：
- targets: [], attack_types: []
- hints: "rag_query"
- 示例："查CVE-2021-44228", "查漏洞", "查知识库", "有哪些漏洞", "log4j漏洞" → hints:"rag_query"

**3. 系统能力询问**：
- targets: [], attack_types: []
- hints: "query_tools"
- 示例："有哪些工具", "你能做什么", "列出工具" → hints:"query_tools"

**4. 帮助**：
- targets: [], attack_types: []
- hints: "help"
- 示例："帮助", "help", "怎么使用" → hints:"help"

**5. 状态查询**：
- targets: [], attack_types: []
- hints: "status"
- 示例："状态", "进度" → hints:"status"

**6. 一般对话**（闲聊、问候、单个数字/字符、无意义的输入）：
- targets: [], attack_types: []
- hints: "general_chat"
- 示例："hello", "1", "你好", "今天天气怎么样" → hints:"general_chat"

重要：只返回纯JSON，不要额外文字。
格式：{"targets":["..."], "attack_types":["..."], "depth":"standard", "scope":"web", "hints":"..."}"""

    def parse(self, user_message: str) -> Intent:
        """解析用户输入"""
        response = self.llm.chat(
            prompt=f"用户输入：{user_message}\n\n请分析并提取渗透测试参数，JSON格式返回：",
            system_prompt=self.system_prompt,
        )

        return self._parse_response(response, user_message)

    def _parse_response(self, response: str, original_message: str) -> Intent:
        """解析 LLM 响应"""
        # 提取 JSON
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
            except json.JSONDecodeError:
                data = {}
        else:
            data = {}

        # 解析 targets
        targets = data.get("targets", [])
        if not targets:
            targets = self._extract_targets(original_message)

        # 解析 attack_types
        attack_types = data.get("attack_types", ["full_pentest"])
        if isinstance(attack_types, str):
            attack_types = [attack_types]

        # 解析 depth
        depth = data.get("depth", "standard")

        return Intent(
            targets=targets,
            attack_types=attack_types,
            depth=depth,
            scope=data.get("scope", "web"),
            hints=data.get("hints", ""),
            ports=data.get("ports", []),
            credentials=data.get("credentials"),
        )

    def _extract_targets(self, message: str) -> List[str]:
        """从消息中提取目标"""
        targets = []

        # URL pattern
        url_pattern = r'https?://[a-zA-Z0-9.:/-]+'
        targets.extend(re.findall(url_pattern, message))

        # IP pattern
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        targets.extend(re.findall(ip_pattern, message))

        # Domain pattern
        domain_pattern = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}'
        targets.extend(re.findall(domain_pattern, message))

        # 去重
        seen = set()
        result = []
        for t in targets:
            t = t.rstrip('.,;/')
            if t and t not in seen:
                seen.add(t)
                result.append(t)

        return result


# 全局实例
_parser: Optional[IntentParser] = None


def get_intent_parser() -> IntentParser:
    """获取全局解析器"""
    global _parser
    if _parser is None:
        _parser = IntentParser()
    return _parser
