"""
Hati - 交互式聊天 Agent
支持通过 WebSocket 与用户实时对话
真正触发 Orchestrator 执行全流程渗透测试
"""

import json
import re
import uuid
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from config.minimax_config import get_llm, get_system_prompt
from config.minimax_config import SYSTEM_PROMPTS
from config.celery_config import celery_app
from tools.langchain_adapter import get_hexstrike_client
from celery.result import AsyncResult


class _DummyRAG:
    """RAG 降级占位，当 RAG 初始化失败时使用"""

    def query(self, *args, **kwargs):
        return type('QueryResult', (), {
            'total_count': 0, 'vulnerabilities': [], 'by_severity': {}, 'by_source': {}
        })()

    def query_by_product(self, *args, **kwargs):
        return self.query()

    def get_exploit_content(self, *args, **kwargs):
        return None

    def get_stats(self):
        return {'cve_count': 0, 'poc_count': 0, 'total_count': 0}


class ChatAgent:
    """
    交互式聊天 Agent

    处理用户自然语言输入，协调渗透测试全流程
    """

    def __init__(self):
        self.llm = get_llm()
        self.hexstrike_client = get_hexstrike_client()
        self.conversation_history = []
        self.pending_tasks: Dict[str, dict] = {}  # 存储待处理的任务

        # 后台任务执行器（绕过 Celery Windows 兼容问题）
        from concurrent.futures import ThreadPoolExecutor
        self._executor = ThreadPoolExecutor(max_workers=3)

        # RAG 知识库懒加载 (首次使用时才初始化，避免启动阻塞)
        self._rag_interface = None

    @property
    def rag_interface(self):
        """懒加载 RAG 接口，首次使用时才初始化"""
        if self._rag_interface is None:
            try:
                from rag.query_interface import get_rag_interface
                self._rag_interface = get_rag_interface()
            except Exception as e:
                print(f"[ChatAgent] RAG 初始化失败 (功能降级): {e}")
                self._rag_interface = _DummyRAG()
        return self._rag_interface

    def process_message(self, user_message: str) -> Dict[str, Any]:
        """
        处理用户消息

        Args:
            user_message: 用户输入

        Returns:
            {
                "type": "text|action|result|error",
                "content": "响应内容",
                "data": {}  # 可选的附加数据
            }
        """
        # 添加到历史
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
            "timestamp": datetime.utcnow().isoformat(),
        })

        # 分析用户意图（LLM 语义分析优先）
        intent_info = self._analyze_intent(user_message)
        intent = intent_info["intent"]

        # 根据意图路由
        if intent.startswith("pentest_"):
            # 单项渗透测试（端口扫描、SQL注入等）
            response = self._handle_pentest_workflow(user_message, intent, intent_info)
        elif intent == "start_pentest":
            response = self._handle_start_pentest(user_message, intent_info)
        elif intent == "rag_query":
            response = self._handle_rag_query(user_message)
        elif intent == "query_tool":
            response = self._handle_query_tool(user_message)
        elif intent == "status_query":
            response = self._handle_status_query(user_message)
        elif intent == "help":
            response = self._handle_help()
        else:
            # general_chat 或未知
            response = self._handle_general_chat(user_message)

        # 添加到历史
        self.conversation_history.append({
            "role": "assistant",
            "content": response["content"],
            "timestamp": datetime.utcnow().isoformat(),
        })

        return response

    def _analyze_intent(self, message: str) -> Dict[str, Any]:
        """
        分析用户意图 — LLM 语义分析优先，关键词仅作极速旁路。

        Returns:
            {"intent": str, "target": str|None, "attack_types": list, "hints": str}
        """
        message_lower = message.lower()

        # ===========================================
        # 极速旁路：明确的元命令（不调用 LLM）
        # ===========================================
        if any(kw in message_lower for kw in ["帮助", "help", "使用说明", "怎么使用"]):
            return {"intent": "help", "target": None, "attack_types": [], "hints": "help"}

        if any(kw in message_lower for kw in ["有哪些工具", "工具列表", "你能做什么", "列出工具", "mcp工具"]):
            return {"intent": "query_tool", "target": None, "attack_types": [], "hints": "query_tools"}

        if any(kw in message_lower for kw in ["状态", "进度", "任务状态"]):
            return {"intent": "status_query", "target": None, "attack_types": [], "hints": "status"}

        # ===========================================
        # 主路径：LLM 语义分析
        # ===========================================
        try:
            from agents.intent_parser import get_intent_parser
            parser = get_intent_parser()
            intent_obj = parser.parse(message)

            hints = (intent_obj.hints or "").lower()

            # RAG 知识库查询
            if "rag_query" in hints:
                return {"intent": "rag_query", "target": None, "attack_types": [], "hints": "rag_query"}

            # 一般对话
            if "general_chat" in hints:
                return {"intent": "general_chat", "target": None, "attack_types": [], "hints": "general_chat"}

            # 帮助
            if "help" in hints:
                return {"intent": "help", "target": None, "attack_types": [], "hints": "help"}

            # 工具查询
            if "query_tools" in hints:
                return {"intent": "query_tool", "target": None, "attack_types": [], "hints": "query_tools"}

            # 状态查询
            if "status" in hints:
                return {"intent": "status_query", "target": None, "attack_types": [], "hints": "status"}

            # 渗透测试任务（有目标 + attack_types）
            attack_to_intent = {
                "port_scan": "pentest_recon", "recon": "pentest_recon",
                "fingerprint": "pentest_recon_fingerprint", "dir_scan": "pentest_recon_dir",
                "subdomain_enum": "pentest_recon_subdomain",
                "sqli": "pentest_attack_sqli", "xss": "pentest_attack_xss",
                "vuln_scan": "pentest_vuln_scan", "full_pentest": "start_pentest",
                "rce": "pentest_attack_rce", "lfi": "pentest_attack_lfi",
                "auth_bypass": "pentest_attack_brute", "ssrf": "pentest_attack_ssrf",
                "cors": "pentest_recon_cors", "csrf": "pentest_attack_csrf",
                "brute": "pentest_attack_brute",
            }

            targets = intent_obj.targets
            attack_types = intent_obj.attack_types

            if targets and attack_types:
                for at in attack_types:
                    if at in attack_to_intent:
                        return {
                            "intent": attack_to_intent[at],
                            "target": targets[0],
                            "attack_types": attack_types,
                            "hints": hints,
                        }
                # 有目标但 attack_type 未知 → 默认渗透测试
                return {
                    "intent": "start_pentest",
                    "target": targets[0],
                    "attack_types": ["full_pentest"],
                    "hints": hints,
                }

            if targets:
                return {
                    "intent": "start_pentest",
                    "target": targets[0],
                    "attack_types": ["full_pentest"],
                    "hints": hints,
                }

            # 无目标也无特殊 hints → 一般对话
            return {"intent": "general_chat", "target": None, "attack_types": [], "hints": "general_chat"}

        except Exception as e:
            print(f"[ChatAgent] LLM意图解析失败，回退关键词: {e}")
            return self._fallback_intent_analysis(message)

    def _fallback_intent_analysis(self, message: str) -> Dict[str, Any]:
        """LLM 不可用时的关键词回退"""
        message_lower = message.lower()

        intent = "general_chat"
        target = self._extract_target(message)

        if any(kw in message_lower for kw in ["渗透测试", "安全测试", "端口扫描", "漏洞扫描",
               "sql注入", "xss", "rce", "ssrf", "子域名", "指纹", "目录扫描"]):
            intent = "start_pentest" if target else "help"

        return {"intent": intent, "target": target, "attack_types": [], "hints": ""}

    def _handle_pentest_workflow(self, message: str, intent: str, intent_info: dict = None) -> Dict[str, Any]:
        """
        统一渗透测试工作流处理

        所有 pentest_* 意图都走这里，提交后台任务实现流式输出
        """
        # 优先用 LLM 解析到的目标，回退到正则提取
        target = (intent_info or {}).get("target") or self._extract_target(message)

        # 根据 intent 映射 attack_types（避免调用 LLM）
        intent_to_attack_types = {
            "pentest_recon": ["port_scan"],
            "pentest_recon_dir": ["dir_scan"],
            "pentest_recon_subdomain": ["subdomain_enum"],
            "pentest_recon_fingerprint": ["fingerprint"],
            "pentest_recon_cors": ["cors"],
            "pentest_rag_query": ["rag_query"],
            "pentest_attack_sqli": ["sqli"],
            "pentest_attack_brute": ["auth_bypass"],
            "pentest_attack_xss": ["xss"],
            "pentest_attack_rce": ["rce"],
            "pentest_attack_lfi": ["lfi"],
            "pentest_attack_ssrf": ["ssrf"],
            "pentest_attack_csrf": ["csrf"],
            "pentest_attack_poc": ["poc_verify"],
            "pentest_vuln_scan": ["vuln_scan"],
        }

        if not target:
            return {
                "type": "text",
                "content": "请提供要测试的目标，例如：「对 https://example.com 做端口扫描」",
            }

        # 生成任务ID
        task_id = str(uuid.uuid4())

        # 清理目标 URL
        scan_target = target
        if scan_target.startswith("http://"):
            scan_target = scan_target.replace("http://", "")
        elif scan_target.startswith("https://"):
            scan_target = scan_target.replace("https://", "")
        scan_target = scan_target.split("/")[0]

        try:
            # 初始化进度追踪
            from state.progress_tracker import get_progress_tracker
            tracker = get_progress_tracker()
            tracker.start_task(task_id, scan_target)

            # 根据意图映射到阶段
            intent_to_phase = {
                "pentest_recon": ("recon", "信息收集"),
                "pentest_recon_dir": ("recon", "目录扫描"),
                "pentest_recon_subdomain": ("recon", "子域名发现"),
                "pentest_recon_fingerprint": ("recon", "指纹识别"),
                "pentest_recon_cors": ("recon", "CORS检测"),
                "pentest_rag_query": ("recon", "RAG漏洞查询"),
                "pentest_attack_sqli": ("attack", "SQL注入测试"),
                "pentest_attack_brute": ("attack", "暴力破解"),
                "pentest_attack_xss": ("attack", "XSS测试"),
                "pentest_attack_rce": ("attack", "RCE测试"),
                "pentest_attack_lfi": ("attack", "LFI测试"),
                "pentest_attack_ssrf": ("attack", "SSRF测试"),
                "pentest_attack_csrf": ("attack", "CSRF测试"),
                "pentest_attack_poc": ("attack", "POC验证"),
                "pentest_vuln_scan": ("vuln_scan", "漏洞扫描"),
            }

            phase, phase_name = intent_to_phase.get(intent, ("recon", "信息收集"))
            tracker.update_phase(task_id, "init", "任务初始化", f"开始{phase_name}，目标: {scan_target}")

            # 构建 Intent 信息用于动态调度（直接从关键词映射，不调用 LLM）
            intent_info = {
                "targets": [scan_target],
                "attack_types": intent_to_attack_types.get(intent, ["full_pentest"]),
                "depth": "standard",
                "scope": "web",
                "hints": "",
                "ports": [],
            }

            # 在后台线程直接执行（绕过 Celery，避免 Windows worker 问题）
            from agents.orchestrator import run_single_phase_standalone

            # 存储任务信息
            self.pending_tasks[task_id] = {
                "target": scan_target,
                "status": "running",
                "celery_task_id": task_id,
                "phase": phase,
                "user_intent": message,
            }

            # 在线程池中启动后台任务
            def do_scan():
                try:
                    run_single_phase_standalone(
                        task_id, scan_target, phase, intent, message, intent_info,
                    )
                except Exception as e:
                    import traceback
                    print(f"[ChatAgent] scan task {task_id} FAILED: {e}")
                    traceback.print_exc()
                    try:
                        tracker.fail_task(task_id, str(e))
                    except:
                        pass

            self._executor.submit(do_scan)

            # 返回 action 触发前端创建流式卡片
            return {
                "type": "action",
                "action": "pentest_started",
                "content": f"🎯 {phase_name}任务已启动\n\n目标: {scan_target}\n\n正在执行{phase_name}，请稍候...",
                "data": {
                    "task_id": task_id,
                    "target": scan_target,
                    "phase": phase,
                    "intent": intent,
                }
            }

        except Exception as e:
            return {
                "type": "error",
                "content": f"任务启动失败：{str(e)}",
            }

    def _extract_target(self, message: str) -> Optional[str]:
        """从消息中提取目标"""
        # URL pattern - 匹配纯ASCII字符，排除中文和特殊符号
        url_pattern = r'https?://[a-zA-Z0-9.:/-]+'
        # IP pattern
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        # Domain pattern
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'

        urls = re.findall(url_pattern, message)
        ips = re.findall(ip_pattern, message)
        domains = re.findall(domain_pattern, message)

        # Priority: URL > IP > Domain
        if urls:
            return urls[0].rstrip('.,;/')
        if ips:
            return ips[0]
        if domains:
            return domains[0]

        return None

    def _handle_start_pentest(self, message: str, intent_info: dict = None) -> Dict[str, Any]:
        """处理启动渗透测试请求 - 立即响应，预分析异步执行"""
        # 优先用 LLM 解析到的目标
        target = (intent_info or {}).get("target") or self._extract_target(message)

        if not target:
            return {
                "type": "text",
                "content": "请提供要测试的目标，例如：\n- 「对 https://example.com 进行渗透测试」\n- 「扫描 192.168.1.1」",
            }

        # 生成任务ID
        task_id = str(uuid.uuid4())

        try:
            # 0. 初始化进度追踪
            from state.progress_tracker import get_progress_tracker
            tracker = get_progress_tracker()
            tracker.start_task(task_id, target)
            tracker.update_phase(task_id, "init", "任务初始化", f"开始渗透测试任务，目标: {target}")

            # 1. 立即在后台线程启动任务，不等预分析
            from agents.orchestrator import run_single_phase_standalone
            self.pending_tasks[task_id] = {
                "target": target,
                "status": "running",
                "celery_task_id": task_id,
                "user_intent": message,
            }

            def do_pentest():
                try:
                    run_single_phase_standalone(
                        task_id, target, "pentest", "full_pentest", message, None,
                    )
                except Exception as e:
                    import traceback
                    print(f"[ChatAgent] pentest task {task_id} FAILED: {e}")
                    traceback.print_exc()
                    try:
                        tracker.fail_task(task_id, str(e))
                    except:
                        pass

            self._executor.submit(do_pentest)

            # 2. 预分析在后台执行（不阻塞响应）
            def do_pre_analysis():
                try:
                    analysis = self._quick_analyze_target(target)
                    rag = self._query_rag_for_target(target, analysis.get("technologies", []))
                    if analysis.get("technologies"):
                        tracker.update_phase(task_id, "init", "目标分析",
                            f"检测到技术栈: {', '.join(analysis['technologies'])}")
                    if rag.get("total", 0) > 0:
                        tracker.update_phase(task_id, "init", "POC匹配",
                            f"知识库匹配到 {rag['total']} 条相关漏洞")
                except Exception as e:
                    print(f"[ChatAgent] 预分析失败: {e}")

            self._executor.submit(do_pre_analysis)

            # 3. 立即返回响应
            return {
                "type": "action",
                "action": "pentest_started",
                "content": (
                    f"🎯 渗透测试任务已启动\n\n"
                    f"目标: {target}\n\n"
                    f"🔍 正在执行信息收集和漏洞扫描..."
                ),
                "data": {
                    "task_id": task_id,
                    "target": target,
                    "phase": "pentest",
                    "intent": "full_pentest",
                }
            }

        except Exception as e:
            return {
                "type": "error",
                "content": f"任务启动失败：{str(e)}",
            }

    def _handle_port_scan(self, message: str) -> Dict[str, Any]:
        """精准端口扫描 - 只做端口扫描"""
        target = self._extract_target(message)

        if not target:
            return {
                "type": "text",
                "content": "请提供要扫描的目标，例如：「对 example.com 做端口扫描」",
            }

        try:
            # 清理URL前缀
            scan_target = target
            if scan_target.startswith("http://"):
                scan_target = scan_target.replace("http://", "")
            elif scan_target.startswith("https://"):
                scan_target = scan_target.replace("https://", "")
            scan_target = scan_target.split("/")[0]  # 只取域名部分

            # 先快速探测主机存活
            ping_result = self.hexstrike_client.execute_command(
                f"nmap -sn -PS21-23,80,443,8080,8443 {scan_target}",
                category="network"
            )

            # 执行端口扫描
            port_result = self.hexstrike_client.execute_command(
                f"nmap -F -sV --version-intensity 5 {scan_target}",
                category="network"
            )

            # 解析端口结果
            open_ports = []
            if port_result.get("success"):
                output = port_result.get("stdout", "")
                for line in output.split("\n"):
                    if "/tcp" in line and "open" in line:
                        parts = line.strip().split()
                        if parts:
                            port_info = parts[0]
                            service = ""
                            for p in parts[1:]:
                                if p != "open":
                                    service += p + " "
                            open_ports.append({
                                "port": port_info.split("/")[0],
                                "protocol": port_info.split("/")[1] if "/" in port_info else "tcp",
                                "service": service.strip()
                            })

            # 构建自然语言回复
            if open_ports:
                response_text = f"""🎯 **端口扫描完成**: {scan_target}

**主机状态**: {'存活' if ping_result.get('success') else '未知'}

**发现 {len(open_ports)} 个开放端口**:
"""
                for p in open_ports:
                    response_text += f"- {p['port']}/{p['protocol']} {p['service']}\n"

                response_text += f"""
**建议**:
- 如需进一步漏洞扫描，请说「对 {scan_target} 进行漏洞扫描」"""
            else:
                response_text = f"""🎯 **端口扫描完成**: {scan_target}

**主机状态**: {'存活' if ping_result.get('success') else '未知'}

**未发现开放端口或扫描超时**"""

            return {
                "type": "result",
                "content": response_text,
                "data": {
                    "target": scan_target,
                    "open_ports": open_ports,
                    "host_alive": ping_result.get("success"),
                }
            }

        except Exception as e:
            return {
                "type": "error",
                "content": f"端口扫描失败：{str(e)}",
            }

    def _handle_sql_injection(self, message: str) -> Dict[str, Any]:
        """SQL注入测试"""
        target = self._extract_target(message)
        if not target:
            return {"type": "text", "content": "请提供测试目标，例如：「对 https://example.com?id=1 做SQL注入测试」"}

        try:
            result = self.hexstrike_client.execute_command(
                f"sqlmap -u {target} --batch --random-agent --disable-precon --disable-anti-csrf",
                category="web_security"
            )
            if result.get("success"):
                output = result.get("stdout", "")[:1000]
                return {
                    "type": "result",
                    "content": f"🎯 **SQL注入测试完成**: {target}\n\n{output}\n\n如需手动验证，可使用 sqlmap 命令。",
                    "data": {"target": target, "output": output}
                }
            else:
                return {"type": "error", "content": f"SQL注入测试失败：{result.get('error', '未知错误')}"}
        except Exception as e:
            return {"type": "error", "content": f"SQL注入测试异常：{str(e)}"}

    def _handle_dir_scan(self, message: str) -> Dict[str, Any]:
        """目录扫描"""
        target = self._extract_target(message)
        if not target:
            return {"type": "text", "content": "请提供测试目标，例如：「对 https://example.com 做目录扫描」"}

        try:
            result = self.hexstrike_client.execute_command(
                f"dirb {target} /usr/share/dirb/wordlists/common.txt",
                category="web_security"
            )
            if result.get("success"):
                output = result.get("stdout", "")[:1500]
                return {
                    "type": "result",
                    "content": f"🎯 **目录扫描完成**: {target}\n\n{output}",
                    "data": {"target": target, "output": output}
                }
            else:
                return {"type": "error", "content": f"目录扫描失败：{result.get('error', '未知错误')}"}
        except Exception as e:
            return {"type": "error", "content": f"目录扫描异常：{str(e)}"}

    def _handle_subdomain_enum(self, message: str) -> Dict[str, Any]:
        """子域名发现"""
        target = self._extract_target(message)
        if not target:
            return {"type": "text", "content": "请提供测试目标，例如：「发现 example.com 的子域名」"}

        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            result = self.hexstrike_client.execute_command(
                f"amass enum -passive -d {domain}",
                category="osint"
            )
            if result.get("success"):
                output = result.get("stdout", "")[:1000]
                return {
                    "type": "result",
                    "content": f"🎯 **子域名发现完成**: {domain}\n\n{output if output.strip() else '未发现子域名'}",
                    "data": {"domain": domain, "output": output}
                }
            else:
                return {"type": "error", "content": f"子域名发现失败：{result.get('error', '未知错误')}"}
        except Exception as e:
            return {"type": "error", "content": f"子域名发现异常：{str(e)}"}

    def _handle_fingerprint(self, message: str) -> Dict[str, Any]:
        """Web指纹识别"""
        target = self._extract_target(message)
        if not target:
            return {"type": "text", "content": "请提供测试目标，例如：「识别 https://example.com 的指纹」"}

        try:
            result = self.hexstrike_client.execute_command(
                f"whatweb {target}",
                category="web_security"
            )
            if result.get("success"):
                output = result.get("stdout", "")[:1000]
                return {
                    "type": "result",
                    "content": f"🎯 **指纹识别完成**: {target}\n\n{output}",
                    "data": {"target": target, "output": output}
                }
            else:
                return {"type": "error", "content": f"指纹识别失败：{result.get('error', '未知错误')}"}
        except Exception as e:
            return {"type": "error", "content": f"指纹识别异常：{str(e)}"}

    def _handle_web_vuln_scan(self, message: str) -> Dict[str, Any]:
        """Web漏洞扫描"""
        target = self._extract_target(message)
        if not target:
            return {"type": "text", "content": "请提供测试目标，例如：「对 https://example.com 做漏洞扫描」"}

        try:
            result = self.hexstrike_client.execute_command(
                f"nikto -h {target} -Format txt -nointeractive",
                category="vuln_scanning"
            )
            if result.get("success"):
                output = result.get("stdout", "")[:1500]
                return {
                    "type": "result",
                    "content": f"🎯 **Web漏洞扫描完成**: {target}\n\n{output}",
                    "data": {"target": target, "output": output}
                }
            else:
                return {"type": "error", "content": f"漏洞扫描失败：{result.get('error', '未知错误')}"}
        except Exception as e:
            return {"type": "error", "content": f"漏洞扫描异常：{str(e)}"}

    def _handle_web_analyze(self, message: str) -> Dict[str, Any]:
        """综合Web分析"""
        target = self._extract_target(message)
        if not target:
            return {"type": "text", "content": "请提供测试目标，例如：「分析 https://example.com」"}

        try:
            # 1. 指纹识别
            fp_result = self.hexstrike_client.execute_command(f"whatweb {target}", category="web_security")
            # 2. 获取页面标题
            title_result = self.hexstrike_client.execute_command(f"curl -sI {target} | grep -i title", category="essential")

            fingerprint = fp_result.get("stdout", "")[:500] if fp_result.get("success") else "获取失败"
            title = title_result.get("stdout", "").strip() if title_result.get("success") else "获取失败"

            return {
                "type": "result",
                "content": f"""🎯 **Web综合分析**: {target}

**页面标题**: {title}
**指纹识别**: {fingerprint}

如需进一步测试，可说「目录扫描」「漏洞扫描」等。""",
                "data": {"target": target, "fingerprint": fingerprint, "title": title}
            }
        except Exception as e:
            return {"type": "error", "content": f"Web分析异常：{str(e)}"}

    def _handle_analyze_target(self, message: str) -> Dict[str, Any]:
        """快速分析目标"""
        target = self._extract_target(message)

        if not target:
            return {
                "type": "text",
                "content": "请提供要分析的目标，例如：「分析 https://example.com」",
            }

        try:
            # 执行快速分析
            analysis = self._quick_analyze_target(target)

            # 查询相关漏洞
            rag_findings = self._query_rag_for_target(target, analysis.get("technologies", []))

            response_text = f"""🔍 **目标分析完成**: {target}

**技术栈识别**:
{analysis.get('summary', '未识别到技术栈')}

**潜在漏洞风险** (基于RAG知识库):
{self._format_rag_findings(rag_findings)}

**建议**:
- 如需完整渗透测试，请说「对 {target} 进行渗透测试」
"""

            return {
                "type": "result",
                "content": response_text,
                "data": {
                    "target": target,
                    "technologies": analysis.get("technologies", []),
                    "rag_findings": rag_findings,
                }
            }

        except Exception as e:
            return {
                "type": "error",
                "content": f"目标分析失败：{str(e)}",
            }

    def _handle_exploit_verify(self, message: str) -> Dict[str, Any]:
        """验证/利用漏洞"""
        target = self._extract_target(message)
        vuln_name = message

        # 提取漏洞名称
        if "验证" in message:
            parts = message.replace("验证", "").replace("漏洞", "").strip()
            vuln_name = parts if parts else None

        if not target:
            return {
                "type": "text",
                "content": "请提供目标，例如：「验证 example.com 的 Log4j 漏洞」",
            }

        try:
            # 从RAG获取POC
            if vuln_name:
                rag_result = self.rag_interface.query(vuln_name, n_results=3)
                poc_info = rag_result.vulnerabilities[0] if rag_result.vulnerabilities else None
            else:
                poc_info = None

            # 使用HexStrike执行验证
            if poc_info and poc_info.poc_content:
                # 执行POC验证
                result = self.hexstrike_client.execute_command(
                    f"echo 'POC验证: {poc_info.name}'",
                    category="essential"
                )
                exploit_result = f"正在验证漏洞: {poc_info.name}\n"
                exploit_result += f"CVE: {poc_info.cve_id or 'N/A'}\n"
                exploit_result += f"严重程度: {poc_info.severity}\n"
                exploit_result += f"POC: {poc_info.poc_content[:200]}..."
            else:
                exploit_result = f"未在知识库中找到 {vuln_name or target} 的POC\n"
                exploit_result += "建议先进行完整渗透测试以发现可用漏洞"

            return {
                "type": "result",
                "content": exploit_result,
                "data": {
                    "target": target,
                    "vulnerability": vuln_name,
                    "poc": poc_info.__dict__ if poc_info else None,
                }
            }

        except Exception as e:
            return {
                "type": "error",
                "content": f"漏洞验证失败：{str(e)}",
            }

    def _handle_query_vulnerability(self, message: str) -> Dict[str, Any]:
        """处理漏洞查询"""
        keywords = message
        for kw in ["漏洞", "查询", "查找", "搜索", "cve", "poc"]:
            keywords = keywords.replace(kw, "")
        keywords = keywords.strip()

        if not keywords:
            return {
                "type": "text",
                "content": "请指定要查询的漏洞关键词，例如：「查询 Log4j 漏洞」或「搜索 SQL注入 POC」",
            }

        # 查询RAG知识库
        result = self.rag_interface.query(
            query_text=keywords,
            n_results=10,
        )

        if result.total_count == 0:
            return {
                "type": "text",
                "content": f"知识库中未找到与「{keywords}」相关的漏洞信息。",
            }

        # 构建响应
        response_text = f"🔬 **漏洞查询结果**: {keywords}\n\n"
        response_text += f"找到 **{result.total_count}** 条相关漏洞：\n\n"

        for vuln in result.vulnerabilities[:10]:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(vuln.severity, "⚪")

            response_text += f"{severity_emoji} **{vuln.name}**\n"
            response_text += f"   产品: {vuln.product or 'N/A'}\n"
            response_text += f"   严重程度: {vuln.severity}"
            if vuln.cvss_score:
                response_text += f" (CVSS: {vuln.cvss_score})"
            response_text += "\n"
            if vuln.cve_id:
                response_text += f"   CVE: `{vuln.cve_id}`\n"
            response_text += f"   相似度: {vuln.similarity:.2f}\n"
            response_text += "\n"

        response_text += "\n**操作建议**:\n"
        response_text += f"- 「验证 {keywords} 漏洞 on [目标]」- 验证该漏洞是否存在于目标\n"
        response_text += f"- 「对 [目标] 进行渗透测试」- 完整测试该目标\n"

        return {
            "type": "result",
            "content": response_text,
            "data": {
                "vulnerabilities": [
                    {
                        "name": v.name,
                        "product": v.product,
                        "severity": v.severity,
                        "cve_id": v.cve_id,
                        "cvss_score": v.cvss_score,
                        "similarity": v.similarity,
                    }
                    for v in result.vulnerabilities[:10]
                ]
            }
        }

    def _handle_query_tool(self, message: str) -> Dict[str, Any]:
        """处理工具查询"""
        # 检查HexStrike连接
        if not self.hexstrike_client.health:
            return {
                "type": "error",
                "content": "⚠️ HexStrike MCP Server 未连接，请检查服务状态",
            }

        tools = self.hexstrike_client.health.get("category_stats", {})
        total_tools = self.hexstrike_client.health.get("total_tools_available", 0)

        response = f"🛠️ **HexStrike 工具生态**\n\n"
        response += f"总可用工具: **{total_tools}**\n\n"

        response += "**工具分类统计**:\n"
        for category, stats in tools.items():
            if isinstance(stats, dict) and "available" in stats:
                available = stats["available"]
                total = stats.get("total", 0)
                response += f"- {category}: {available}/{total}\n"

        response += "\n**核心工具**:\n"
        response += "```\n"
        response += "# 网络扫描\n"
        response += "nmap -sV -sC target.com\n"
        response += "masscan -p1-10000 target.com --rate=1000\n\n"
        response += "# Web漏洞扫描\n"
        response += "nuclei -u https://target.com -severity critical,high\n"
        response += "nikto -h https://target.com\n"
        response += "sqlmap -u \"https://target.com/?id=1\"\n\n"
        response += "# 子域名枚举\n"
        response += "subfinder -d target.com\n"
        response += "amass enum -passive -d target.com\n\n"
        response += "# Web探测\n"
        response += "httpx -u target.com -title -tech-detect\n"
        response += "```\n"

        response += "\n**启动渗透测试**:\n"
        response += "「对 target.com 进行渗透测试」\n"

        return {
            "type": "text",
            "content": response,
        }

    def _handle_status_query(self, message: str) -> Dict[str, Any]:
        """处理状态查询"""
        # 检查是否有正在运行的任务
        running_tasks = []
        for task_id, info in self.pending_tasks.items():
            if info.get("status") == "running":
                # 从进度追踪器获取任务状态
                try:
                    from state.progress_tracker import get_progress_tracker
                    tracker = get_progress_tracker()
                    progress = tracker.get_progress(task_id)
                    state = progress.get("status", "running") if progress else "running"
                except Exception:
                    state = "running"
                running_tasks.append({
                    "task_id": task_id,
                    "target": info.get("target"),
                    "status": state,
                })

        response = "📊 **系统状态**\n\n"

        # 系统组件状态
        response += "**组件状态**:\n"
        response += f"🟢 HexStrike MCP: {'已连接' if self.hexstrike_client.health else '未连接'}\n"
        response += f"🟢 RAG知识库: {self.rag_interface.get_stats().get('total_count', 0)} 条\n"

        # 待审批项
        pending_approvals = []
        for task_id, info in self.pending_tasks.items():
            if info.get("status") == "pending_approval":
                pending_approvals.append(task_id)

        if pending_approvals:
            response += f"\n⏳ **待审批任务**: {len(pending_approvals)}\n"
            for task_id in pending_approvals[:5]:
                response += f"   - `{task_id[:8]}...`\n"

        # 运行中的任务
        if running_tasks:
            response += f"\n🔄 **运行中的任务**: {len(running_tasks)}\n"
            for task in running_tasks:
                response += f"   - `{task['task_id'][:8]}...` | {task['target']} | {task['status']}\n"
        else:
            response += "\n🔄 **运行中的任务**: 无\n"

        response += "\n**快速操作**:\n"
        response += "- 「状态」- 查看当前状态\n"
        response += "- 「对 x.x.x.x 进行渗透测试」- 启动新测试\n"

        return {
            "type": "text",
            "content": response,
        }

    def _handle_help(self) -> Dict[str, Any]:
        """处理帮助请求"""
        help_text = """🐺 **Hati — 追月的狼**

我是 Hati，你的渗透测试伙伴。以下是我能做的事：

**1. 🐺 完整狩猎**
   「对 example.com 进行渗透测试」
   完整流程：Recon → Vuln Scan → Exploit → Report

**2. 🔍 目标嗅探**
   「分析 example.com」
   「侦察目标站点」

**3. 📦 漏洞追踪**
   「查询 Log4j 漏洞」
   「搜索 SQL注入 POC」
   「查 CVE-2021-44228」

**4. ⚡ 快速验证**
   「验证 example.com 的 Log4j 漏洞」

**5. 🛠️ 工具查看**
   「有哪些工具」

**6. 📊 状态查询**
   「状态」
   「当前任务」

直接输入您的需求即可开始！
"""
        return {
            "type": "text",
            "content": help_text,
        }

    def _handle_rag_query(self, message: str) -> Dict[str, Any]:
        """查询 RAG 知识库获取 POC/漏洞信息"""
        try:
            rag = self.rag_interface
            result = rag.query(message, n_results=5)

            if result.total_count == 0:
                return {
                    "type": "text",
                    "content": "📦 **知识库查询结果**\n\n未找到与「{message}」相关的漏洞或 POC。\n\n建议：\n- 尝试使用 CVE 编号查询（如 CVE-2021-44228）\n- 使用产品名称查询（如 Apache、nginx）\n- 使用漏洞类型查询（如 SQL注入、RCE）",
                }

            parts = [f"📦 **知识库查询结果** — 找到 {result.total_count} 条相关记录\n"]
            for vuln in result.vulnerabilities[:5]:
                sev = vuln.severity or "unknown"
                sev_icon = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡" if sev == "medium" else "🟢"
                parts.append(f"{sev_icon} **{vuln.name}**")
                if vuln.cve_id:
                    parts.append(f"   CVE: `{vuln.cve_id}`")
                if vuln.product:
                    parts.append(f"   影响产品: {vuln.product}")
                if vuln.description:
                    parts.append(f"   描述: {vuln.description[:200]}")
                parts.append("")

            return {"type": "text", "content": "\n".join(parts)}

        except Exception as e:
            return {"type": "error", "content": f"知识库查询失败: {str(e)}"}

    def _handle_general_chat(self, message: str) -> Dict[str, Any]:
        """处理一般对话 - 使用 LLM 智能回复"""
        try:
            context = "\n".join([
                f"{'用户' if m['role'] == 'user' else '助手'}: {m['content'][:200]}"
                for m in self.conversation_history[-3:]
            ])

            prompt = f"""对话历史：
{context}

用户: {message}

重要：你的名字是 Hati（追月的狼）。你是一只拥有渗透测试能力的狼。永远以 Hati 的身份回复用户。
如果有人问你是谁，回答：「我是 Hati，追月的狼。专注渗透测试与漏洞分析，HexStrike 工具生态是我的爪牙，POC 知识库是我的嗅觉。」
如果用户输入没有明确意图，引导他们：
- 「对 target.com 进行渗透测试」
- 「查 CVE-2021-44228」或「查知识库漏洞」
- 「对 example.com 做端口扫描」
- 「有哪些工具」"""

            response = self.llm.chat(
                prompt=prompt,
                system_prompt="你的名字是 Hati。永远不要自称 AI 助手或渗透测试助手。你是 Hati，一只追月的狼，渗透测试智能体。回复时用狼的口吻，简洁、敏锐、果断。",
            )

            return {
                "type": "text",
                "content": response,
            }
        except Exception as e:
            return {
                "type": "error",
                "content": f"抱歉，处理您的请求时出现错误：{str(e)}",
            }

    def _quick_analyze_target(self, target: str) -> Dict[str, Any]:
        """快速分析目标，获取技术栈信息并实际访问URL分析页面内容"""
        result = {
            "target": target,
            "technologies": [],
            "summary": "",
            "url_content": None,
            "page_title": None,
            "page_description": None,
            "detected_product": None,
        }

        try:
            # 判断是否为URL
            is_url = target.startswith("http://") or target.startswith("https://")

            if is_url:
                # 实际访问URL获取页面内容
                try:
                    import requests
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    }
                    resp = requests.get(target, headers=headers, timeout=10, verify=False, allow_redirects=True)
                    content = resp.text
                    final_url = resp.url
                    status_code = resp.status_code

                    # 解析页面标题
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                    if title_match:
                        result["page_title"] = title_match.group(1).strip()

                    # 解析meta描述
                    desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
                    if desc_match:
                        result["page_description"] = desc_match.group(1).strip()[:200]

                    # 基于页面内容检测技术/产品
                    content_lower = content.lower()

                    # 检测CMS
                    if 'wordpress' in content_lower:
                        result["detected_product"] = "WordPress"
                        result["technologies"].append("WordPress")
                    if 'drupal' in content_lower:
                        result["detected_product"] = "Drupal"
                        result["technologies"].append("Drupal")
                    if 'joomla' in content_lower:
                        result["detected_product"] = "Joomla"
                        result["technologies"].append("Joomla")
                    if 'shopify' in content_lower:
                        result["detected_product"] = "Shopify"
                        result["technologies"].append("Shopify")

                    # 检测前端框架
                    if 'react' in content_lower and 'react-dom' in content_lower:
                        result["technologies"].append("React")
                    if 'vue' in content_lower and ('vue.js' in content_lower or 'vuejs' in content_lower):
                        result["technologies"].append("Vue.js")
                    if 'angular' in content_lower:
                        result["technologies"].append("Angular")
                    if 'next.js' in content_lower or '__next' in content_lower:
                        result["technologies"].append("Next.js")

                    # 检测服务器类型
                    server = resp.headers.get('server', '').lower()
                    if 'nginx' in server:
                        result["technologies"].append("Nginx")
                    if 'apache' in server:
                        result["technologies"].append("Apache")
                    if 'iis' in server:
                        result["technologies"].append("IIS")

                    # 检测CDN
                    if 'cloudflare' in str(resp.headers).lower():
                        result["technologies"].append("Cloudflare")

                    # 获取页面内容片段（用于上下文介绍）
                    result["url_content"] = {
                        "url": final_url,
                        "status": status_code,
                        "title": result["page_title"],
                        "description": result["page_description"],
                        "server": server,
                        "content_length": len(content),
                        "content_snippet": content[:500] if content else "",
                    }

                    result["summary"] = f"访问成功 [{status_code}] - {result['page_title'] or '未知页面'}"
                    if result["detected_product"]:
                        result["summary"] += f" | 检测到: {result['detected_product']}"

                except Exception as url_err:
                    result["summary"] = f"URL访问失败: {str(url_err)}"

            # 使用HexStrike补充分析
            if self.hexstrike_client.health:
                analysis = self.hexstrike_client.analyze_target(target, analysis_type="quick")
                if analysis.get("success"):
                    for tech in analysis.get("technologies", []):
                        if tech not in result["technologies"]:
                            result["technologies"].append(tech)
                    if not result["summary"]:
                        result["summary"] = analysis.get("summary", "")

            if not result["summary"] and not result["technologies"]:
                # 备用：基于目标域名猜测技术栈
                domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                if "amazon" in domain.lower():
                    result["technologies"] = ["AWS", "CloudFront"]
                elif "azure" in domain.lower():
                    result["technologies"] = ["Azure", "ASP.NET"]
                elif "google" in domain.lower():
                    result["technologies"] = ["GCP", "Google Cloud"]
                if result["technologies"]:
                    result["summary"] = " / ".join(result["technologies"])
                else:
                    result["summary"] = "基于目标特征分析..."

        except Exception as e:
            result["summary"] = f"分析过程出错: {str(e)}"

        return result

    def _query_rag_for_target(self, target: str, technologies: list) -> Dict[str, Any]:
        """查询RAG知识库获取目标相关漏洞"""
        findings = {
            "total": 0,
            "by_severity": {},
            "top_vulnerabilities": [],
        }

        try:
            # 构建查询文本
            query_parts = [target]
            query_parts.extend(technologies)
            query_text = " ".join(query_parts)

            # 查询RAG
            rag_result = self.rag_interface.query(query_text, n_results=10)

            findings["total"] = rag_result.total_count
            findings["by_severity"] = rag_result.by_severity

            for vuln in rag_result.vulnerabilities[:5]:
                findings["top_vulnerabilities"].append({
                    "name": vuln.name,
                    "cve_id": vuln.cve_id,
                    "severity": vuln.severity,
                    "product": vuln.product,
                    "similarity": vuln.similarity,
                })

        except Exception as e:
            findings["error"] = str(e)

        return findings

    def _format_rag_findings(self, findings: Dict[str, Any]) -> str:
        """格式化RAG发现"""
        if not findings or findings.get("total", 0) == 0:
            return "未在知识库中发现相关漏洞信息"

        lines = []
        lines.append(f"知识库中发现 **{findings['total']}** 条相关漏洞：")

        by_severity = findings.get("by_severity", {})
        if by_severity:
            severity_parts = []
            for sev, count in by_severity.items():
                if count > 0:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")
                    severity_parts.append(f"{emoji}{sev}:{count}")
            if severity_parts:
                lines.append(" | ".join(severity_parts))

        top_vulns = findings.get("top_vulnerabilities", [])
        if top_vulns:
            lines.append("\n**高风险漏洞**:")
            for v in top_vulns[:3]:
                lines.append(f"- {v.get('name', 'Unknown')} ({v.get('severity', 'N/A')})")

        return "\n".join(lines)

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务状态（使用进度追踪器，兼容 Celery 和 standalone 模式）"""
        if task_id in self.pending_tasks:
            info = self.pending_tasks[task_id]
            try:
                from state.progress_tracker import get_progress_tracker
                tracker = get_progress_tracker()
                progress = tracker.get_progress(task_id)
                status = progress.get("status", "running") if progress else "running"
                result = progress.get("steps", []) if progress else None
            except Exception:
                status = "running"
                result = None
            return {
                "task_id": task_id,
                "status": status,
                "target": info.get("target"),
                "result": result,
            }
        return None

    def clear_history(self):
        """清除对话历史"""
        self.conversation_history = []