"""
Hati - FastAPI 主入口
REST API 接收任务、查询状态、审批利用
"""

import os
import sys
import uuid
import asyncio
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

# Fix Unicode output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Celery worker: stdout/stderr is LoggingProxy

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from celery.result import AsyncResult

# ===========================================
# 配置
# ===========================================
from config.celery_config import celery_app
from security.audit_logger import AuditLogger


# ===========================================
# AI 辅助函数
# ===========================================
async def generate_ai_summary_streaming(websocket: WebSocket, prompt: str) -> str:
    """流式调用AI生成任务总结，逐字发送到前端"""
    try:
        from config.minimax_config import get_llm
        llm = get_llm()
        # 发送一个"开始生成AI总结"的消息
        await websocket.send_json({
            "type": "progress",
            "content": "🤖 **AI正在生成专业总结...**",
            "data": {"phase": "ai_summary", "step": "AI总结生成中"},
            "timestamp": datetime.utcnow().isoformat(),
        })
        # 调用流式接口
        full_response = ""
        async for token in llm.stream_chat(prompt, system_prompt="你是一个专业的渗透测试报告撰写专家，擅长生成清晰、专业、有洞见的测试总结。"):
            full_response += token
            await websocket.send_json({
                "type": "ai_token",
                "content": token,
                "timestamp": datetime.utcnow().isoformat(),
            })
        return full_response if full_response else "测试完成，未发现明显漏洞。"
    except Exception as e:
        print(f"[WS] AI流式总结生成失败: {e}")
        return "测试完成，AI总结生成失败。"


async def generate_ai_summary(prompt: str) -> str:
    """调用AI生成任务总结"""
    try:
        from config.minimax_config import get_llm, get_system_prompt
        llm = get_llm()
        response = llm.chat(
            prompt=prompt,
            system_prompt="你是一个专业的渗透测试报告撰写专家，擅长生成清晰、专业、有洞见的测试总结。"
        )
        # 清理响应，移除可能的JSON格式
        import re
        response = re.sub(r'\{.*\}', '', response, flags=re.DOTALL).strip()
        return response if response else "测试完成，未发现明显漏洞。"
    except Exception as e:
        print(f"[WS] AI总结生成失败: {e}")
        return "测试完成，AI总结生成失败。"


# ===========================================
# Pydantic 模型
# ===========================================
class PentestStartRequest(BaseModel):
    """启动渗透测试请求"""
    target: str = Field(..., description="目标 URL 或 IP")
    scope: list[str] = Field(default=[], description="授权范围")
    authorized_by: str = Field(..., description="授权人")
    task_name: Optional[str] = Field(None, description="任务名称")
    user_intent: Optional[str] = Field(None, description="用户原始意图（如'弱密码测试'）")
    options: Optional[dict] = Field(default={}, description="额外选项")


class PentestStartResponse(BaseModel):
    """启动渗透测试响应"""
    task_id: str
    status: str
    message: str


class PentestStatusResponse(BaseModel):
    """任务状态响应"""
    task_id: str
    status: str
    phase: str
    current_phase: str
    phase_history: list[str]
    pending_approvals: list[dict]


class ExploitApprovalRequest(BaseModel):
    """利用审批请求"""
    task_id: str = Field(..., description="任务 ID")
    exploit_id: str = Field(..., description="利用方案 ID")
    approved: bool = Field(..., description="是否批准")
    approved_by: str = Field(..., description="审批人")
    comment: Optional[str] = Field(None, description="审批意见")


class ExploitApprovalResponse(BaseModel):
    """利用审批响应"""
    task_id: str
    exploit_id: str
    status: str
    message: str


class ReportResponse(BaseModel):
    """报告响应"""
    task_id: str
    report: dict


# ===========================================
# FastAPI 应用
# ===========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期"""
    # 启动时
    print("🚀 Hati API 启动")
    audit_logger = AuditLogger()

    # 懒加载 ChatAgent（避免启动时网络阻塞）
    app.state.chat_agent = None
    print("📦 ChatAgent 将懒加载（首次使用时初始化）")

    yield
    # 关闭时
    print("👋 Hati API 关闭")


app = FastAPI(
    title="Hati API",
    description="Hati（渗透测试智能体） 系统 API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================
# 静态文件服务
# ===========================================
# 获取项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

# 挂载静态文件
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# 挂载报告目录（只读）
app.mount("/reports", StaticFiles(directory=REPORTS_DIR, html=False), name="reports")


# ===========================================
# API 端点
# ===========================================
@app.get("/")
async def root():
    """根路径 - 返回 Web UI"""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/reports")
async def list_reports():
    """列出所有报告"""
    import os
    reports = []
    for f in os.listdir(REPORTS_DIR):
        exts = ('.md', '.json')
        if f.endswith(exts):
            path = os.path.join(REPORTS_DIR, f)
            reports.append({
                "name": f,
                "path": f"/reports/{f}",
                "size": os.path.getsize(path),
                "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
            })
    reports.sort(key=lambda x: x["modified"], reverse=True)
    return {"reports": reports[:50]}


@app.get("/health")
async def health():
    """健康检查"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/api/pentest/start", response_model=PentestStartResponse)
async def start_pentest(request: PentestStartRequest, background_tasks: BackgroundTasks):
    """
    启动渗透测试任务

    Args:
        request: 启动请求

    Returns:
        任务 ID 和状态
    """
    # 生成任务 ID
    task_id = str(uuid.uuid4())

    # 记录审计日志
    audit_logger = AuditLogger()
    audit_logger.log_agent_action(
        agent="API",
        action="task_submitted",
        task_id=task_id,
        target=request.target,
        result_summary=f"任务由 {request.authorized_by} 提交",
    )

    # 发送 Celery 任务
    task = celery_app.send_task(
        "agents.orchestrator.run",
        args=[
            task_id,
            request.target,
            request.scope,
            request.authorized_by,
            request.user_intent or "",
        ],
        task_id=task_id,
    )

    return PentestStartResponse(
        task_id=task_id,
        status="queued",
        message=f"渗透测试任务已提交，目标: {request.target}",
    )


@app.get("/api/pentest/status/{task_id}", response_model=PentestStatusResponse)
async def get_status(task_id: str):
    """
    获取任务状态

    Args:
        task_id: 任务 ID

    Returns:
        任务状态信息
    """
    # 获取 Celery 任务结果
    task_result = AsyncResult(task_id, app=celery_app)

    # 获取任务状态
    status = task_result.state.lower()

    # 尝试获取结果
    result_data = None
    if task_result.ready():
        try:
            result_data = task_result.get(timeout=1)
        except Exception:
            pass

    # 提取阶段信息
    current_phase = "unknown"
    phase_history = []
    pending_approvals = []

    if result_data:
        current_phase = result_data.get("phase_history", ["unknown"])[-1] if result_data.get("phase_history") else "unknown"
        phase_history = result_data.get("phase_history", [])
        if result_data.get("report"):
            pending_approvals = result_data["report"].get("pending_approvals", [])

    return PentestStatusResponse(
        task_id=task_id,
        status=status,
        phase=current_phase,
        current_phase=current_phase,
        phase_history=phase_history,
        pending_approvals=pending_approvals,
    )


@app.post("/api/exploit/approve", response_model=ExploitApprovalResponse)
async def approve_exploit(request: ExploitApprovalRequest):
    """
    审批漏洞利用

    Args:
        request: 审批请求

    Returns:
        审批结果
    """
    # 记录审批
    audit_logger = AuditLogger()
    audit_logger.log_approval(
        task_id=request.task_id,
        exploit_id=request.exploit_id,
        approved=request.approved,
        approved_by=request.approved_by,
        comment=request.comment,
    )

    if request.approved:
        # 发送执行任务
        celery_app.send_task(
            "agents.exploit_agent.execute",
            args=[request.task_id, request.exploit_id],
        )
        message = "利用方案已批准，正在执行"
    else:
        message = "利用方案已拒绝"

    return ExploitApprovalResponse(
        task_id=request.task_id,
        exploit_id=request.exploit_id,
        status="approved" if request.approved else "rejected",
        message=message,
    )


@app.get("/api/pentest/report/{task_id}", response_model=ReportResponse)
async def get_report(task_id: str):
    """
    获取渗透测试报告

    Args:
        task_id: 任务 ID

    Returns:
        报告内容
    """
    task_result = AsyncResult(task_id, app=celery_app)

    if not task_result.ready():
        raise HTTPException(status_code=404, detail="报告尚未生成")

    try:
        result_data = task_result.get(timeout=5)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not result_data or not result_data.get("report"):
        raise HTTPException(status_code=404, detail="报告不存在")

    return ReportResponse(
        task_id=task_id,
        report=result_data["report"],
    )


@app.get("/api/pentest/list")
async def list_tasks():
    """
    列出所有任务

    Returns:
        任务列表
    """
    # TODO: 实现任务列表查询
    return {
        "message": "任务列表功能开发中",
        "tasks": [],
    }


@app.delete("/api/pentest/cancel/{task_id}")
async def cancel_task(task_id: str):
    """
    取消任务

    Args:
        task_id: 任务 ID

    Returns:
        取消结果
    """
    task_result = AsyncResult(task_id, app=celery_app)
    task_result.revoke(terminate=True)

    audit_logger = AuditLogger()
    audit_logger.log_agent_action(
        agent="API",
        action="task_cancelled",
        task_id=task_id,
        result_summary="任务被取消",
    )

    return {
        "task_id": task_id,
        "status": "cancelled",
        "message": "任务已取消",
    }


# ===========================================
# WebSocket 端点
# ===========================================
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """
    WebSocket 端点 - 支持与 Agent 实时对话

    Args:
        websocket: WebSocket 连接
        client_id: 客户端 ID
    """
    from agents.chat_agent import ChatAgent
    from security.audit_logger import AuditLogger
    from celery.result import AsyncResult
    import asyncio
    import json

    # 接受连接
    await websocket.accept()
    chat_agent = websocket.app.state.chat_agent

    # 懒加载 ChatAgent（如需要）
    if chat_agent is None:
        print(f"[WS] Lazily initializing ChatAgent...")
        try:
            from agents.chat_agent import ChatAgent
            chat_agent = ChatAgent()
            websocket.app.state.chat_agent = chat_agent
            print(f"[WS] ChatAgent initialized successfully")
        except Exception as e:
            print(f"[WS] ChatAgent initialization failed: {e}")
            await websocket.send_json({
                "type": "error",
                "content": f"⚠️ ChatAgent 初始化失败: {str(e)[:100]}",
                "timestamp": datetime.utcnow().isoformat(),
            })
            await websocket.close()
            return

    # 每个新连接都是新对话，清除历史避免上下文泄露
    chat_agent.conversation_history = []

    active_tasks = {}  # 存储活动任务 {task_id: {"target": str, "status": str, "phase": str}}

    print(f"[WS] Client connected: {client_id}, conversation history cleared")

    async def poll_task_progress(task_id: str, target: str):
        """后台任务：轮询Redis进度数据并实时推送"""
        from state.progress_tracker import get_progress_tracker
        tracker = get_progress_tracker()

        last_sent_step_index = -1
        poll_count = 0
        max_polls = 180  # 最多轮询6分钟 (2秒 * 180)

        phase_names = {
            "init": "初始化",
            "recon": "🔍 信息收集",
            "vuln_scan": "🔬 漏洞扫描",
            "exploit": "💥 漏洞利用",
            "report": "📋 报告生成",
            "complete": "✅ 完成",
        }

        def send_step(step_data: dict, phase_names: dict) -> str:
            """发送单个步骤到WebSocket"""
            step_phase = step_data.get("phase", "")
            step_name = step_data.get("step", "")
            step_details = step_data.get("details", "")
            step_reasoning = step_data.get("reasoning", "")
            step_tool = step_data.get("tool", "")
            step_command = step_data.get("command", "")
            phase_text = phase_names.get(step_phase, step_phase)
            full_content = f"**{phase_text}** - {step_name}\n\n{step_details}"
            return full_content, step_phase, step_name, step_details, step_reasoning, step_tool, step_command

        while poll_count < max_polls:
            try:
                await asyncio.sleep(2)
                poll_count += 1

                progress_data = tracker.get_progress(task_id)

                # 不再依赖 Celery（ThreadPoolExecutor 路径），直接检查进度状态
                is_done = (progress_data and
                           progress_data.get("status") in ("completed", "failed"))
                if is_done:
                    print(f"[WS] Task {task_id[:12]} DONE detected: status={progress_data.get('status')}, steps={len(progress_data.get('steps', []))}")
                celery_state = "SUCCESS" if (progress_data or {}).get("status") == "completed" else (
                    "FAILURE" if (progress_data or {}).get("status") == "failed" else "PENDING")

                if progress_data:
                    steps = progress_data.get("steps", [])

                    # 发送新增的步骤
                    new_steps_count = len(steps) - (last_sent_step_index + 1)
                    if new_steps_count > 0:
                        for i in range(last_sent_step_index + 1, len(steps)):
                            step_data = steps[i]
                            (full_content, step_phase, step_name, step_details,
                             step_reasoning, step_tool, step_command) = send_step(step_data, phase_names)
                            await websocket.send_json({
                                "type": "progress",
                                "content": full_content,
                                "data": {
                                    "task_id": task_id,
                                    "step": step_name,
                                    "phase": step_phase,
                                    "details": step_details,
                                    "reasoning": step_reasoning,
                                    "tool": step_tool,
                                    "command": step_command,
                                },
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                            last_sent_step_index = i

                    # 任务完成 — 确保 result 消息一定发送
                    if is_done:
                        try:
                            phase_history = progress_data.get("phase_history", [])
                            findings = progress_data.get("findings", {})
                            status_text = "✅ 渗透测试完成！" if celery_state == "SUCCESS" else f"❌ 任务失败: {celery_state}"

                            steps = progress_data.get("steps", [])
                            vulns_found = [s for s in steps if "🚨" in s.get("step", "") or "漏洞" in s.get("step", "")]
                            tool_usage = {}
                            for s in steps:
                                tool = s.get("tool", "")
                                if tool:
                                    tool_usage[tool] = tool_usage.get(tool, 0) + 1

                            # 快速完成摘要（不阻塞）
                            print(f"[WS] Task {task_id} done, {len(steps)} steps, {len(vulns_found)} vulns, sending result")
                            ai_summary = f"共执行 {len(steps)} 个检测步骤"

                            # 构建内容
                            content = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 渗透测试任务完成
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{status_text}

**目标**: {target}

{ai_summary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 任务详情
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
                            content += f"**执行流程**: {' → '.join(phase_history) if phase_history else 'N/A'}\n"
                            content += f"**总步骤数**: {len(steps)} 个\n"

                            if vulns_found:
                                content += f"\n**🚨 漏洞统计**: 发现 {len(vulns_found)} 个安全漏洞\n"
                                vuln_by_type = {}
                                for v in vulns_found:
                                    step = v.get("step", "")
                                    if "SQL" in step or "sqli" in step.lower():
                                        vuln_type = "SQL注入"
                                    elif "XSS" in step or "xss" in step.lower():
                                        vuln_type = "XSS跨站脚本"
                                    elif "RCE" in step or "rce" in step.lower():
                                        vuln_type = "远程代码执行"
                                    elif "LFI" in step or "lfi" in step.lower():
                                        vuln_type = "本地文件包含"
                                    else:
                                        vuln_type = "其他漏洞"
                                    vuln_by_type[vuln_type] = vuln_by_type.get(vuln_type, 0) + 1
                                for vtype, count in vuln_by_type.items():
                                    content += f"   • {vtype}: {count} 个\n"

                            if tool_usage:
                                content += "\n**🔧 工具使用统计**:\n"
                                for tool, count in sorted(tool_usage.items(), key=lambda x: -x[1])[:10]:
                                    content += f"   • {tool}: {count} 次\n"

                            payloads = [s.get('command', '') for s in steps
                                        if s.get('command') and s.get('command') != 'N/A' and len(str(s.get('command', ''))) > 5]
                            if payloads:
                                content += "\n**💉 攻击Payload示例** (前3个):\n"
                                for p in payloads[:3]:
                                    p_str = str(p)[:60] + "..." if len(str(p)) > 60 else str(p)
                                    content += f"   • `{p_str}`\n"

                            content += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

                            import os, re
                            # 优先使用 orchestrator 生成的报告路径
                            findings = progress_data.get("findings", {})
                            report_path = findings.get("report_md_path", "")
                            report_json_path = findings.get("report_json_path", "")
                            # 如果没有（旧版或异常），退回构造路径
                            if not report_path:
                                safe_target = re.sub(r'[^\w\-_.]', '_', target)
                                safe_target = safe_target.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
                                if len(safe_target) > 50:
                                    safe_target = safe_target[:50]
                                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                                report_path = f"/reports/{timestamp}_{safe_target}_{task_id[:8]}.md"
                                report_json_path = f"/reports/{timestamp}_{safe_target}_{task_id[:8]}.json"

                            await websocket.send_json({
                                "type": "result",
                                "content": content,
                                "data": {
                                    "task_id": task_id,
                                    "status": celery_state,
                                    "phase": "complete",
                                    "phase_history": phase_history,
                                    "findings": findings,
                                    "steps": steps,
                                    "ai_summary": ai_summary,
                                    "report_path": report_path,
                                    "report_json_path": report_json_path,
                                },
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                            print(f"[WS] Result sent for {task_id}")

                        except Exception as e:
                            error_msg = str(e)
                            print(f"[WS] Failed to send result for {task_id}: {error_msg}")
                            if "websocket" in error_msg.lower():
                                break
                            # 非 websocket 错误也 break，避免死循环
                            break

                        finally:
                            if task_id in active_tasks:
                                del active_tasks[task_id]
                            break

            except asyncio.CancelledError:
                print(f"[WS] Task polling cancelled for {task_id}")
                break
            except Exception as e:
                error_msg = str(e)
                print(f"[WS] Polling error: {error_msg}")
                # 如果WebSocket已关闭，直接退出
                if "websocket.send" in error_msg or "websocket.close" in error_msg:
                    print(f"[WS] WebSocket closed, stopping polling for {task_id}")
                    break
                await asyncio.sleep(5)

    try:
        # 发送欢迎消息（确保连接已建立）
        await websocket.send_json({
            "type": "welcome",
            "content": """🐺 **Hati 已连接**

我是 Hati，追月的狼，你的智能渗透测试伙伴。

**🔍 信息侦察**
- 「对 example.com 做端口扫描」
- 「识别 https://example.com 的指纹」
- 「对 example.com 做目录扫描」
- 「发现 example.com 的子域名」

**📦 漏洞狩猎**
- 「查知识库漏洞」或「查 CVE-2021-44228」
- 「对 example.com 做 SQL 注入」
- 「对 example.com 做漏洞扫描」

**🐺 完整渗透**
- 「对 example.com 进行渗透测试」

**❓ 其他**
- 「有哪些工具」
- 「帮助」

告诉我你的目标，Hati 为你狩猎。""",
            "timestamp": datetime.utcnow().isoformat(),
        })

        while True:
            # 接收消息
            data = await websocket.receive_text()

            try:
                # 解析消息
                message_data = json.loads(data)
                user_message = message_data.get("content", "").strip()

                if not user_message:
                    continue

                # 记录审计日志
                try:
                    audit_logger = AuditLogger()
                    audit_logger.log_agent_action(
                        agent="ChatAgent",
                        action="user_message",
                        task_id=client_id,
                        result_summary=user_message[:200],
                    )
                except Exception as e:
                    print(f"[WS] Audit log error: {e}")

                # 发送处理中状态
                await websocket.send_json({
                    "type": "thinking",
                    "content": "正在处理您的请求...",
                    "timestamp": datetime.utcnow().isoformat(),
                })

                # 处理消息（同步调用）
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(None, chat_agent.process_message, user_message)

                # 发送响应
                response["timestamp"] = datetime.utcnow().isoformat()
                print(f"[WS] Sending response: type={response.get('type')}, content_len={len(response.get('content',''))}")
                await websocket.send_json(response)
                print(f"[WS] Response sent successfully")

                # 如果是渗透测试任务启动，启动后台进度轮询
                if response.get("type") == "action" and response.get("action") == "pentest_started":
                    task_id = response.get("data", {}).get("task_id")
                    target = response.get("data", {}).get("target")

                    if task_id:
                        # 启动后台轮询任务
                        poll_task = asyncio.create_task(poll_task_progress(task_id, target))
                        active_tasks[task_id] = {
                            "target": target,
                            "status": "running",
                            "phase": "recon",
                            "poll_task": poll_task,
                        }
                        print(f"[WS] Started polling task {task_id} for {target}")

            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "content": "无效的消息格式，请发送 JSON 格式的消息。",
                    "timestamp": datetime.utcnow().isoformat(),
                })

    except Exception as e:
        import traceback
        print(f"[WS] Error: {e}")
        traceback.print_exc()
    finally:
        # 取消所有轮询任务
        for task_id in list(active_tasks.keys()):
            if "poll_task" in active_tasks[task_id]:
                active_tasks[task_id]["poll_task"].cancel()
                print(f"[WS] Cancelled polling for {task_id}")
        print(f"[WS] Client disconnected: {client_id}")


# ===========================================
# 主程序入口
# ===========================================
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("API_PORT", "8000"))
    host = os.getenv("API_HOST", "0.0.0.0")

    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
