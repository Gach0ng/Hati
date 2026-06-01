"""
Hati - WebSocket API
支持与 Agent 实时对话
"""

import sys

# Fix Unicode output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Celery worker: stdout/stderr is LoggingProxy

import asyncio
import json
from typing import Dict, Any
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from websockets.server import serve

from agents.chat_agent import ChatAgent
from security.audit_logger import AuditLogger


class ConnectionManager:
    """WebSocket 连接管理器"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.chat_agents: Dict[str, ChatAgent] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """接受客户端连接"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.chat_agents[client_id] = ChatAgent()
        print(f"[WS] Client connected: {client_id}")

    def disconnect(self, client_id: str):
        """断开连接"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.chat_agents:
            del self.chat_agents[client_id]
        print(f"[WS] Client disconnected: {client_id}")

    async def send_message(self, client_id: str, message: Dict[str, Any]):
        """发送消息到客户端"""
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_json(message)

    def get_agent(self, client_id: str) -> ChatAgent:
        """获取客户端对应的 Agent"""
        return self.chat_agents.get(client_id)


# 全局连接管理器
manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """
    WebSocket 端点处理函数

    Args:
        websocket: WebSocket 连接
        client_id: 客户端 ID
    """
    await manager.connect(websocket, client_id)

    # 发送欢迎消息
    await manager.send_message(client_id, {
        "type": "welcome",
        "content": """🛡️ **Hati 已连接**

我是 Hati，追月的狼，你的智能渗透测试伙伴。可以帮您：

1. **渗透测试** - 对目标进行完整的安全测试
2. **漏洞查询** - 搜索 CVE/POC 知识库
3. **工具使用** - 了解和使用安全工具
4. **状态查询** - 查看系统状态

请输入您的需求... (输入「帮助」查看更多)""",
        "timestamp": datetime.utcnow().isoformat(),
    })

    try:
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
                audit_logger = AuditLogger()
                audit_logger.log_agent_action(
                    agent="ChatAgent",
                    action="user_message",
                    task_id=client_id,
                    result_summary=user_message[:200],
                )

                # 获取 Agent 处理消息
                agent = manager.get_agent(client_id)
                if agent:
                    # 发送处理中状态
                    await manager.send_message(client_id, {
                        "type": "thinking",
                        "content": "正在处理您的请求...",
                        "timestamp": datetime.utcnow().isoformat(),
                    })

                    # 处理消息（同步调用）
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(None, agent.process_message, user_message)

                    # 发送响应
                    response["timestamp"] = datetime.utcnow().isoformat()
                    await manager.send_message(client_id, response)

            except json.JSONDecodeError:
                await manager.send_message(client_id, {
                    "type": "error",
                    "content": "无效的消息格式，请发送 JSON 格式的消息。",
                    "timestamp": datetime.utcnow().isoformat(),
                })

    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        print(f"[WS] Error: {e}")
        await manager.send_message(client_id, {
            "type": "error",
            "content": f"连接错误: {str(e)}",
            "timestamp": datetime.utcnow().isoformat(),
        })
        manager.disconnect(client_id)


async def broadcast_message(message: Dict[str, Any]):
    """广播消息到所有连接"""
    for client_id in list(manager.active_connections.keys()):
        await manager.send_message(client_id, message)
