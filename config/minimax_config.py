"""
Hati - MiniMax LLM 配置
使用 OpenAI SDK 兼容 MiniMax API
"""

import os
import re
import sys
from typing import Optional
from dotenv import load_dotenv

# 加载 .env 文件（确保环境变量在模块级别可用）
load_dotenv()

# Fix Unicode output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Celery worker: stdout/stderr is LoggingProxy

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

# ===========================================
# 配置常量
# ===========================================
MINIMAX_API_KEY = os.getenv("MINIMAX_API_KEY", "")
MINIMAX_GROUP_ID = os.getenv("MINIMAX_GROUP_ID", "")
MINIMAX_BASE_URL = "https://api.minimax.chat/v1"  # MiniMax API 端点
MINIMAX_MODEL = os.getenv("MINIMAX_MODEL", "MiniMax-M2.7")

# LLM 配置
LLM_TEMPERATURE = 0.7
LLM_MAX_TOKENS = 4096
LLM_TOP_P = 0.95
LLM_REQUEST_TIMEOUT = 180  # 秒


# ===========================================
# MiniMax LLM 客户端
# ===========================================
class MiniMaxLLM:
    """
    MiniMax LLM 客户端封装

    MiniMax API 兼容 OpenAI SDK 格式
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = MINIMAX_MODEL,
        temperature: float = LLM_TEMPERATURE,
        max_tokens: int = LLM_MAX_TOKENS,
        base_url: str = MINIMAX_BASE_URL,
    ):
        """
        初始化 MiniMax LLM 客户端

        Args:
            api_key: MiniMax API Key
            model: 模型名称
            temperature: 温度参数
            max_tokens: 最大 token 数
            base_url: API 端点
        """
        self.api_key = api_key or MINIMAX_API_KEY
        self.group_id = MINIMAX_GROUP_ID
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.base_url = base_url

        if not self.api_key:
            raise ValueError("MINIMAX_API_KEY 环境变量未设置")

        # 构建 extra_headers
        extra_headers = {}
        if self.group_id:
            extra_headers["GroupId"] = self.group_id

        # 创建 ChatOpenAI 实例 (OpenAI SDK 兼容)
        self.llm = ChatOpenAI(
            api_key=self.api_key,
            model=self.model,
            base_url=self.base_url,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            request_timeout=LLM_REQUEST_TIMEOUT,
            extra_headers=extra_headers if extra_headers else None,
        )

        self._total_tokens = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0

        print(f"✅ MiniMax LLM 初始化成功")
        print(f"   模型: {self.model}")
        print(f"   API: {self.base_url}")

    def invoke(
        self,
        messages: list[dict],
        system_prompt: Optional[str] = None,
    ) -> dict:
        """
        调用 LLM

        Args:
            messages: 消息列表 [{"role": "user", "content": "..."}]
            system_prompt: 系统提示词

        Returns:
            {
                "content": str,  # LLM 回复
                "usage": {
                    "total_tokens": int,
                    "prompt_tokens": int,
                    "completion_tokens": int,
                }
            }
        """
        # 构建消息列表
        langchain_messages = []

        # 添加系统提示
        if system_prompt:
            langchain_messages.append(SystemMessage(content=system_prompt))

        # 添加对话消息
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "user":
                langchain_messages.append(HumanMessage(content=content))
            elif role == "assistant":
                langchain_messages.append(AIMessage(content=content))
            else:
                # 其他角色作为 user 处理
                langchain_messages.append(HumanMessage(content=content))

        # 直接调用 LLM
        response = self.llm.invoke(langchain_messages)

        # 提取 token 使用量
        usage = response.usage_metadata if hasattr(response, 'usage_metadata') else {}
        total_tokens = usage.get('total_tokens', 0)
        prompt_tokens = usage.get('prompt_tokens', 0)
        completion_tokens = usage.get('completion_tokens', 0)

        self._total_tokens += total_tokens
        self._prompt_tokens += prompt_tokens
        self._completion_tokens += completion_tokens

        content = response.content
        # 移除 MiniMax 模型的 <think>...</think> 思维链标签
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
        return {
            "content": content,
            "usage": {
                "total_tokens": total_tokens,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        }

    def chat(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        简单的聊天接口

        Args:
            prompt: 用户输入
            system_prompt: 系统提示

        Returns:
            LLM 回复内容
        """
        result = self.invoke(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=system_prompt,
        )
        content = result["content"]
        # 移除 MiniMax 模型的 <think>...</think> 思维链标签
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        return content.strip()

    async def stream_chat(self, prompt: str, system_prompt: Optional[str] = None):
        """
        流式聊天接口，逐 token yeild

        Args:
            prompt: 用户输入
            system_prompt: 系统提示

        Yields:
            每个 token
        """
        import asyncio

        langchain_messages = []
        if system_prompt:
            langchain_messages.append(SystemMessage(content=system_prompt))
        langchain_messages.append(HumanMessage(content=prompt))

        # 使用 astream 异步流式调用
        full_response = ""
        async for event in self.llm.astream(langchain_messages):
            token = event.content if hasattr(event, 'content') else str(event)
            if token:
                full_response += token
        # 移除 <think> 标签后按 token 分割输出
        clean = re.sub(r'<think>.*?</think>', '', full_response, flags=re.DOTALL).strip()
        # 简单按词分割（保留流式体验）
        words = clean.split()
        for i, word in enumerate(words):
            yield word + (" " if i < len(words) - 1 else "")

    @property
    def total_tokens(self) -> int:
        """获取已使用的总 token 数"""
        return self._total_tokens

    def reset_token_count(self):
        """重置 token 计数器"""
        self._total_tokens = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0


# ===========================================
# 全局 LLM 实例 (延迟初始化)
# ===========================================
_llm_instance: Optional[MiniMaxLLM] = None


def get_llm() -> MiniMaxLLM:
    """
    获取全局 LLM 实例 (单例模式)

    Returns:
        MiniMaxLLM 实例
    """
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = MiniMaxLLM()
    return _llm_instance


def reset_llm():
    """重置全局 LLM 实例"""
    global _llm_instance
    _llm_instance = None


# ===========================================
# Agent Prompts
# ===========================================
SYSTEM_PROMPTS = {
    "orchestrator": """你是一个专业的渗透测试任务协调者。

你的职责：
1. 分析当前渗透测试状态
2. 决定下一步最佳行动
3. 协调各子 Agent 工作

决策原则：
- 优先进行信息收集 (recon)
- 发现潜在漏洞后进行漏洞扫描 (vuln_scan)
- 高风险操作需要人工审批 (require_approval)
- 发现漏洞后尝试利用 (exploit)
- 最后生成完整报告 (report)

当前状态包含：
- target: 目标
- current_phase: 当前阶段
- recon_result: 信息收集结果
- vuln_result: 漏洞扫描结果

请分析状态并给出下一步行动建议。""",

    "recon": """你是一个专业的网络安全信息收集 Agent。

你的职责：
1. 收集目标的网络架构信息
2. 发现子域名和 IP 地址
3. 识别开放端口和运行服务
4. 检测使用的技术栈

可用工具：
- nmap: 端口扫描
- subfinder: 子域名发现
- amass: 子域名枚举
- httpx: HTTP探测
- whatweb: 技术识别

输出格式：
{
    "hosts": [{"ip": "", "hostname": "", "os": ""}],
    "subdomains": ["sub.example.com"],
    "open_ports": {"host": [{"port": 80, "service": "http"}]},
    "technologies": {"url": ["tech1", "tech2"]},
    "screenshots": [],
    "fingerprints": {}
}""",

    "vuln": """你是一个专业的漏洞扫描 Agent。

你的职责：
1. 基于信息收集结果进行漏洞检测
2. 使用 nuclei/nikto/sqlmap 等工具扫描
3. 查询 CVE 知识库获取漏洞详情
4. 评估漏洞风险等级

可用工具：
- nuclei: 漏洞扫描
- nikto: Web 服务器扫描
- sqlmap: SQL 注入检测
- nmap: 漏洞脚本扫描

输出格式：
{
    "vulnerabilities": [
        {
            "id": "",
            "cve_id": "CVE-2021-12345",
            "name": "漏洞名称",
            "severity": "critical/high/medium/low",
            "cvss_score": 9.8,
            "description": "",
            "target": "",
            "url": "",
            "evidence": {},
            "poc_path": "",
            "status": "confirmed"
        }
    ],
    "scan_summary": {"total": 0, "critical": 0, ...}
}""",

    "exploit": """你是一个专业的漏洞利用 Agent。

⚠️ 重要：这个 Agent 只生成利用命令，不会自动执行
⚠️ 所有利用操作需要人工审批

你的职责：
1. 分析已确认的漏洞
2. 生成可能的利用命令
3. 评估利用风险
4. 提供详细的利用步骤

注意：
- 只生成命令，不执行
- 高风险操作标记为需要审批
- 提供多个可选方案

输出格式：
{
    "exploit_id": "",
    "target_vulnerability": "",
    "generated_commands": ["命令1", "命令2"],
    "risk_level": "critical/high/medium/low",
    "requires_approval": true,
    "explanation": "利用原理说明"
}""",

    "report": """你是一个专业的渗透测试报告生成 Agent。

你的职责：
1. 汇总所有渗透测试结果
2. 生成结构化的 Markdown 报告
3. 提供风险评估和建议

报告结构：
1. 执行摘要
2. 测试范围
3. 测试方法论
4. 发现的问题（按严重程度排序）
5. 详细发现
6. 风险总结
7. 修复建议
8. 附录

输出：
- markdown_content: 完整的 Markdown 格式报告
- executive_summary: 执行摘要
- risk_summary: 风险统计
""",
}


def get_system_prompt(agent_type: str) -> str:
    """
    获取指定 Agent 类型的系统提示

    Args:
        agent_type: Agent 类型

    Returns:
        系统提示词
    """
    return SYSTEM_PROMPTS.get(agent_type, "你是一个专业的安全助手。")
