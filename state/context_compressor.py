"""
Pentest Agent - 上下文压缩器
减少 KV-cache 失效，控制 token 消耗

触发条件：token 达到上下文窗口的 70%
压缩策略：保留最近轮次 + 压缩摘要 + Todo
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass


# ===========================================
# 配置
# ===========================================
CONTEXT_WINDOW = 128000  # MiniMax 上下文窗口
TOKEN_THRESHOLD_RATIO = 0.7  # 70% 时触发压缩
KEEP_RECENT_ROUNDS = 3  # 保留最近 3 轮完整交互


# ===========================================
# 消息结构
# ===========================================
@dataclass
class Message:
    """对话消息"""
    role: str  # system/user/assistant
    content: str
    token_count: int = 0


# ===========================================
# 上下文压缩器
# ===========================================
class ContextCompressor:
    """
    上下文压缩器

    当 token 达到阈值时，触发压缩：
    1. 保留最近 N 轮完整交互
    2. 将早期交互压缩为摘要
    3. 保留 Todo 列表和关键状态
    """

    def __init__(
        self,
        context_window: int = CONTEXT_WINDOW,
        threshold_ratio: float = TOKEN_THRESHOLD_RATIO,
        keep_recent: int = KEEP_RECENT_ROUNDS,
    ):
        self.context_window = context_window
        self.threshold = int(context_window * threshold_ratio)
        self.keep_recent = keep_recent

    def should_compress(self, messages: List[Message]) -> bool:
        """
        检查是否需要压缩

        Args:
            messages: 消息列表

        Returns:
            True 如果需要压缩
        """
        total_tokens = sum(m.token_count for m in messages)
        return total_tokens > self.threshold

    def estimate_tokens(self, text: str) -> int:
        """
        粗略估算 token 数

        中文约 1 token/字符，英文约 1 token/4 字符
        """
        if not text:
            return 0
        # 简化估算
        return len(text) // 4 + len(text)

    def compress(self, messages: List[Message]) -> List[Message]:
        """
        压缩上下文

        Args:
            messages: 原始消息列表

        Returns:
            压缩后的消息列表
        """
        if len(messages) <= self.keep_recent * 2:
            return messages  # 消息太少，不需要压缩

        # 分离系统消息、近期消息、早期消息
        system_msgs = [m for m in messages if m.role == "system"]
        other_msgs = [m for m in messages if m.role != "system"]

        # 保留最近的交互
        recent = other_msgs[-self.keep_recent * 2:]  # user + assistant 对
        early = other_msgs[:-self.keep_recent * 2]

        # 压缩早期消息
        if early:
            compressed_early = self._summarize_messages(early)
            compressed_msg = Message(
                role="system",
                content=f"[早期对话压缩摘要]\n{compressed_early}",
                token_count=self.estimate_tokens(compressed_early)
            )
            # 替换为压缩后的摘要
            early_summary = [compressed_msg]
        else:
            early_summary = []

        # 组合结果
        result = system_msgs + early_summary + recent

        print(f"[ContextCompressor] 压缩完成: {len(messages)} -> {len(result)} 条消息")

        return result

    def _summarize_messages(self, messages: List[Message]) -> str:
        """
        将多条消息压缩为摘要

        Args:
            messages: 要压缩的消息列表

        Returns:
            压缩摘要
        """
        summary_parts = []

        # 按角色分组
        user_msgs = [m.content for m in messages if m.role == "user"]
        assistant_msgs = [m.content for m in messages if m.role == "assistant"]

        if user_msgs:
            # 提取关键操作
            actions = []
            for content in user_msgs[-10:]:  # 只看最近 10 条
                if "action" in content.lower():
                    # 提取 action 关键词
                    lines = content.split('\n')
                    for line in lines:
                        if 'action' in line.lower() or '攻击' in line or '扫描' in line:
                            actions.append(line.strip()[:100])
            if actions:
                summary_parts.append(f"执行的操作: {'; '.join(actions[:5])}")

        if assistant_msgs:
            # 提取关键发现
            findings = []
            for content in assistant_msgs[-10:]:
                if any(kw in content.lower() for kw in ['vuln', 'cve', '发现', '漏洞']):
                    lines = content.split('\n')
                    for line in lines:
                        if any(kw in line.lower() for kw in ['cve-', '漏洞', '发现']):
                            findings.append(line.strip()[:100])
            if findings:
                summary_parts.append(f"关键发现: {'; '.join(findings[:5])}")

        # 生成摘要
        if summary_parts:
            return "\n".join(summary_parts)
        else:
            return f"[共 {len(messages)} 条消息，已压缩]"


# ===========================================
# 压缩后的状态转换
# ===========================================
def create_compressed_state(
    original_state: Dict[str, Any],
    compression_summary: str
) -> Dict[str, Any]:
    """
    创建压缩后的状态

    Args:
        original_state: 原始状态
        compression_summary: 压缩摘要

    Returns:
        压缩后的状态
    """
    compressed = original_state.copy()

    # 添加压缩元数据
    compressed["_compression"] = {
        "applied": True,
        "summary": compression_summary,
        "original_tokens": original_state.get("llm_tokens_used", 0),
    }

    # 保留关键字段
    key_fields = [
        "task_id", "target", "scope", "authorized_by",
        "current_phase", "phase_history",
        "recon_result", "vuln_result", "exploit_results",
        "status", "todo_list", "error_history",
        "pending_approvals"
    ]

    # 清理大型原始数据
    if "agent_messages" in compressed:
        # 只保留最近的 agent 消息
        agent_msgs = compressed["agent_messages"]
        if len(agent_msgs) > 10:
            compressed["agent_messages"] = agent_msgs[-10:]
            compressed["_compression"]["agent_messages_truncated"] = len(agent_msgs) - 10

    return compressed


# ===========================================
# 全局实例
# ===========================================
_compressor: Optional[ContextCompressor] = None


def get_context_compressor() -> ContextCompressor:
    """获取全局上下文压缩器"""
    global _compressor
    if _compressor is None:
        _compressor = ContextCompressor()
    return _compressor
