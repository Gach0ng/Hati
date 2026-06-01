"""
Pentest Agent - 审计日志
将 Agent 决策链、工具调用记录到 Elasticsearch
"""

import os
import json
from datetime import datetime
from typing import Optional, Dict, Any

# ===========================================
# 配置
# ===========================================
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")
ES_URL = f"http://{ES_HOST}:{ES_PORT}"
INDEX_PREFIX = "pentest-logs"


# ===========================================
# 审计日志类
# ===========================================
class AuditLogger:
    """
    审计日志记录器

    将所有 Agent 行为记录到 Elasticsearch
    """

    _instance: Optional["AuditLogger"] = None
    _es: Optional[Any] = None  # Elasticsearch client (lazy import)

    def __new__(cls):
        """单例模式"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.index_prefix = INDEX_PREFIX

        # 尝试连接 Elasticsearch (lazy import for Windows compatibility)
        try:
            from elasticsearch import Elasticsearch
            self._es = Elasticsearch(
                [ES_URL],
                verify_certs=False,
                request_timeout=10,
            )
            # 测试连接
            if self._es.ping():
                print(f"✅ Elasticsearch 连接成功: {ES_URL}")
            else:
                print(f"⚠️  Elasticsearch 连接失败，将使用本地日志")
                self._es = None
        except ImportError:
            print(f"⚠️  Elasticsearch 包未安装，将使用本地日志")
            self._es = None
        except Exception as e:
            print(f"⚠️  Elasticsearch 连接失败: {e}")
            self._es = None

    def _get_index_name(self) -> str:
        """获取当前索引名称（按日期）"""
        return f"{self.index_prefix}-{datetime.utcnow().strftime('%Y.%m.%d')}"

    def log(
        self,
        document: Dict[str, Any],
    ) -> bool:
        """
        记录日志到 Elasticsearch

        Args:
            document: 日志文档

        Returns:
            是否成功
        """
        if self._es is None:
            # Elasticsearch 不可用时打印到控制台
            print(f"[AUDIT] {json.dumps(document, ensure_ascii=False)}")
            return True

        try:
            # 添加时间戳
            document["@timestamp"] = datetime.utcnow().isoformat()
            document["timestamp"] = datetime.utcnow().isoformat()

            # 写入索引
            self._es.index(
                index=self._get_index_name(),
                document=document,
            )
            return True

        except Exception as e:
            print(f"❌ 审计日志写入失败: {e}")
            return False

    def log_agent_action(
        self,
        agent: str,
        action: str,
        task_id: str,
        target: str = "",
        tool: str = None,
        command: str = None,
        result_summary: str = None,
        status: str = "success",
        risk_level: str = "low",
        approved_by: str = None,
        phase: str = None,
        reasoning: str = None,
        llm_tokens: int = None,
        **kwargs,
    ) -> bool:
        """
        记录 Agent 动作

        Args:
            agent: Agent 名称
            action: 执行的动作
            task_id: 任务 ID
            target: 目标
            tool: 使用的工具
            command: 执行的命令
            result_summary: 结果摘要
            status: 状态
            risk_level: 风险等级
            approved_by: 审批人
            phase: 当前阶段
            reasoning: 推理过程
            llm_tokens: LLM 使用 token 数

        Returns:
            是否成功
        """
        document = {
            "agent": agent,
            "action": action,
            "task_id": task_id,
            "target": target,
            "status": status,
            "risk_level": risk_level,
        }

        if tool:
            document["tool"] = tool
        if command:
            document["command"] = command
        if result_summary:
            document["result_summary"] = result_summary
        if approved_by:
            document["approved_by"] = approved_by
        if phase:
            document["phase"] = phase
        if reasoning:
            document["reasoning"] = reasoning
        if llm_tokens is not None:
            document["llm_tokens_used"] = llm_tokens

        # 添加额外字段
        document.update(kwargs)

        return self.log(document)

    def log_decision(
        self,
        task_id: str,
        agent: str,
        decision: str,
        reasoning: str,
        state_snapshot: dict = None,
        llm_model: str = None,
        llm_tokens: int = None,
    ) -> bool:
        """
        记录 LLM 决策

        Args:
            task_id: 任务 ID
            agent: Agent 名称
            decision: 做出的决策
            reasoning: 推理过程
            state_snapshot: 状态快照
            llm_model: 使用的 LLM 模型
            llm_tokens: LLM token 使用量

        Returns:
            是否成功
        """
        document = {
            "agent": agent,
            "action": "llm_decision",
            "task_id": task_id,
            "decision": decision,
            "reasoning": reasoning,
            "status": "success",
            "risk_level": "low",
        }

        if state_snapshot:
            document["state_snapshot"] = json.dumps(state_snapshot)
        if llm_model:
            document["llm_model"] = llm_model
        if llm_tokens is not None:
            document["llm_tokens_used"] = llm_tokens

        return self.log(document)

    def log_tool_execution(
        self,
        task_id: str,
        agent: str,
        tool: str,
        command: str,
        result: dict,
        duration_ms: int = None,
        risk_level: str = "medium",
    ) -> bool:
        """
        记录工具执行

        Args:
            task_id: 任务 ID
            agent: Agent 名称
            tool: 工具名称
            command: 执行的命令
            result: 执行结果
            duration_ms: 执行时长（毫秒）
            risk_level: 风险等级

        Returns:
            是否成功
        """
        success = result.get("success", False)

        document = {
            "agent": agent,
            "action": "tool_execution",
            "tool": tool,
            "task_id": task_id,
            "command": command,
            "status": "success" if success else "failure",
            "result_summary": result.get("stdout", "")[:500] if success else result.get("error", ""),
            "return_code": result.get("return_code", -1),
            "duration_ms": duration_ms,
            "risk_level": risk_level,
        }

        if not success:
            document["error_message"] = result.get("stderr", "")

        return self.log(document)

    def log_approval(
        self,
        task_id: str,
        exploit_id: str,
        approved: bool,
        approved_by: str,
        comment: str = None,
    ) -> bool:
        """
        记录审批决策

        Args:
            task_id: 任务 ID
            exploit_id: 利用方案 ID
            approved: 是否批准
            approved_by: 审批人
            comment: 审批意见

        Returns:
            是否成功
        """
        document = {
            "agent": "HumanReviewer",
            "action": "exploit_approval" if approved else "exploit_rejection",
            "task_id": task_id,
            "exploit_id": exploit_id,
            "approved": approved,
            "approved_by": approved_by,
            "status": "success",
            "risk_level": "critical",
        }

        if comment:
            document["approval_comment"] = comment

        return self.log(document)


# ===========================================
# 便捷函数
# ===========================================
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """获取审计日志实例"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_agent_action(**kwargs) -> bool:
    """便捷的日志记录函数"""
    return get_audit_logger().log_agent_action(**kwargs)
