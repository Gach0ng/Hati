"""
Pentest Agent - 任务进度追踪器
使用 Redis 存储实时进度，供 WebSocket 轮询读取
"""

import json
import redis
import os
from typing import Optional, Dict, Any
from datetime import datetime

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB_PROGRESS = int(os.getenv("REDIS_DB_PROGRESS", "2"))


class TaskProgressTracker:
    """
    任务进度追踪器

    将任务进度实时写入 Redis，WebSocket 通过轮询读取
    """

    def __init__(self):
        self.redis = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB_PROGRESS,
            decode_responses=True
        )
        self.prefix = "pentest:progress:"

    def _key(self, task_id: str) -> str:
        return f"{self.prefix}{task_id}"

    def start_task(self, task_id: str, target: str) -> None:
        """开始新任务"""
        data = {
            "task_id": task_id,
            "target": target,
            "status": "running",
            "current_phase": "init",
            "phase_history": ["init"],
            "steps": [],
            "findings": {},
            "start_time": datetime.utcnow().isoformat(),
            "last_update": datetime.utcnow().isoformat(),
        }
        self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def update_phase(self, task_id: str, phase: str, step: str, details: str = "",
                    reasoning: str = "", tool: str = "", command: str = "") -> None:
        """更新当前阶段和步骤"""
        data = self.get_progress(task_id)
        if data:
            data["current_phase"] = phase
            if phase not in data["phase_history"]:
                data["phase_history"].append(phase)
            data["steps"].append({
                "phase": phase,
                "step": step,
                "details": details,
                "reasoning": reasoning,  # AI思考/决策
                "tool": tool,             # 调用的工具
                "command": command,       # 实际命令
                "timestamp": datetime.utcnow().isoformat()
            })
            data["last_update"] = datetime.utcnow().isoformat()
            self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def add_finding(self, task_id: str, key: str, value: Any) -> None:
        """添加发现结果"""
        data = self.get_progress(task_id)
        if data:
            data["findings"][key] = value
            data["last_update"] = datetime.utcnow().isoformat()
            self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def add_rag_result(self, task_id: str, query: str, results: list) -> None:
        """添加RAG查询结果"""
        data = self.get_progress(task_id)
        if data:
            if "rag_queries" not in data:
                data["rag_queries"] = []
            data["rag_queries"].append({
                "query": query,
                "results": results,
                "timestamp": datetime.utcnow().isoformat()
            })
            data["last_update"] = datetime.utcnow().isoformat()
            self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def complete_phase(self, task_id: str, phase: str, summary: str) -> None:
        """完成一个阶段"""
        data = self.get_progress(task_id)
        if data:
            data["steps"].append({
                "phase": phase,
                "step": "complete",
                "details": summary,
                "timestamp": datetime.utcnow().isoformat()
            })
            data["last_update"] = datetime.utcnow().isoformat()
            self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def complete_task(self, task_id: str, final_summary: str) -> None:
        """完成任务"""
        data = self.get_progress(task_id)
        if data:
            data["status"] = "completed"
            data["current_phase"] = "complete"
            data["phase_history"].append("complete")
            data["final_summary"] = final_summary
            data["end_time"] = datetime.utcnow().isoformat()
            data["last_update"] = datetime.utcnow().isoformat()
            self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def fail_task(self, task_id: str, error: str) -> None:
        """任务失败"""
        data = self.get_progress(task_id)
        if data:
            data["status"] = "failed"
            data["error"] = error
            data["end_time"] = datetime.utcnow().isoformat()
            data["last_update"] = datetime.utcnow().isoformat()
            self.redis.set(self._key(task_id), json.dumps(data), ex=86400)

    def get_progress(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务进度"""
        data = self.redis.get(self._key(task_id))
        if data:
            return json.loads(data)
        return None

    def format_progress_message(self, task_id: str) -> str:
        """格式化进度消息，返回可读的进度描述"""
        data = self.get_progress(task_id)
        if not data:
            return "未知进度"

        lines = []
        target = data.get("target", "未知目标")
        lines.append(f"**目标**: {target}")

        current_phase = data.get("current_phase", "unknown")
        phase_names = {
            "init": "初始化",
            "recon": "🔍 信息收集",
            "vuln_scan": "🔬 漏洞扫描",
            "exploit": "💥 漏洞利用",
            "report": "📋 报告生成",
            "complete": "✅ 完成",
        }

        lines.append(f"**当前阶段**: {phase_names.get(current_phase, current_phase)}")

        # 添加当前步骤的详细信息
        steps = data.get("steps", [])
        if steps:
            last_step = steps[-1]
            lines.append(f"**当前步骤**: {last_step.get('step', '')}")
            if last_step.get("details"):
                lines.append(f"**详情**: {last_step['details'][:100]}")

        # 添加关键发现
        findings = data.get("findings", {})
        if findings:
            find_lines = []
            if findings.get("hosts"):
                find_lines.append(f"发现 {len(findings['hosts'])} 个主机")
            if findings.get("ports"):
                find_lines.append(f"发现 {len(findings['ports'])} 个开放端口")
            if findings.get("vulnerabilities"):
                find_lines.append(f"发现 {len(findings['vulnerabilities'])} 个漏洞")
            if find_lines:
                lines.append("**发现**: " + " | ".join(find_lines))

        return "\n".join(lines)


# 全局实例
_tracker: Optional[TaskProgressTracker] = None


def get_progress_tracker() -> TaskProgressTracker:
    global _tracker
    if _tracker is None:
        _tracker = TaskProgressTracker()
    return _tracker
