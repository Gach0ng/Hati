"""
Pentest Agent - Celery 配置
任务队列配置、路由规则、超时设置
"""

import os
from dotenv import load_dotenv

# ⚠️ Windows DLL 冲突修复：在 import torch 之前设置
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from celery import Celery
from kombu import Exchange, Queue

load_dotenv()

# ===========================================
# Redis 连接配置
# ===========================================
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_DB = os.getenv("REDIS_DB", "0")

BROKER_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
RESULT_BACKEND = f"redis://{REDIS_HOST}:{REDIS_PORT}/1"

# ===========================================
# 创建 Celery 应用
# ===========================================
celery_app = Celery(
    "pentest_agent",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=[
        "agents.orchestrator",
        "agents.recon_agent",
        "agents.vuln_agent",
        "agents.exploit_agent",
        "agents.report_agent",
    ],
)

# ===========================================
# 队列定义
# ===========================================
# 定义优先级队列
EXCHANGES = {
    "orchestrator": Exchange("orchestrator", type="direct"),
    "recon": Exchange("recon", type="direct"),
    "vuln": Exchange("vuln", type="direct"),
    "exploit": Exchange("exploit", type="direct"),
    "report": Exchange("report", type="direct"),
}

QUEUES = [
    # 主控队列 - 高优先级
    Queue(
        "orchestrator",
        exchange=EXCHANGES["orchestrator"],
        routing_key="orchestrator",
        queue_arguments={"x-max-priority": 10},
    ),
    # 各子 Agent 队列
    Queue(
        "recon",
        exchange=EXCHANGES["recon"],
        routing_key="recon",
        queue_arguments={"x-max-priority": 7},
    ),
    Queue(
        "vuln",
        exchange=EXCHANGES["vuln"],
        routing_key="vuln",
        queue_arguments={"x-max-priority": 7},
    ),
    Queue(
        "exploit",
        exchange=EXCHANGES["exploit"],
        routing_key="exploit",
        queue_arguments={"x-max-priority": 5},  # 利用任务较低优先级
    ),
    Queue(
        "report",
        exchange=EXCHANGES["report"],
        routing_key="report",
        queue_arguments={"x-max-priority": 3},
    ),
]

# ===========================================
# Celery 配置
# ===========================================
celery_app.conf.update(
    # 序列化配置
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # 任务路由
    task_routes={
        "agents.orchestrator.*": {"queue": "orchestrator", "routing_key": "orchestrator"},
        "agents.recon_agent.*": {"queue": "recon", "routing_key": "recon"},
        "agents.vuln_agent.*": {"queue": "vuln", "routing_key": "vuln"},
        "agents.exploit_agent.*": {"queue": "exploit", "routing_key": "exploit"},
        "agents.report_agent.*": {"queue": "report", "routing_key": "report"},
    },

    # 任务执行限制
    task_soft_time_limit=3300,  # 55分钟软超时
    task_time_limit=3600,  # 1小时硬超时
    task_acks_late=True,  # 任务完成后才确认
    task_reject_on_worker_lost=True,  # Worker 丢失时重新入队
    task_track_started=True,  # 跟踪任务开始状态

    # Worker 配置
    worker_prefetch_multiplier=1,  # 每次只获取一个任务
    worker_max_tasks_per_child=50,  # 每个 worker 最多执行 50 个任务后重启
    worker_concurrency=4,  # 每个 worker 4 个并发

    # 结果配置
    result_expires=86400,  # 结果 24 小时后过期
    result_extended=True,  # 返回扩展信息

    # 定期任务
    beat_schedule={
        "cleanup-old-results": {
            "task": "agents.orchestrator.cleanup_old_results",
            "schedule": 3600.0,  # 每小时清理一次
        },
    },
)

# ===========================================
# 任务优先级常量
# ===========================================
class TaskPriority:
    ORCHESTRATOR = 10
    RECON = 7
    VULN = 7
    EXPLOIT = 5
    REPORT = 3
    DEFAULT = 5


# ===========================================
# 任务状态常量
# ===========================================
class TaskStatus:
    PENDING = "PENDING"
    STARTED = "STARTED"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    RETRY = "RETRY"
    REVOKED = "REVOKED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


# ===========================================
# 渗透测试阶段常量
# ===========================================
class PentestPhase:
    INIT = "init"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    REPORT = "report"
    COMPLETE = "complete"
    ABORTED = "aborted"
