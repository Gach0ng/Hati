#!/usr/bin/env python3
"""
Pentest Agent - Elasticsearch 索引配置脚本
创建审计日志所需的索引模板和初始化设置
"""

import sys
import os
from datetime import datetime

# 添加项目根目录到 path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import RequestError


# ===========================================
# Elasticsearch 连接配置
# ===========================================
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")
ES_URL = f"http://{ES_HOST}:{ES_PORT}"

# 索引名称模板
AUDIT_INDEX_PREFIX = "pentest-logs"
AUDIT_INDEX_PATTERN = f"{AUDIT_INDEX_PREFIX}-*"

# ===========================================
# 索引映射定义
# ===========================================
AUDIT_INDEX_MAPPING = {
    "index_patterns": [AUDIT_INDEX_PATTERN],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
            "index.lifecycle.name": "pentest-logs-policy",
            "index.lifecycle.rollover_alias": AUDIT_INDEX_PREFIX,
        },
        "mappings": {
            "properties": {
                # 时间戳 - 核心字段
                "timestamp": {"type": "date"},
                "@timestamp": {"type": "date"},

                # 任务标识
                "task_id": {"type": "keyword"},
                "parent_task_id": {"type": "keyword"},
                "task_name": {"type": "keyword"},

                # Agent 信息
                "agent": {"type": "keyword"},
                "agent_type": {"type": "keyword"},
                "agent_version": {"type": "keyword"},

                # 动作信息
                "action": {"type": "keyword"},
                "action_type": {"type": "keyword"},
                "phase": {"type": "keyword"},

                # 目标信息
                "target": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "target_type": {"type": "keyword"},
                "scope": {"type": "keyword"},

                # 工具信息
                "tool": {"type": "keyword"},
                "tool_version": {"type": "keyword"},
                "command": {"type": "text"},
                "command_args": {"type": "text"},

                # 执行结果
                "status": {"type": "keyword"},
                "result_summary": {"type": "text"},
                "result_detail": {"type": "text"},
                "error_message": {"type": "text"},
                "duration_ms": {"type": "long"},
                "return_code": {"type": "integer"},

                # 安全相关
                "risk_level": {"type": "keyword"},  # low, medium, high, critical
                "is_privileged": {"type": "boolean"},
                "approval_required": {"type": "boolean"},
                "approved_by": {"type": "keyword"},
                "approval_timestamp": {"type": "date"},
                "approval_comment": {"type": "text"},

                # 决策相关
                "reasoning": {"type": "text"},
                "decision_confidence": {"type": "float"},
                "llm_model": {"type": "keyword"},
                "llm_tokens_used": {"type": "integer"},

                # LLM 输入输出
                "llm_prompt": {"type": "text"},
                "llm_response": {"type": "text"},

                # 容器信息
                "container_id": {"type": "keyword"},
                "container_image": {"type": "keyword"},
                "network_mode": {"type": "keyword"},

                # 元数据
                "metadata": {
                    "type": "object",
                    "dynamic": True
                },

                # 标签
                "tags": {"type": "keyword"},
            }
        },
    },
    "priority": 100,
    "composed_of": [],
    "_meta": {
        "description": "Pentest Agent Audit Log Index Template",
        "version": "1.0.0",
        "created_at": datetime.utcnow().isoformat(),
    },
}

# ===========================================
# ILM (Index Lifecycle Management) 策略
# ===========================================
ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_size": "5gb",
                        "max_age": "7d"
                    },
                    "set_priority": 100
                }
            },
            "warm": {
                "min_age": "7d",
                "actions": {
                    "set_priority": 50,
                    "shrink": {
                        "number_of_shards": 1
                    },
                    "forcemerge": {
                        "max_num_segments": 1
                    }
                }
            },
            "delete": {
                "min_age": "30d",
                "actions": {
                    "delete": {}
                }
            }
        }
    }
}

# ===========================================
# 初始化函数
# ===========================================


def wait_for_elasticsearch(es: Elasticsearch, max_retries: int = 30) -> bool:
    """等待 Elasticsearch 就绪"""
    for i in range(max_retries):
        try:
            if es.ping():
                print(f"✅ Elasticsearch 已连接 (尝试 {i+1}/{max_retries})")
                return True
        except Exception as e:
            print(f"等待 Elasticsearch 就绪... ({i+1}/{max_retries}): {e}")
        import time
        time.sleep(2)
    return False


def create_index_template(es: Elasticsearch) -> bool:
    """创建索引模板"""
    try:
        # 检查是否已存在
        if es.indices.exists_index_template(name="pentest-logs"):
            print("ℹ️  索引模板 'pentest-logs' 已存在，尝试更新...")
            es.indices.delete_index_template(name="pentest-logs")

        # 创建新模板
        es.indices.put_index_template(
            name="pentest-logs",
            body=AUDIT_INDEX_MAPPING
        )
        print("✅ 索引模板 'pentest-logs' 创建成功")
        return True
    except RequestError as e:
        print(f"❌ 创建索引模板失败: {e}")
        return False


def create_ilm_policy(es: Elasticsearch) -> bool:
    """创建 ILM 策略"""
    try:
        policy_name = "pentest-logs-policy"

        # 检查是否已存在
        try:
            es.ilm.get_lifecycle(name=policy_name)
            print(f"ℹ️  ILM 策略 '{policy_name}' 已存在")
        except Exception:
            # 不存在则创建
            es.ilm.put_lifecycle(name=policy_name, policy=ILM_POLICY["policy"])
            print(f"✅ ILM 策略 '{policy_name}' 创建成功")
        return True
    except Exception as e:
        print(f"⚠️  ILM 策略创建失败: {e}")
        return False


def create_initial_index(es: Elasticsearch) -> bool:
    """创建初始索引（带日期后缀）"""
    try:
        index_name = f"{AUDIT_INDEX_PREFIX}-{datetime.now().strftime('%Y.%m.%d')}"

        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name)
            print(f"✅ 初始索引 '{index_name}' 创建成功")
        else:
            print(f"ℹ️  索引 '{index_name}' 已存在")
        return True
    except Exception as e:
        print(f"❌ 创建初始索引失败: {e}")
        return False


def setup_elasticsearch() -> bool:
    """主设置函数"""
    print("=" * 60)
    print("Pentest Agent - Elasticsearch 初始化")
    print("=" * 60)

    # 连接 Elasticsearch
    print(f"\n正在连接 Elasticsearch: {ES_URL}")
    es = Elasticsearch([ES_URL])

    # 等待就绪
    if not wait_for_elasticsearch(es):
        print("❌ 无法连接到 Elasticsearch")
        return False

    # 创建索引模板
    if not create_index_template(es):
        return False

    # 创建 ILM 策略
    create_ilm_policy(es)

    # 创建初始索引
    create_initial_index(es)

    # 验证设置
    print("\n" + "=" * 60)
    print("验证设置:")
    print("-" * 60)

    # 检查模板
    template_info = es.indices.get_index_template(name="pentest-logs")
    print(f"✅ 索引模板: {template_info['index_templates'][0]['name']}")

    # 检查健康状态
    health = es.cluster.health()
    print(f"✅ 集群状态: {health['status']}")
    print(f"✅ 节点数: {health['number_of_nodes']}")

    print("\n" + "=" * 60)
    print("✅ Elasticsearch 初始化完成!")
    print("=" * 60)

    return True


# ===========================================
# 主程序入口
# ===========================================
if __name__ == "__main__":
    success = setup_elasticsearch()
    sys.exit(0 if success else 1)
