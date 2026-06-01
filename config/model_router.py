"""
Pentest Agent - 模型路由配置
混合使用轻量模型和重量模型，降低成本和延迟

路由策略：
- 轻量模型 (Haiku级别): 简单任务（解析HTML、正则匹配、指纹识别）
- 重量模型 (大模型): 复杂推理（决策、漏洞分析、报告生成）
"""

from typing import Optional, Dict, Any, Callable
from enum import Enum
from functools import wraps


# ===========================================
# 模型定义
# ===========================================
class ModelType(Enum):
    """模型类型"""
    LIGHT = "light"      # 轻量模型
    HEAVY = "heavy"      # 重量模型


# ===========================================
# 模型配置
# ===========================================
MODEL_CONFIG = {
    # 轻量模型 (快速、便宜)
    "light": {
        "model": "MiniMax-M2",
        "temperature": 0.3,  # 低温度，更确定性
        "max_tokens": 1024,
        "use_cases": [
            "parse_html",        # HTML 解析
            "regex_match",      # 正则匹配
            "fingerprint",      # 指纹识别
            "extract_urls",     # URL 提取
            "extract_emails",   # 邮箱提取
            "json_parse",       # JSON 解析
            "summarize_short",  # 短文本摘要
            "keyword_extract",   # 关键词提取
        ],
    },
    # 重量模型 (复杂、昂贵)
    "heavy": {
        "model": "MiniMax-M2.7",
        "temperature": 0.7,
        "max_tokens": 4096,
        "use_cases": [
            "attack_decision",   # 攻击决策
            "vuln_analysis",    # 漏洞分析
            "poc_generation",   # POC 生成
            "report_write",     # 报告撰写
            "reasoning",       # 复杂推理
            "planning",        # 规划
            "orchestration",    # 协调
        ],
    },
}


# ===========================================
# 任务类型映射
# ===========================================
TASK_TO_MODEL: Dict[str, str] = {
    # 简单任务 -> 轻量模型
    "parse_nmap_output": "light",
    "parse_nuclei_output": "light",
    "extract_ports": "light",
    "extract_cves": "light",
    "fingerprint_service": "light",
    "match_cve_keywords": "light",
    "summarize_scan_results": "light",

    # 复杂任务 -> 重量模型
    "decide_next_action": "heavy",
    "analyze_vulnerability": "heavy",
    "generate_poc": "heavy",
    "create_exploit": "heavy",
    "write_report": "heavy",
    "plan_attack": "heavy",
    "coordinate_agents": "heavy",
}


# ===========================================
# 模型路由器
# ===========================================
class ModelRouter:
    """
    模型路由器

    根据任务类型自动选择合适的模型

    使用方式：
    router = ModelRouter()

    # 自动路由
    result = router.route("parse_html", html_content)

    # 强制使用特定模型
    result = router.route("attack_decision", prompt, force_model="heavy")
    """

    def __init__(self, light_llm=None, heavy_llm=None):
        """
        初始化路由器

        Args:
            light_llm: 轻量模型实例
            heavy_llm: 重量模型实例
        """
        from config.minimax_config import get_llm

        self.light_llm = light_llm or get_llm()
        self.heavy_llm = heavy_llm or get_llm()

    def get_model_for_task(self, task_type: str) -> ModelType:
        """
        获取任务对应的模型类型

        Args:
            task_type: 任务类型

        Returns:
            ModelType
        """
        model_key = TASK_TO_MODEL.get(task_type, "heavy")
        return ModelType.LIGHT if model_key == "light" else ModelType.HEAVY

    def route(
        self,
        task_type: str,
        prompt: str,
        force_model: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        路由任务到合适的模型

        Args:
            task_type: 任务类型
            prompt: 输入提示
            force_model: 强制使用的模型 (light/heavy)

        Returns:
            模型输出
        """
        # 确定使用哪个模型
        if force_model == "light":
            model_type = ModelType.LIGHT
        elif force_model == "heavy":
            model_type = ModelType.HEAVY
        else:
            model_type = self.get_model_for_task(task_type)

        # 选择 LLM 实例
        if model_type == ModelType.LIGHT:
            return self._call_light_model(prompt, **kwargs)
        else:
            return self._call_heavy_model(prompt, **kwargs)

    def _call_light_model(self, prompt: str, **kwargs) -> str:
        """调用轻量模型"""
        config = MODEL_CONFIG["light"]

        # 临时调整参数
        original_max_tokens = self.light_llm.max_tokens
        self.light_llm.max_tokens = config["max_tokens"]

        try:
            response = self.light_llm.chat(
                prompt=prompt,
                system_prompt="你是一个快速准确的文本分析助手。直接给出答案，不需要解释。"
            )
            return response
        finally:
            self.light_llm.max_tokens = original_max_tokens

    def _call_heavy_model(self, prompt: str, **kwargs) -> str:
        """调用重量模型"""
        config = MODEL_CONFIG["heavy"]

        # 临时调整参数
        original_max_tokens = self.heavy_llm.max_tokens
        original_temperature = self.heavy_llm.temperature

        self.heavy_llm.max_tokens = config["max_tokens"]
        self.heavy_llm.temperature = config["temperature"]

        try:
            response = self.heavy_llm.chat(prompt=prompt)
            return response
        finally:
            self.heavy_llm.max_tokens = original_max_tokens
            self.heavy_llm.temperature = original_temperature

    def batch_route(
        self,
        tasks: list[tuple[str, str]]
    ) -> list[str]:
        """
        批量路由任务

        Args:
            tasks: [(task_type, prompt), ...]

        Returns:
            输出列表
        """
        results = []

        # 按模型分组
        light_tasks = []
        heavy_tasks = []

        for i, (task_type, prompt) in enumerate(tasks):
            model_type = self.get_model_for_task(task_type)
            if model_type == ModelType.LIGHT:
                light_tasks.append((i, prompt))
            else:
                heavy_tasks.append((i, prompt))

        # 批量处理轻量任务
        light_results = []
        for _, prompt in light_tasks:
            result = self._call_light_model(prompt)
            light_results.append(result)

        # 批量处理重量任务
        heavy_results = []
        for _, prompt in heavy_tasks:
            result = self._call_heavy_model(prompt)
            heavy_results.append(result)

        # 合并结果
        all_results = [None] * len(tasks)
        for idx, result in zip([t[0] for t in light_tasks], light_results):
            all_results[idx] = result
        for idx, result in zip([t[0] for t in heavy_tasks], heavy_results):
            all_results[idx] = result

        return all_results


# ===========================================
# 便捷函数
# ===========================================
_router: Optional[ModelRouter] = None


def get_model_router() -> ModelRouter:
    """获取全局模型路由器"""
    global _router
    if _router is None:
        _router = ModelRouter()
    return _router


def parse_with_light_model(content: str, parse_type: str) -> str:
    """
    使用轻量模型解析内容

    Args:
        content: 要解析的内容
        parse_type: 解析类型

    Returns:
        解析结果
    """
    router = get_model_router()

    prompts = {
        "extract_ports": f"从以下输出中提取所有端口号：\n{content}",
        "extract_cves": f"从以下文本中提取所有 CVE ID：\n{content}",
        "fingerprint": f"识别以下服务指纹：\n{content}",
        "summarize": f"简短摘要以下内容（50字以内）：\n{content}",
    }

    prompt = prompts.get(parse_type, f"分析以下内容：\n{content}")
    return router.route(parse_type, prompt)


# ===========================================
# KV-Cache 优化
# ===========================================
class KVCacheConfig:
    """KV-Cache 优化配置"""

    # 启用前缀缓存
    ENABLE_PREFIX_CACHE = True

    # 避免的动态内容
    AVOID_DYNAMIC = [
        "时间戳",
        "会话ID",
        "随机数",
        "当前时间",
    ]

    # 缓存键前缀
    CACHE_PREFIX = "kv_cache:"

    # 缓存有效期（秒）
    CACHE_TTL = 3600


def optimize_for_kv_cache(system_prompt: str) -> str:
    """
    优化 Prompt 以提高 KV-Cache 命中率

    Args:
        system_prompt: 原始系统 Prompt

    Returns:
        优化后的 Prompt
    """
    import re

    # 1. 移除动态时间戳
    patterns_to_remove = [
        r'\d{4}-\d{2}-\d{2}',  # 日期
        r'\d{2}:\d{2}:\d{2}',   # 时间
        r'timestamp[=:].*',      # timestamp 字段
    ]

    optimized = system_prompt
    for pattern in patterns_to_remove:
        optimized = re.sub(pattern, '[动态内容已移除]', optimized)

    # 2. 替换可变占位符
    if '{target}' in optimized:
        optimized = optimized.replace('{target}', '[目标]')
    if '{task_id}' in optimized:
        optimized = optimized.replace('{task_id}', '[任务ID]')

    return optimized


def build_cache_friendly_prompt(
    phase: str,
    target: str = None,
    use_fixed_prefix: bool = True
) -> tuple[str, str]:
    """
    构建缓存友好的 Prompt

    Returns:
        (system_prompt, user_prompt)
    """
    from config.prompts_layered import get_prompt_builder

    builder = get_prompt_builder()

    # 系统 Prompt 使用固定前缀
    if use_fixed_prefix:
        system_prompt = builder.build_system_message(phase)
        system_prompt = optimize_for_kv_cache(system_prompt)
    else:
        system_prompt = None

    # 用户 Prompt 包含动态内容
    user_parts = []
    if target:
        user_parts.append(f"## 目标\n{target}")

    user_prompt = "\n".join(user_parts) if user_parts else None

    return system_prompt, user_prompt
