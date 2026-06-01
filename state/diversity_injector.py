"""
Pentest Agent - 多样性注入模块
防止模式僵化，增加 LLM 输出的多样性

功能：
1. CoT 强制前缀
2. 随机化延迟
3. 输出格式变体
4. Prompt 多样性增强
"""

import random
import time
from typing import Optional, Callable
from functools import wraps


# ===========================================
# 多样性配置
# ===========================================
class DiversityConfig:
    """多样性注入配置"""

    # CoT 强制前缀模板
    COT_PREFIXES = [
        "先分析再行动。分析: {reasoning}\n行动:",
        "思考过程：首先{step1}，然后{step2}，最后行动。",
        "让我分析一下：{reasoning}\n基于以上分析，决定：",
        "推理链路：{reasoning}\n结论：",
    ]

    # 随机化延迟配置（秒）
    POC_EXECUTION_DELAY = {"min": 0.1, "max": 0.5}
    SCAN_INTERVAL_DELAY = {"min": 0.5, "max": 2.0}
    AGENT_RESPONSE_DELAY = {"min": 0.05, "max": 0.2}

    # 输出格式变体
    OUTPUT_FORMATS = [
        "简洁摘要（3句话以内）",
        "详细分析（包含步骤说明）",
        "结构化报告（分点阐述）",
        "对话式回复（友好语气）",
        "技术文档风格（正式格式）",
    ]

    # 行动描述变体
    ACTION_VERBS = {
        "scan": ["扫描", "探测", "检查", "分析"],
        "attack": ["攻击", "尝试", "测试", "验证"],
        "report": ["生成报告", "汇总结果", "整理发现", "编写文档"],
    }


# ===========================================
# 多样性注入器
# ===========================================
class DiversityInjector:
    """
    多样性注入器

    使用方式：
    injector = DiversityInjector()
    enhanced_prompt = injector.enhance_prompt(base_prompt)
    delay = injector.get_scan_delay()
    """

    def __init__(self, seed: Optional[int] = None):
        """
        初始化多样性注入器

        Args:
            seed: 随机种子（用于可重现性）
        """
        if seed is not None:
            random.seed(seed)
        self.call_count = 0

    def enhance_prompt(
        self,
        prompt: str,
        include_cot: bool = True,
        include_format: bool = True,
    ) -> str:
        """
        增强 Prompt 多样性

        Args:
            prompt: 原始 Prompt
            include_cot: 是否添加 CoT 前缀
            include_format: 是否指定输出格式

        Returns:
            增强后的 Prompt
        """
        self.call_count += 1

        # 1. 添加 CoT 前缀（轮换使用）
        if include_cot:
            prompt = self._add_cot_prefix(prompt)

        # 2. 指定输出格式（随机选择）
        if include_format:
            prompt = self._add_format_hint(prompt)

        # 3. 添加角色变体（每3次调用切换）
        if self.call_count % 3 == 0:
            prompt = self._add_role_variant(prompt)

        return prompt

    def _add_cot_prefix(self, prompt: str) -> str:
        """添加 CoT 前缀"""
        cot_template = random.choice(DiversityConfig.COT_PREFIXES)

        # 填充模板
        cot_prefix = cot_template.format(
            reasoning="正在分析当前状态...",
            step1="理解目标",
            step2="评估可用资源",
        )

        return f"{cot_prefix}\n\n{prompt}"

    def _add_format_hint(self, prompt: str) -> str:
        """添加输出格式提示"""
        format_variant = random.choice(DiversityConfig.OUTPUT_FORMATS)

        format_hint = f"\n\n[回复格式]\n请使用「{format_variant}」格式回复。"

        return prompt + format_hint

    def _add_role_variant(self, prompt: str) -> str:
        """添加角色变体"""
        role_variants = [
            "\n\n[角色扮演] 假设你是一位经验丰富的安全研究员。",
            "\n\n[角色扮演] 以专业渗透测试工程师的视角分析。",
            "\n\n[角色扮演] 从红队攻击者的角度思考。",
        ]

        role = random.choice(role_variants)
        return prompt + role

    def get_scan_delay(self) -> float:
        """
        获取随机的扫描间隔延迟

        Returns:
            延迟秒数
        """
        config = DiversityConfig.SCAN_INTERVAL_DELAY
        return random.uniform(config["min"], config["max"])

    def get_poc_delay(self) -> float:
        """
        获取 POC 执行延迟

        Returns:
            延迟秒数
        """
        config = DiversityConfig.POC_EXECUTION_DELAY
        return random.uniform(config["min"], config["max"])

    def get_action_verb(self, action_type: str) -> str:
        """
        获取动作的同义词变体

        Args:
            action_type: 动作类型 (scan/attack/report)

        Returns:
            动作动词
        """
        verbs = DiversityConfig.ACTION_VERBS.get(action_type, ["执行"])
        return random.choice(verbs)

    def get_response_style(self) -> str:
        """
        获取响应风格

        Returns:
            响应风格描述
        """
        styles = [
            "专业简洁",
            "详细分析",
            "重点突出",
            "全面覆盖",
        ]
        return random.choice(styles)


# ===========================================
# 延迟装饰器
# ===========================================
def random_delay(func: Callable = None, delay_type: str = "scan") -> Callable:
    """
    随机延迟装饰器

    用于在工具执行之间添加随机延迟，增加多样性

    Args:
        func: 被装饰的函数
        delay_type: 延迟类型 (scan/poc/agent)

    Returns:
        装饰后的函数
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            injector = DiversityInjector()
            delay_config = {
                "scan": injector.get_scan_delay,
                "poc": injector.get_poc_delay,
                "agent": lambda: random.uniform(
                    DiversityConfig.AGENT_RESPONSE_DELAY["min"],
                    DiversityConfig.AGENT_RESPONSE_DELAY["max"]
                ),
            }
            delay_fn = delay_config.get(delay_type, injector.get_scan_delay)
            time.sleep(delay_fn())
            return f(*args, **kwargs)
        return wrapper

    if func is None:
        return decorator
    return decorator(func)


# ===========================================
# Prompt 变体生成器
# ===========================================
class PromptVariantGenerator:
    """
    Prompt 变体生成器

    为同一任务生成多个不同的 Prompt 变体
    """

    # 问题模板变体
    QUESTION_TEMPLATES = [
        "请分析 {target} 的安全性",
        "对 {target} 进行安全评估",
        "{target} 存在哪些安全风险？",
        "评估 {target} 的攻击面",
        "{target} 的潜在漏洞有哪些？",
    ]

    # 行动指令变体
    ACTION_INSTRUCTIONS = [
        "执行扫描并报告结果",
        "进行漏洞检测",
        "识别潜在威胁",
        "完成安全评估",
        "收集目标情报",
    ]

    # 约束条件变体
    CONSTRAINT_VARIANTS = [
        "优先发现高危漏洞",
        "关注认证和授权问题",
        "全面扫描所有已知漏洞",
        "重点测试 API 安全",
        "检查配置安全问题",
    ]

    @classmethod
    def generate_variants(cls, target: str, count: int = 3) -> list[str]:
        """
        生成 Prompt 变体

        Args:
            target: 目标
            count: 变体数量

        Returns:
            Prompt 变体列表
        """
        variants = []

        for i in range(count):
            question = random.choice(cls.QUESTION_TEMPLATES).format(target=target)
            action = random.choice(cls.ACTION_INSTRUCTIONS)
            constraint = random.choice(cls.CONSTRAINT_VARIANTS)

            variant = f"{question}。{action}。{constraint}。"
            variants.append(variant)

        return variants

    @classmethod
    def get_context_switch(cls) -> str:
        """
        获取上下文切换提示

        用于打破重复模式
        """
        switches = [
            "换个角度思考这个问题。",
            "尝试一种不同的方法。",
            "重新审视这个目标。",
            "从另一个视角分析。",
        ]
        return random.choice(switches)


# ===========================================
# 全局实例
# ===========================================
_diversity_injector: Optional[DiversityInjector] = None


def get_diversity_injector() -> DiversityInjector:
    """获取全局多样性注入器"""
    global _diversity_injector
    if _diversity_injector is None:
        _diversity_injector = DiversityInjector()
    return _diversity_injector
