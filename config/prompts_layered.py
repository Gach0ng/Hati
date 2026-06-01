"""
Hati - 分层 Prompt 架构
减少 KV-cache 失效，降低推理延迟

Layer 1 (常驻): 安全边界 + 核心目标 (~300 tokens)
Layer 2 (按需加载): 阶段专用工具描述 (~800/阶段)
Layer 3 (即时引用): RAG 检索结果片段 (~200/结果)
"""

from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field


# ===========================================
# Layer 1: 常驻 Prompt (固定前缀，保护 KV-cache)
# ===========================================
LAYER1_FIXED_PREFIX = """你是一个专业的渗透测试智能体。

安全边界规则（必须遵守）：
- 仅对授权目标进行测试
- 禁止对未授权目标执行任何操作
- 高危操作（rm -rf、格式化等）自动拦截
- 所有漏洞利用需人工审批后方可执行
- 测试过程全程审计记录

核心目标：
- 发现并验证目标安全漏洞
- 提供可修复的安全建议
- 不对目标系统造成破坏
"""


# ===========================================
# Layer 2: 阶段专用工具描述
# ===========================================
LAYER2_TOOLS: Dict[str, str] = {
    "init": """## 阶段：初始化

当前任务：访问目标、获取页面信息

可用操作：
- HTTP 请求探测目标
- 获取页面标题、内容、结构
- 识别登录页面、SPA 应用
""",

    "recon": """## 阶段：信息收集 (recon)

职责：收集目标网络架构信息、发现子域名和IP、识别开放端口和服务

可用工具（前缀：recon_*）：
- recon_nmap_scan: 端口扫描，发现开放端口
- recon_masscan: 快速端口扫描（大规模扫描）
- recon_subfinder: 子域名发现
- recon_amass: 子域名枚举
- recon_httpx: HTTP探测，获取响应头、标题
- recon_whatweb: 技术指纹识别
- recon_ screenshot: 页面截图

工具使用规范：
- 先做子域名枚举，再做端口扫描
- 优先使用轻量级探测工具
- 发现服务后立即识别指纹
""",

    "vuln_scan": """## 阶段：漏洞扫描 (vuln_scan)

职责：基于信息收集结果检测漏洞，使用nuclei/nikto/sqlmap等扫描

可用工具（前缀：vuln_*）：
- vuln_nuclei_scan: 漏洞扫描，支持CVE检测
- vuln_nikto_scan: Web服务器漏洞扫描
- vuln_sqlmap_test: SQL注入检测
- vuln_nmap_vuln: nmap漏洞脚本扫描

工具使用规范：
- 先用nuclei扫描已知CVE
- Web目标使用nikto深度扫描
- 发现SQL相关参数后使用sqlmap
- 每次扫描后更新RAG关联
""",

    "exploit": """## 阶段：漏洞利用 (exploit)

⚠️ 重要：利用前必须获得人工审批

可用工具（前缀：exploit_*）：
- exploit_hydra_brute: 暴力破解（需审批）
- exploit_poc_execute: POC执行验证
- exploit_custom_payload: 自定义Payload生成

工具使用规范：
- 所有利用操作需要审批
- 提供多个可选利用方案
- 评估风险等级供决策参考
""",

    "report": """## 阶段：报告生成 (report)

职责：汇总所有结果，生成结构化Markdown报告

可用工具（前缀：report_*）：
- report_generate: 生成渗透测试报告

报告结构：
1. 执行摘要
2. 测试范围
3. 测试方法论
4. 发现的问题（按严重程度排序）
5. 详细发现
6. 风险总结
7. 修复建议
8. 附录
""",
}


# ===========================================
# Layer 3: RAG 检索结果片段（即时引用）
# ===========================================
@dataclass
class RAGFragment:
    """RAG 检索结果片段"""
    cve_id: str
    name: str
    severity: str
    affected_versions: str = ""
    exploit_conditions: str = ""
    poc_params: List[str] = field(default_factory=list)
    remediation: str = ""


def layer3_rag_fragment(rag_results: List[RAGFragment]) -> str:
    """生成 Layer 3 RAG 引用片段"""
    if not rag_results:
        return ""

    lines = ["\n## RAG 知识库关联（实时引用）"]
    lines.append(f"共检索到 {len(rag_results)} 个相关漏洞：\n")

    for r in rag_results[:5]:  # 限制5个，避免过长
        lines.append(f"### {r.cve_id}: {r.name}")
        lines.append(f"- 严重程度: {r.severity}")
        if r.affected_versions:
            lines.append(f"- 影响版本: {r.affected_versions}")
        if r.exploit_conditions:
            lines.append(f"- 利用条件: {r.exploit_conditions}")
        if r.poc_params:
            lines.append(f"- 验证参数: {', '.join(r.poc_params)}")
        if r.remediation:
            lines.append(f"- 修复建议: {r.remediation}")
        lines.append("")

    return "\n".join(lines)


# ===========================================
# Todo 列表模板（动态更新）
# ===========================================
def build_todo_block(todo_list: List[str]) -> str:
    """构建 Todo 追踪块"""
    if not todo_list:
        return ""

    lines = ["\n## 当前任务清单\n"]
    for item in todo_list:
        lines.append(f"- {item}")
    lines.append("")

    return "\n".join(lines)


def update_todo_item(todo_list: List[str], item: str, completed: bool = True) -> List[str]:
    """更新 Todo 项"""
    new_list = []
    for existing in todo_list:
        if existing.startswith(item) or existing.startswith("- [x] " + item):
            # 标记为完成
            new_list.append(existing.replace("- [ ] ", "- [x] ").replace("- [x] ", "- [x] "))
        else:
            new_list.append(existing)
    return new_list


# ===========================================
# 分层 Prompt 构建器
# ===========================================
class LayeredPromptBuilder:
    """
    分层 Prompt 构建器

    使用方式：
    builder = LayeredPromptBuilder()
    prompt = builder.build(
        phase="recon",
        target="https://example.com",
        todo_list=["- [ ] 端口扫描", "- [ ] 漏洞检测"],
        rag_results=[RAGFragment(cve_id="CVE-2021-12345", ...)]
    )
    """

    def __init__(self):
        self.fixed_prefix = LAYER1_FIXED_PREFIX

    def build(
        self,
        phase: str,
        target: str,
        todo_list: Optional[List[str]] = None,
        rag_results: Optional[List[RAGFragment]] = None,
        extra_context: Optional[str] = None,
    ) -> str:
        """
        构建完整的分层 Prompt

        Args:
            phase: 当前阶段 (init/recon/vuln_scan/exploit/report)
            target: 测试目标
            todo_list: 当前 Todo 列表
            rag_results: RAG 检索结果
            extra_context: 额外上下文

        Returns:
            完整的分层 Prompt
        """
        parts = []

        # Layer 1: 固定前缀
        parts.append(self.fixed_prefix)

        # 任务目标（动态但稳定）
        parts.append(f"\n## 测试目标\n{target}\n")

        # Layer 2: 阶段专用工具
        phase_tools = LAYER2_TOOLS.get(phase, LAYER2_TOOLS["init"])
        parts.append(phase_tools)

        # Layer 3: RAG 引用
        if rag_results:
            parts.append(layer3_rag_fragment(rag_results))

        # Todo 列表
        if todo_list:
            parts.append(build_todo_block(todo_list))

        # 额外上下文
        if extra_context:
            parts.append(f"\n## 额外上下文\n{extra_context}\n")

        return "\n".join(parts)

    def build_system_message(self, phase: str) -> str:
        """
        仅构建系统消息（Layer 1 + Layer 2）

        用于 KV-cache 优化：系统消息保持稳定
        """
        parts = [self.fixed_prefix]

        phase_tools = LAYER2_TOOLS.get(phase, LAYER2_TOOLS["init"])
        parts.append(phase_tools)

        return "\n".join(parts)

    def get_tool_prefixes(self, phase: str) -> List[str]:
        """获取当前阶段允许的工具前缀"""
        prefixes_map = {
            "init": ["recon_", "http_"],
            "recon": ["recon_"],
            "vuln_scan": ["vuln_", "recon_"],
            "exploit": ["exploit_", "vuln_"],
            "report": ["report_"],
        }
        return prefixes_map.get(phase, [])

    def filter_allowed_tools(self, tools: List[str], phase: str) -> List[str]:
        """
        根据阶段过滤允许的工具

        强制在特定阶段只使用相关工具
        """
        prefixes = self.get_tool_prefixes(phase)
        if not prefixes:
            return tools

        allowed = []
        for tool in tools:
            if any(tool.startswith(p) for p in prefixes):
                allowed.append(tool)
        return allowed if allowed else tools  # 未匹配时返回原列表


# ===========================================
# 默认 Todo 模板
# ===========================================
DEFAULT_TODO_LIST = [
    "- [ ] 识别目标 web 服务指纹",
    "- [ ] 扫描开放端口和服务",
    "- [ ] 检测子域名",
    "- [ ] 根据指纹检索 RAG 知识库的 POC",
    "- [ ] 验证发现的可疑漏洞",
    "- [ ] 生成渗透测试报告",
]


# ===========================================
# 初始化默认 Builder
# ===========================================
_builder: Optional[LayeredPromptBuilder] = None


def get_prompt_builder() -> LayeredPromptBuilder:
    """获取全局 Prompt 构建器"""
    global _builder
    if _builder is None:
        _builder = LayeredPromptBuilder()
    return _builder


# ===========================================
# KV-Cache 优化
# ===========================================
class KVCacheConfig:
    """KV-Cache 优化配置"""

    # 启用前缀缓存
    ENABLE_PREFIX_CACHE = True

    # 缓存的系统前缀（按阶段）
    CACHED_SYSTEM_PROMPTS: Dict[str, str] = {}

    # 避免的动态内容模式
    DYNAMIC_PATTERNS = [
        r'\d{4}-\d{2}-\d{2}',  # 日期
        r'\d{2}:\d{2}:\d{2}',  # 时间
        r'timestamp[=:].*',
        r'session[_-]?id[=:].*',
    ]

    @classmethod
    def get_cached_system_prompt(cls, phase: str) -> Optional[str]:
        """获取缓存的系统 Prompt（无动态内容）"""
        return cls.CACHED_SYSTEM_PROMPTS.get(phase)

    @classmethod
    def cache_system_prompt(cls, phase: str, prompt: str) -> None:
        """缓存系统 Prompt（去除动态内容后）"""
        import re
        cached = prompt

        # 移除动态内容
        for pattern in cls.DYNAMIC_PATTERNS:
            cached = re.sub(pattern, '[动态]', cached, flags=re.IGNORECASE)

        # 移除时间戳占位符
        cached = cached.replace('{timestamp}', '[时间戳]')
        cached = cached.replace('{session_id}', '[会话ID]')
        cached = cached.replace('{task_id}', '[任务ID]')

        cls.CACHED_SYSTEM_PROMPTS[phase] = cached


def optimize_for_kv_cache(prompt: str) -> str:
    """
    优化 Prompt 以提高 KV-Cache 命中率

    Args:
        prompt: 原始 Prompt

    Returns:
        优化后的 Prompt
    """
    import re

    optimized = prompt

    # 移除动态内容
    for pattern in KVCacheConfig.DYNAMIC_PATTERNS:
        optimized = re.sub(pattern, '[动态]', optimized, flags=re.IGNORECASE)

    return optimized


def build_cache_friendly_prompt(
    phase: str,
    target: str = None,
    use_cache: bool = True
) -> tuple[str, Optional[str]]:
    """
    构建缓存友好的分层 Prompt

    Args:
        phase: 当前阶段
        target: 测试目标
        use_cache: 是否使用 KV-Cache 优化

    Returns:
        (system_prompt, user_prompt)
    """
    builder = get_prompt_builder()

    # 系统 Prompt
    if use_cache and KVCacheConfig.ENABLE_PREFIX_CACHE:
        # 尝试从缓存获取
        cached = KVCacheConfig.get_cached_system_prompt(phase)
        if cached:
            system_prompt = cached
        else:
            system_prompt = builder.build_system_message(phase)
            KVCacheConfig.cache_system_prompt(phase, system_prompt)
            system_prompt = KVCacheConfig.get_cached_system_prompt(phase)
    else:
        system_prompt = builder.build_system_message(phase)

    # 用户 Prompt（包含动态内容）
    user_parts = []
    if target:
        user_parts.append(f"## 测试目标\n{target}")

    user_prompt = "\n".join(user_parts) if user_parts else None

    return system_prompt, user_prompt
