"""
Pentest Agent - 任务规划器
使用真实的 SkillLoader + Intent 动态调度 hack-skills

根据 Intent 生成攻击计划，从 hack-skills 技能库中选择匹配的技能
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json


@dataclass
class Skill:
    """技能单元（用于调度）"""
    name: str
    description: str
    attack_types: List[str]      # 适配的攻击类型
    tool: str                   # HexStrike 工具名（可选，用于执行）
    params_template: Dict[str, Any]  # 参数模板
    dependencies: List[str] = None  # 前置依赖

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class SkillLibrary:
    """
    Skill 调度库

    使用 SkillLoader 加载真实的 hack-skills，并根据 Intent 匹配技能
    """

    def __init__(self):
        from agents.skill_loader import get_skill_loader
        self.skill_loader = get_skill_loader()
        self._attack_type_mapping = self._build_attack_type_mapping()

    def _build_attack_type_mapping(self) -> Dict[str, List[str]]:
        """
        构建攻击类型到 SkillLoader 技能的映射

        这个映射定义了每个 Intent attack_type 应该匹配哪些真实技能
        """
        return {
            # 端口扫描/信息收集
            "port_scan": ["recon-and-methodology", "recon-for-sec"],
            "recon": ["recon-and-methodology", "recon-for-sec"],
            "subdomain_enum": ["recon-and-methodology"],

            # SQL 注入
            "sqli": ["sqli-sql-injection", "nosql-injection", "injection-checking"],
            "sql_injection": ["sqli-sql-injection", "nosql-injection"],

            # XSS
            "xss": ["xss-cross-site-scripting"],

            # 命令注入
            "cmdi": ["cmdi-command-injection", "injection-checking"],
            "rce": ["cmdi-command-injection", "jndi-injection"],

            # 文件相关
            "lfi": ["path-traversal-lfi", "file-access-vuln"],
            "file_upload": ["upload-insecure-files"],
            "file_read": ["path-traversal-lfi", "file-access-vuln"],
            "dir_scan": ["recon-and-methodology"],
            "fingerprint": ["recon-and-methodology"],

            # API 安全
            "api": ["api-sec", "api-recon-and-docs", "api-authorization-and-bola"],

            # 认证相关
            "auth_bypass": ["authbypass-authentication-flaws", "auth-sec"],
            "jwt": ["jwt-oauth-token-attacks", "api-auth-and-jwt-abuse"],

            # 业务逻辑
            "business_logic": ["business-logic-vuln", "business-logic-vulnerabilities"],

            # CSRF
            "csrf": ["csrf-cross-site-request-forgery"],

            # CORS
            "cors": ["cors-cross-origin-misconfiguration"],

            # SSRF
            "ssrf": ["ssrf-server-side-request-forgery"],

            # XXE
            "xxe": ["xxe-xml-external-entity"],

            # SSTI
            "ssti": ["ssti-server-side-template-injection"],

            # 注入类（通用）
            "injection": ["injection-checking", "sqli-sql-injection", "cmdi-command-injection"],

            # 漏洞扫描
            "vuln_scan": ["recon-and-methodology"],

            # RAG 查询
            "rag_query": [],  # RAG 查询不需要 SkillLoader 技能

            # 全面渗透
            "full_pentest": [
                "recon-and-methodology",
                "sqli-sql-injection",
                "xss-cross-site-scripting",
                "path-traversal-lfi",
                "cmdi-command-injection",
                "authbypass-authentication-flaws",
                "csrf-cross-site-request-forgery",
                "cors-cross-origin-misconfiguration",
                "api-authorization-and-bola",
            ],
        }

    def match_skills(self, attack_types: List[str], context: Dict[str, Any]) -> List[Skill]:
        """
        根据攻击类型匹配技能

        Args:
            attack_types: Intent.attack_types 列表
            context: 执行上下文

        Returns:
            匹配到的 Skill 对象列表
        """
        matched_skill_names = set()

        for at in attack_types:
            at_lower = at.lower()
            # 直接匹配
            if at_lower in self._attack_type_mapping:
                for name in self._attack_type_mapping[at_lower]:
                    matched_skill_names.add(name)
            # 模糊匹配
            else:
                for key, names in self._attack_type_mapping.items():
                    if at_lower in key or key in at_lower:
                        for name in names:
                            matched_skill_names.add(name)

        # 如果没有任何匹配，使用 full_pentest 默认技能
        if not matched_skill_names:
            matched_skill_names = set(self._attack_type_mapping.get("full_pentest", []))

        # 转换为 Skill 对象
        skills = []
        for name in matched_skill_names:
            skill_data = self.skill_loader.get_skill(name)
            if skill_data:
                skill = Skill(
                    name=name,
                    description=skill_data.get("description", ""),
                    attack_types=[at for at in attack_types if at in self._find_attack_types_for_skill(name)],
                    tool="",  # 真实技能通过 SkillLoader 获取内容
                    params_template={},  # 参数模板由 LLM 生成
                    dependencies=[],  # 依赖由动态推理确定
                )
                skills.append(skill)

        return skills

    def _find_attack_types_for_skill(self, skill_name: str) -> List[str]:
        """查找某个技能关联的攻击类型"""
        for at, skills in self._attack_type_mapping.items():
            if skill_name in skills:
                return skills
        return []

    def build_execution_order(self, skills: List[Skill], context: Dict[str, Any]) -> List[Skill]:
        """
        构建执行顺序（先收集，后攻击）

        Args:
            skills: 匹配到的技能列表
            context: 执行上下文

        Returns:
            按执行顺序排列的技能列表
        """
        # 分离侦察类和攻击类
        recon_skills = []
        attack_skills = []

        recon_types = ["recon", "port_scan", "subdomain_enum"]

        for skill in skills:
            is_recon = any(at in recon_types for at in skill.attack_types)
            if is_recon:
                recon_skills.append(skill)
            else:
                attack_skills.append(skill)

        # 侦察优先，攻击在后
        return recon_skills + attack_skills

    def get_skill_content(self, name: str) -> str:
        """获取技能完整内容"""
        return self.skill_loader.get_skill_content(name, include_scenarios=True)

    def list_all_skills(self) -> List[str]:
        """列出所有可用技能"""
        return self.skill_loader.list_skills()


class TaskScheduler:
    """
    任务调度器

    根据 Intent 使用真实的 SkillLoader 技能库动态生成攻击计划
    """

    def __init__(self):
        self.skill_library = SkillLibrary()

    def schedule(self, intent, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        生成执行计划

        Args:
            intent: Intent 对象
            context: 执行上下文

        Returns:
            执行计划列表
        """
        target = intent.targets[0] if intent.targets else ""

        # 匹配技能
        matched_skills = self.skill_library.match_skills(intent.attack_types, context)

        # 构建执行顺序
        execution_order = self.skill_library.build_execution_order(matched_skills, context)

        # 生成执行计划
        plan = []
        for i, skill in enumerate(execution_order):
            plan.append({
                "step": i + 1,
                "skill": skill.name,
                "description": skill.description,
                "tool": "",  # 真实技能使用 SkillLoader 获取内容
                "params": {},  # 参数由 LLM 基于技能内容动态生成
                "attack_types": skill.attack_types,
                "content": self.skill_library.get_skill_content(skill.name),  # 真实技能内容
            })

        return plan

    def get_attack_guidance(self, intent, context: Dict[str, Any]) -> str:
        """
        获取针对 Intent 的攻击指导

        Args:
            intent: Intent 对象
            context: 执行上下文

        Returns:
            格式化的攻击指导文本
        """
        matched_skills = self.skill_library.match_skills(intent.attack_types, context)

        if not matched_skills:
            return "未识别到特定攻击面，建议进行综合侦察"

        guidance_parts = ["## 攻击面分析与建议\n"]

        for i, skill in enumerate(matched_skills[:5], 1):
            guidance_parts.append(f"### {i}. {skill.name}")
            guidance_parts.append(f"描述: {skill.description}")
            guidance_parts.append(f"攻击类型: {', '.join(skill.attack_types)}")
            guidance_parts.append("")

        return "\n".join(guidance_parts)


# 全局实例
_scheduler: Optional[TaskScheduler] = None


def get_scheduler() -> TaskScheduler:
    """获取全局调度器"""
    global _scheduler
    if _scheduler is None:
        _scheduler = TaskScheduler()
    return _scheduler


def get_skill_library() -> SkillLibrary:
    """获取技能库"""
    scheduler = get_scheduler()
    return scheduler.skill_library