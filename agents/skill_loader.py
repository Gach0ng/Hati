"""
Pentest Agent - Skills Loader
加载和管理 hack-skills 攻击知识库
"""

import os
import sys
import re
from typing import Dict, List, Optional, Any
from pathlib import Path

# Fix Unicode output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Celery worker: stdout/stderr is LoggingProxy


class SkillLoader:
    """
    攻击技能加载器

    从 hack-skills 目录加载各类渗透测试技能 playbook
    """

    def __init__(self, skills_path: str = None):
        if skills_path is None:
            # 默认路径
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            skills_path = os.path.join(base_dir, "skills", "hack-skills", "skills")
        self.skills_path = Path(skills_path)
        self._skills_cache: Dict[str, Dict[str, Any]] = {}
        self._load_all_skills()

    def _load_all_skills(self):
        """加载所有技能"""
        if not self.skills_path.exists():
            print(f"[SkillLoader] 技能目录不存在: {self.skills_path}")
            return

        for skill_dir in self.skills_path.iterdir():
            if skill_dir.is_dir():
                skill_name = skill_dir.name
                skill_data = self._load_skill(skill_dir)
                if skill_data:
                    self._skills_cache[skill_name] = skill_data

        print(f"[SkillLoader] 已加载 {len(self._skills_cache)} 个攻击技能")

    def _load_skill(self, skill_dir: Path) -> Optional[Dict[str, Any]]:
        """加载单个技能"""
        skill_file = skill_dir / "SKILL.md"
        scenarios_file = skill_dir / "SCENARIOS.md"

        if not skill_file.exists():
            return None

        try:
            with open(skill_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 解析 frontmatter
            metadata = self._parse_frontmatter(content)

            # 提取主要章节
            sections = self._extract_sections(content)

            result = {
                "name": metadata.get("name", skill_dir.name),
                "description": metadata.get("description", ""),
                "content": content,
                "sections": sections,
                "dir": skill_dir.name,
            }

            # 加载 SCENARIOS 如果存在
            if scenarios_file.exists():
                with open(scenarios_file, 'r', encoding='utf-8') as f:
                    result["scenarios"] = f.read()

            return result

        except Exception as e:
            print(f"[SkillLoader] 加载技能失败 {skill_dir.name}: {e}")
            return None

    def _parse_frontmatter(self, content: str) -> Dict[str, str]:
        """解析 YAML frontmatter"""
        metadata = {}
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                for line in parts[1].strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        metadata[key.strip()] = value.strip()
        return metadata

    def _extract_sections(self, content: str) -> Dict[str, str]:
        """提取主要章节"""
        sections = {}

        # 移除 frontmatter
        if content.startswith('---'):
            content = content.split('---', 2)[-1]

        # 按 ## 标题分割
        current_title = "introduction"
        current_content = []

        for line in content.split('\n'):
            if line.startswith('## '):
                # 保存上一个章节
                if current_title:
                    sections[current_title] = '\n'.join(current_content).strip()
                # 开始新章节
                current_title = line[3:].strip().lower().replace(' ', '_')
                current_content = []
            else:
                current_content.append(line)

        # 保存最后一个章节
        if current_title:
            sections[current_title] = '\n'.join(current_content).strip()

        return sections

    def get_skill(self, name: str) -> Optional[Dict[str, Any]]:
        """获取指定技能"""
        return self._skills_cache.get(name)

    def list_skills(self) -> List[str]:
        """列出所有技能"""
        return list(self._skills_cache.keys())

    def get_skill_description(self, name: str) -> str:
        """获取技能描述"""
        skill = self._skills_cache.get(name)
        return skill.get("description", "") if skill else ""

    def match_skills(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        根据目标信息匹配相关技能

        Args:
            target_info: {
                "url": str,
                "tech": ["php", "mysql", ...],
                "open_ports": [80, 443, 3306, ...],
                "headers": {...},
                "keywords": ["login", "search", "id"]
            }

        Returns:
            匹配到的技能列表，按相关度排序
        """
        matched = []
        tech = target_info.get("tech", [])
        ports = target_info.get("open_ports", [])
        keywords = target_info.get("keywords", [])
        url = target_info.get("url", "")

        for name, skill in self._skills_cache.items():
            score = 0
            reasons = []

            # URL 关键词匹配
            url_lower = url.lower()
            desc_lower = skill["description"].lower()

            if "sql" in tech or "mysql" in tech or "postgresql" in tech or "mssql" in tech:
                if "sql" in name.lower() or "sqli" in desc_lower:
                    score += 3
                    reasons.append("数据库相关")

            if 3306 in ports or 1433 in ports or 5432 in ports or 27017 in ports:
                if "sql" in name.lower():
                    score += 2
                    reasons.append("数据库端口开放")

            if "php" in tech:
                if "rce" in name.lower() or "file" in name.lower() or "lfi" in name.lower():
                    score += 2
                    reasons.append("PHP目标")

            if "apache" in tech or "nginx" in tech:
                if "path" in name.lower() or "lfi" in name.lower():
                    score += 1
                    reasons.append("Web服务器")

            if any(k in url_lower for k in ["login", "auth", "signin", "admin"]):
                if "auth" in name.lower() or "bypass" in name.lower():
                    score += 2
                    reasons.append("认证相关URL")

            if any(k in keywords for k in ["search", "query", "id", "page", "cat"]):
                if "sqli" in name.lower() or "injection" in name.lower():
                    score += 3
                    reasons.append("可疑参数")

            # 检查技能描述中的关键词
            for keyword in keywords:
                if keyword.lower() in desc_lower:
                    score += 1
                    reasons.append(f"关键词: {keyword}")

            if score > 0:
                matched.append({
                    "name": name,
                    "description": skill["description"],
                    "score": score,
                    "reasons": reasons,
                    "skill": skill,
                })

        # 按分数排序
        matched.sort(key=lambda x: x["score"], reverse=True)
        return matched

    def get_skill_content(self, name: str, include_scenarios: bool = True) -> str:
        """获取技能完整内容"""
        skill = self._skills_cache.get(name)
        if not skill:
            return ""

        content = skill["content"]
        if include_scenarios and skill.get("scenarios"):
            content += "\n\n---\n\n## SCENARIOS\n\n" + skill["scenarios"]

        return content

    def get_attack_guidance(self, target_info: Dict[str, Any]) -> str:
        """
        获取针对目标的攻击指导

        Returns:
            格式化的攻击指导文本
        """
        matched = self.match_skills(target_info)

        if not matched:
            return "未识别到特定攻击面，建议进行综合侦察"

        guidance_parts = ["## 攻击面分析与建议\n"]

        for i, m in enumerate(matched[:5], 1):
            guidance_parts.append(f"### {i}. {m['name']}")
            guidance_parts.append(f"相关度: {m['score']}")
            guidance_parts.append(f"原因: {', '.join(m['reasons'])}")
            guidance_parts.append(f"描述: {m['description']}")

            # 提取技能的关键建议
            sections = m['skill'].get('sections', {})
            if 'quick_start' in sections:
                guidance_parts.append(f"\n快速开始:\n{sections['quick_start'][:500]}")
            elif 'detection' in sections:
                guidance_parts.append(f"\n检测方法:\n{sections['detection'][:300]}")

            guidance_parts.append("")

        return "\n".join(guidance_parts)


# 全局单例
_skill_loader: Optional[SkillLoader] = None


def get_skill_loader() -> SkillLoader:
    """获取技能加载器单例"""
    global _skill_loader
    if _skill_loader is None:
        _skill_loader = SkillLoader()
    return _skill_loader
