"""
Hati - Report Agent (报告生成)
汇总渗透测试结果，生成 Markdown 格式报告
"""

import json
from typing import Dict, Any
from datetime import datetime

from state.pentest_state import PentestState, PentestPhase, TaskState, add_agent_message
from config.minimax_config import get_llm, get_system_prompt
from security.audit_logger import AuditLogger


# ===========================================
# Report Agent
# ===========================================
class ReportAgent:
    """
    报告生成 Agent

    职责：
    - 汇总所有渗透测试结果
    - 生成结构化的 Markdown 报告
    - 提供风险评估和建议
    """

    def __init__(self, audit_logger: AuditLogger = None):
        self.audit_logger = audit_logger
        self.llm = get_llm()

    def run(self, state: PentestState) -> PentestState:
        """
        生成渗透测试报告

        Args:
            state: 当前状态

        Returns:
            更新后的状态
        """
        task_id = state["task_id"]
        target = state["target"]
        scope = state["scope"]
        created_at = state["created_at"]

        print(f"[ReportAgent] 生成渗透测试报告: {target}")

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="ReportAgent",
                action="start_report_generation",
                task_id=task_id,
                target=target,
            )

        # 收集各阶段结果
        recon_result = state.get("recon_result", {})
        vuln_result = state.get("vuln_result", {})
        exploit_results = state.get("exploit_results", [])

        # 生成报告内容
        report_content = self._generate_markdown_report(
            task_id=task_id,
            target=target,
            scope=scope,
            created_at=created_at,
            recon_result=recon_result,
            vuln_result=vuln_result,
            exploit_results=exploit_results,
        )

        # 生成执行摘要
        executive_summary = self._generate_executive_summary(vuln_result, exploit_results)

        # 生成风险统计
        risk_summary = self._generate_risk_summary(vuln_result)

        # 修复建议
        recommendations = self._generate_recommendations(vuln_result)

        report = {
            "task_id": task_id,
            "target": target,
            "scope": scope,
            "start_time": created_at,
            "end_time": datetime.utcnow().isoformat(),
            "executive_summary": executive_summary,
            "methodology": [
                "信息收集 (Reconnaissance)",
                "漏洞扫描 (Vulnerability Assessment)",
                "漏洞利用 (Exploitation)",
                "报告生成 (Reporting)",
            ],
            "recon_findings": recon_result,
            "vuln_findings": vuln_result,
            "exploit_findings": exploit_results,
            "risk_summary": risk_summary,
            "recommendations": recommendations,
            "appendices": {
                "tools_used": ["nmap", "nuclei", "nikto", "httpx"],
                "raw_outputs": "See attached raw data",
            },
            "markdown_content": report_content,
        }

        # 记录审计日志
        if self.audit_logger:
            self.audit_logger.log_agent_action(
                agent="ReportAgent",
                action="report_generation_complete",
                task_id=task_id,
                target=target,
                result_summary=f"报告生成完成",
            )

        # 添加 Agent 消息
        state = add_agent_message(
            state=state,
            from_agent="ReportAgent",
            to_agent="Orchestrator",
            action="report_generation",
            reasoning="渗透测试完成，生成最终报告",
            result={"report_length": len(report_content)},
            status="success",
        )

        # 更新状态
        from state.pentest_state import update_state, advance_phase

        state = update_state(
            state,
            report=report,
            status=TaskState.SUCCESS,
        )
        state = advance_phase(state, PentestPhase.COMPLETE)

        print(f"[ReportAgent] 报告生成完成")

        # 保存报告到磁盘
        self._save_report_to_disk(task_id, target, report, report_content)

        return state

    def _save_report_to_disk(self, task_id: str, target: str, report: dict, markdown_content: str):
        """保存报告到磁盘"""
        import os
        import re

        # 创建报告目录
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # 清理目标URL用于文件名
        safe_target = re.sub(r'[^\w\-_.]', '_', target)
        safe_target = safe_target.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
        if len(safe_target) > 50:
            safe_target = safe_target[:50]

        # 生成文件名
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{safe_target}_{task_id[:8]}.md"
        filepath = os.path.join(reports_dir, filename)

        # 写入文件
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            print(f"[ReportAgent] 📄 报告已保存: {filepath}")

            # 同时保存JSON格式（包含完整数据结构）
            json_filename = filepath.replace('.md', '.json')
            with open(json_filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"[ReportAgent] 📄 JSON报告已保存: {json_filename}")
        except Exception as e:
            print(f"[ReportAgent] ⚠️ 保存报告失败: {e}")

    def _generate_markdown_report(
        self,
        task_id: str,
        target: str,
        scope: list,
        created_at: str,
        recon_result: dict,
        vuln_result: dict,
        exploit_results: list,
    ) -> str:
        """生成 Markdown 格式报告"""
        scan_summary = vuln_result.get("scan_summary", {}) if vuln_result else {}
        vulnerabilities = vuln_result.get("vulnerabilities", []) if vuln_result else []

        # 如果 scan_summary 为空，从 vulnerabilities 计算
        if not scan_summary and vulnerabilities:
            scan_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in vulnerabilities:
                severity = v.get("severity", "unknown").lower()
                if severity in scan_summary:
                    scan_summary[severity] += 1
                    scan_summary["total"] += 1
                elif severity == "info":
                    scan_summary["info"] += 1
                    scan_summary["total"] += 1

        md = f"""# 渗透测试报告

## 执行摘要

**任务 ID**: {task_id}
**目标**: {target}
**测试范围**: {', '.join(scope)}
**测试日期**: {created_at.split('T')[0]}
**报告生成时间**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. 测试概述

本次渗透测试针对 **{target}** 进行了全面的安全评估，测试范围包括：
- 网络发现与端口扫描
- 漏洞识别与验证
- 风险评估与建议

### 1.1 发现统计

| 类别 | 数量 |
|------|------|
| 关键 (Critical) | {scan_summary.get('critical', 0)} |
| 高危 (High) | {scan_summary.get('high', 0)} |
| 中危 (Medium) | {scan_summary.get('medium', 0)} |
| 低危 (Low) | {scan_summary.get('low', 0)} |
| 信息 (Info) | {scan_summary.get('info', 0)} |
| **总计** | **{scan_summary.get('total', 0)}** |

---

## 2. 测试方法论

本次测试采用业界标准的渗透测试方法论：

1. **信息收集 (Reconnaissance)**
   - 被动信息收集
   - 主动扫描探测

2. **漏洞评估 (Vulnerability Assessment)**
   - 自动化漏洞扫描
   - 手动漏洞验证

3. **漏洞利用 (Exploitation)**
   - 已确认漏洞的利用尝试
   - (在获得授权的情况下进行)

4. **报告编写 (Reporting)**
   - 结果汇总与分析
   - 修复建议提供

---

## 3. 发现的漏洞

"""

        # 添加漏洞详情
        vulnerabilities = vuln_result.get("vulnerabilities", []) if vuln_result else []

        if vulnerabilities:
            # 按严重程度排序
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: severity_order.get(v.get("severity", "info").lower(), 5)
            )

            for i, vuln in enumerate(sorted_vulns, 1):
                md += f"""### 3.{i} {vuln.get('name', 'Unknown Vulnerability')}

**严重程度**: {vuln.get('severity', 'Unknown').upper()}
**CVE ID**: {vuln.get('cve_id', 'N/A')}
**CVSS 评分**: {vuln.get('cvss_score', 'N/A')}

**描述**:
{vuln.get('description', 'No description available.')}

**影响目标**: {vuln.get('target', target)}
**URL**: {vuln.get('url', 'N/A')}

**状态**: {vuln.get('status', 'potential').upper()}

---
"""
        else:
            md += """
*本次测试未发现明显漏洞。*

"""

        # 添加风险总结
        md += """
---

## 4. 风险总结

"""
        if scan_summary.get("critical", 0) > 0 or scan_summary.get("high", 0) > 0:
            md += """
⚠️ **重要发现**: 检测到多个高风险漏洞，建议立即处理。

"""
        else:
            md += """
✅ 本次测试未发现高危或严重级别的漏洞。
"""

        # 添加建议
        md += """
---

## 5. 修复建议

"""
        recommendations = self._generate_recommendations(vuln_result)
        for i, rec in enumerate(recommendations, 1):
            md += f"{i}. {rec}\n"

        # 页脚
        md += f"""
---

## 附录

### A. 工具列表

本次测试使用的主要工具：
- Nmap (网络扫描)
- Nuclei (漏洞扫描)
- Nikto (Web 服务器扫描)
- Httpx (HTTP 检测)

### B. 免责声明

本报告仅供授权方使用，未经许可不得对外传播。测试结果仅反映测试时的安全状态，安全状况可能随系统变更而改变。

---

*报告由 Hati 自动生成*
*生成时间: {datetime.utcnow().isoformat()}*
"""

        return md

    def _generate_executive_summary(self, vuln_result: dict, exploit_results: list) -> str:
        """生成执行摘要"""
        scan_summary = vuln_result.get("scan_summary", {}) if vuln_result else {}
        vulnerabilities = vuln_result.get("vulnerabilities", []) if vuln_result else []

        # 如果 scan_summary 为空，从 vulnerabilities 计算
        if not scan_summary and vulnerabilities:
            scan_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in vulnerabilities:
                severity = v.get("severity", "unknown").lower()
                if severity in scan_summary:
                    scan_summary[severity] += 1
                    scan_summary["total"] += 1
                elif severity == "info":
                    scan_summary["info"] += 1
                    scan_summary["total"] += 1

        total = scan_summary.get("total", 0)
        critical = scan_summary.get("critical", 0)
        high = scan_summary.get("high", 0)

        if total == 0:
            return f"对目标进行了全面扫描，未发现安全漏洞。建议继续保持安全监测。"

        summary_parts = []
        if critical > 0:
            summary_parts.append(f"发现 {critical} 个严重漏洞，需要立即处理")
        if high > 0:
            summary_parts.append(f"发现 {high} 个高危漏洞，建议尽快处理")

        if summary_parts:
            return " ".join(summary_parts) + f"。共发现 {total} 个安全问题。"
        else:
            return f"共发现 {total} 个安全问题，均为中低危，建议按计划处理。"

    def _generate_risk_summary(self, vuln_result: dict) -> dict:
        """生成风险统计"""
        scan_summary = vuln_result.get("scan_summary", {}) if vuln_result else {}
        vulnerabilities = vuln_result.get("vulnerabilities", []) if vuln_result else []

        # 如果 scan_summary 为空，从 vulnerabilities 计算
        if not scan_summary and vulnerabilities:
            scan_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in vulnerabilities:
                severity = v.get("severity", "unknown").lower()
                if severity in scan_summary:
                    scan_summary[severity] += 1
                    scan_summary["total"] += 1
                elif severity == "info":
                    scan_summary["info"] += 1
                    scan_summary["total"] += 1

        return {
            "total_vulnerabilities": scan_summary.get("total", 0),
            "critical": scan_summary.get("critical", 0),
            "high": scan_summary.get("high", 0),
            "medium": scan_summary.get("medium", 0),
            "low": scan_summary.get("low", 0),
            "info": scan_summary.get("info", 0),
            "overall_risk": self._calculate_overall_risk(scan_summary),
        }

    def _calculate_overall_risk(self, scan_summary: dict) -> str:
        """计算整体风险等级"""
        critical = scan_summary.get("critical", 0)
        high = scan_summary.get("high", 0)

        if critical > 0:
            return "CRITICAL"
        elif high > 3:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self, vuln_result: dict) -> list:
        """生成修复建议"""
        vulnerabilities = vuln_result.get("vulnerabilities", []) if vuln_result else []

        recommendations = []

        # 按严重程度分组
        critical_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]
        high_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == "high"]

        if critical_vulns:
            recommendations.append(
                "【紧急】立即修复以下严重漏洞: " +
                ", ".join([v.get("name", v.get("cve_id", "Unknown")) for v in critical_vulns[:3]])
            )

        if high_vulns:
            recommendations.append(
                "【高优先级】尽快修复以下高危漏洞: " +
                ", ".join([v.get("name", v.get("cve_id", "Unknown")) for v in high_vulns[:5]])
            )

        # 通用建议
        recommendations.extend([
            "建议建立定期漏洞扫描机制，建议每周进行一次全面扫描",
            "建议对所有输入进行严格的输入验证，防止注入类攻击",
            "建议启用 Web 应用防火墙 (WAF) 提供额外保护层",
            "建议定期更新系统和应用程序到最新版本",
            "建议实施安全编码实践，对开发人员进行安全培训",
        ])

        return recommendations[:10]  # 限制数量


# ===========================================
# Celery Task
# ===========================================
from config.celery_config import celery_app


@celery_app.task(name="agents.report_agent.run", queue="report")
def run_report_generation(
    task_id: str,
    target: str,
    scope: list,
    recon_result: dict,
    vuln_result: dict,
    exploit_results: list,
) -> dict:
    """
    Celery Task: 生成渗透测试报告

    Args:
        task_id: 任务 ID
        target: 目标
        scope: 授权范围
        recon_result: 信息收集结果
        vuln_result: 漏洞扫描结果
        exploit_results: 利用结果

    Returns:
        执行结果
    """
    from state.pentest_state import create_initial_state

    # 创建初始状态
    state = create_initial_state(
        task_id=task_id,
        target=target,
        scope=scope,
        authorized_by="system",
    )
    state["recon_result"] = recon_result
    state["vuln_result"] = vuln_result
    state["exploit_results"] = exploit_results

    # 执行 Report Agent
    agent = ReportAgent()
    result_state = agent.run(state)

    return {
        "task_id": task_id,
        "status": result_state["status"],
        "report": result_state["report"],
    }
