"""
Pentest Agent - RAG 查询接口
基于 numpy SimpleVectorStore 的统一 POC 知识库查询
"""
import os
from typing import Optional, Literal
from dataclasses import dataclass

POC_KB_PATH = os.getenv("POC_KB_PATH", "./data/poc_knowledge_base")


@dataclass
class Vulnerability:
    """漏洞信息数据类"""
    id: str
    name: str
    source: str  # "poc"
    cve_id: Optional[str] = None
    product: Optional[str] = None
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    description: str = ""
    poc_content: Optional[str] = None
    poc_path: Optional[str] = None
    references: list = None
    similarity: float = 0.0

    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class QueryResult:
    """查询结果数据类"""
    query: str
    vulnerabilities: list
    total_count: int
    by_severity: dict
    by_source: dict


class RAGQueryInterface:
    """RAG 查询接口 — 基于 SimpleVectorStore"""

    def __init__(self, poc_kb_path: str = POC_KB_PATH):
        self.store = None
        try:
            from rag.vector_store import SimpleVectorStore
            self.store = SimpleVectorStore(db_path=poc_kb_path)
            cnt = self.store.count()
            print(f"[RAG] POC 知识库已加载: {cnt} 条")
        except Exception as e:
            print(f"[RAG] POC 知识库加载失败: {e}")

    def query(
        self,
        query_text: str,
        n_results: int = 10,
        sources: Optional[list] = None,
        severity_filter: Optional[str] = None,
    ) -> QueryResult:
        vulnerabilities = []
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        by_source = {"poc": 0}

        if self.store and self.store.count() > 0:
            try:
                poc_results = self.store.query(
                    query_text=query_text,
                    n_results=n_results,
                    severity_filter=severity_filter,
                )
                for r in poc_results:
                    vuln = Vulnerability(
                        id=r["id"],
                        name=r.get("vuln_name", r.get("product", "")),
                        source="poc",
                        product=r.get("product"),
                        severity=r.get("severity", "unknown"),
                        description=r.get("description", ""),
                        poc_content=r.get("description", ""),
                        poc_path=r.get("file_path"),
                        references=r.get("cve_ids", []),
                        similarity=r.get("similarity", 0),
                    )
                    vulnerabilities.append(vuln)
                    by_source["poc"] += 1
                    by_severity[vuln.severity] = by_severity.get(vuln.severity, 0) + 1
            except Exception as e:
                print(f"[RAG] 查询失败: {e}")

        vulnerabilities.sort(key=lambda v: v.similarity, reverse=True)
        return QueryResult(
            query=query_text,
            vulnerabilities=vulnerabilities,
            total_count=len(vulnerabilities),
            by_severity=by_severity,
            by_source=by_source,
        )

    def query_by_product(self, product: str, n_results: int = 10) -> QueryResult:
        return self.query(query_text=f"{product} vulnerability exploit", n_results=n_results)

    def query_by_cve(self, cve_id: str) -> QueryResult:
        return self.query(query_text=f"{cve_id} {cve_id.replace('CVE-', '')}", n_results=5)

    def query_exploits(
        self,
        target: str,
        technologies: list = None,
        severity: str = "high",
        n_results: int = 10,
    ) -> QueryResult:
        parts = [target]
        if technologies:
            parts.extend(technologies)
        parts.extend(["exploit", "poc", "rce", severity])
        return self.query(query_text=" ".join(parts), n_results=n_results)

    def get_exploit_content(self, poc_id: str) -> Optional[dict]:
        if not self.store:
            return None
        # Find by ID in metadata
        for i, mid in enumerate(self.store._ids):
            if mid == poc_id:
                meta = self.store._metadata[i]
                return {
                    "id": meta["id"],
                    "content": meta.get("description", ""),
                    "metadata": meta,
                }
        return None

    def get_stats(self) -> dict:
        if self.store:
            s = self.store.get_stats()
            return {
                "cve_count": 0,
                "poc_count": s["total_count"],
                "total_count": s["total_count"],
            }
        return {"cve_count": 0, "poc_count": 0, "total_count": 0}


_rag_interface: Optional[RAGQueryInterface] = None


def get_rag_interface() -> RAGQueryInterface:
    global _rag_interface
    if _rag_interface is None:
        _rag_interface = RAGQueryInterface()
    return _rag_interface
