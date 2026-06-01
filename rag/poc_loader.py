"""
Pentest Agent - POC/RAG 知识库加载器 (兼容包装)
委托给 SimpleVectorStore 实现
"""
import sys
from typing import Optional, Callable
from pathlib import Path

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

from rag.vector_store import SimpleVectorStore, POC_REPO_PATH, VECTOR_DB_PATH


class POCLoader:
    """POC 知识库加载器 — 兼容包装 SimpleVectorStore"""

    def __init__(
        self,
        repo_path: str = None,
        db_path: str = None,
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        _repo = repo_path or POC_REPO_PATH
        _db = db_path or VECTOR_DB_PATH
        self.repo_path = Path(_repo)
        self.db_path = _db
        self.store = SimpleVectorStore(db_path=_db)

    def load_pocs(self, callback: Optional[Callable] = None) -> int:
        self.store.build_index(repo_path=str(self.repo_path))
        return self.store.count()

    def query(
        self,
        query_text: str,
        n_results: int = 10,
        severity_filter: Optional[str] = None,
        product_filter: Optional[str] = None,
    ) -> list:
        return self.store.query(query_text, n_results, severity_filter, product_filter)

    def query_by_product(self, product: str, n_results: int = 10) -> list:
        return self.store.query_by_product(product, n_results)

    def query_by_cve(self, cve_id: str) -> list:
        return self.store.query_by_cve(cve_id)

    def query_by_severity(self, severity: str, n_results: int = 20) -> list:
        return self.store.query_by_severity(severity, n_results)

    def get_poc(self, poc_id: str) -> Optional[dict]:
        found = [m for m in self.store._metadata if m.get("id") == poc_id]
        if found:
            return {"id": found[0]["id"], "content": found[0].get("description", ""), "metadata": found[0]}
        return None

    def count(self) -> int:
        return self.store.count()

    def reset(self):
        self.store.reset()


_poc_loader: Optional[POCLoader] = None


def get_poc_loader() -> POCLoader:
    global _poc_loader
    if _poc_loader is None:
        _poc_loader = POCLoader()
    return _poc_loader
