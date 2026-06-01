"""
Pentest Agent - POC 向量存储
使用 numpy 做向量检索，零外部依赖冲突
"""
import os
import sys
import json
import re
import numpy as np
from typing import Optional, List, Dict
from pathlib import Path
from datetime import datetime

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")

# Use SentenceTransformer for embedding generation
from sentence_transformers import SentenceTransformer

# ===========================================
# 配置
# ===========================================
POC_REPO_PATH = os.getenv("POC_REPO_PATH", "./poc/wpoc")
VECTOR_DB_PATH = os.getenv("VECTOR_DB_PATH", "./data/poc_knowledge_base")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DIM = 384


class SimpleVectorStore:
    """numpy 向量存储 — 轻量, 零 DLL 冲突"""

    def __init__(
        self,
        db_path: str = VECTOR_DB_PATH,
        embedding_model: str = EMBEDDING_MODEL,
    ):
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        self.embedding_model_name = embedding_model
        self._model = None
        self._embeddings: Optional[np.ndarray] = None
        self._metadata: List[Dict] = []
        self._ids: List[str] = []

        # Load existing data
        self._load()

    @property
    def model(self):
        if self._model is None:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            self._model = SentenceTransformer(self.embedding_model_name)
        return self._model

    @property
    def embeddings_file(self):
        return self.db_path / "embeddings.npy"

    @property
    def metadata_file(self):
        return self.db_path / "metadata.jsonl"

    def _load(self):
        """从磁盘加载向量和元数据"""
        if self.embeddings_file.exists():
            self._embeddings = np.load(self.embeddings_file)
            print(f"[VectorStore] 加载了 {self._embeddings.shape[0]} 条向量 ({self._embeddings.shape[1]}维)")

        if self.metadata_file.exists():
            with open(self.metadata_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        self._metadata.append(rec)
                        self._ids.append(rec.get("id", ""))
            print(f"[VectorStore] 加载了 {len(self._metadata)} 条元数据")

    def _save(self):
        """保存向量和元数据"""
        if self._embeddings is not None:
            np.save(self.embeddings_file, self._embeddings)
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            for rec in self._metadata:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def count(self) -> int:
        return len(self._ids)

    def _parse_poc_file(self, file_path: Path) -> Optional[dict]:
        """解析 POC markdown 文件"""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        cve_pattern = r"CVE-\d{4}-\d{4,}"
        cve_ids = re.findall(cve_pattern, content, re.IGNORECASE)
        product = file_path.parent.name
        vuln_name = file_path.stem.replace("-", " ").replace("_", " ")
        desc = content[:500].strip()

        severity = "medium"
        cl = content.lower()
        if any(kw in cl for kw in ["rce", "远程代码执行", "命令执行"]):
            severity = "critical"
        elif any(kw in cl for kw in ["sql注入", "sql injection", "xss", "敏感信息"]):
            severity = "high"
        elif any(kw in cl for kw in ["信息泄露", "ssrf", "csrf"]):
            severity = "medium"

        search_text = f"{product} {vuln_name} {desc} {' '.join(cve_ids)}"
        return {
            "id": f"{product}___{file_path.stem}",
            "product": product,
            "vuln_name": vuln_name,
            "severity": severity,
            "cve_ids": cve_ids,
            "description": desc[:500],
            "content": content[:10000],
            "file_path": str(file_path),
            "search_text": search_text,
        }

    def build_index(self, repo_path: str = POC_REPO_PATH, limit: int = 0):
        """从 wpoc/ 构建向量索引"""
        repo = Path(repo_path)
        if not repo.exists():
            print(f"[VectorStore] PoC 目录不存在: {repo}")
            return

        files = sorted(repo.rglob("*.md"))
        if limit > 0:
            files = files[:limit]
        total = len(files)
        print(f"[VectorStore] 开始索引 {total} 个 PoC 文件...")

        emb_list = []
        new_ids, new_meta = [], []

        for i, fp in enumerate(files):
            poc = self._parse_poc_file(fp)
            if poc is None:
                continue

            vec = self.model.encode(poc["search_text"])

            emb_list.append(vec)
            new_ids.append(poc["id"])
            new_meta.append({
                "id": poc["id"],
                "product": poc["product"],
                "vuln_name": poc["vuln_name"],
                "severity": poc["severity"],
                "cve_ids": poc["cve_ids"],
                "description": poc["description"],
                "file_path": poc["file_path"],
                "loaded_at": datetime.utcnow().isoformat(),
            })

            if (i + 1) % 200 == 0:
                print(f"  已索引: {i + 1}/{total}")

        if not emb_list:
            print("[VectorStore] 无文件可索引")
            return

        self._embeddings = np.array(emb_list, dtype=np.float32)
        self._ids = new_ids
        self._metadata = new_meta
        self._save()
        print(f"[VectorStore] 索引完成: {len(new_ids)} 条记录, 向量形状 {self._embeddings.shape}")

    def query(
        self,
        query_text: str,
        n_results: int = 10,
        severity_filter: Optional[str] = None,
        product_filter: Optional[str] = None,
    ) -> list:
        """向量相似度查询"""
        if self._embeddings is None or len(self._ids) == 0:
            return []

        qvec = self.model.encode(query_text)
        # 归一化
        qvec = qvec / (np.linalg.norm(qvec) + 1e-8)
        norms = np.linalg.norm(self._embeddings, axis=1, keepdims=True) + 1e-8
        db_normed = self._embeddings / norms
        sims = np.dot(db_normed, qvec)  # cosine similarity

        # Top-k indices
        k = min(n_results * 3, len(sims))  # get extra for filtering
        top_indices = np.argsort(sims)[::-1][:k]

        results = []
        for idx in top_indices:
            meta = self._metadata[idx]
            if severity_filter and meta.get("severity") != severity_filter:
                continue
            if product_filter and meta.get("product") != product_filter:
                continue
            results.append({
                "id": meta["id"],
                "product": meta.get("product", ""),
                "vuln_name": meta.get("vuln_name", ""),
                "severity": meta.get("severity", ""),
                "cve_ids": meta.get("cve_ids", []),
                "description": meta.get("description", ""),
                "file_path": meta.get("file_path", ""),
                "similarity": float(sims[idx]),
                "distance": float(1.0 - sims[idx]),
            })
            if len(results) >= n_results:
                break

        return results

    def query_by_product(self, product: str, n_results: int = 10) -> list:
        return self.query(f"{product} vulnerability exploit", n_results=n_results)

    def query_by_cve(self, cve_id: str) -> list:
        return self.query(f"{cve_id} {cve_id.replace('CVE-', '')}", n_results=5)

    def query_by_severity(self, severity: str, n_results: int = 20) -> list:
        return self.query(f"{severity} severity vulnerability exploit", n_results=n_results, severity_filter=severity)

    def get_stats(self) -> dict:
        """获取知识库统计"""
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        products = set()
        cves = set()
        for m in self._metadata:
            sev = m.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            products.add(m.get("product", ""))
            for c in m.get("cve_ids", []):
                if c:
                    cves.add(c)
        return {
            "total_count": len(self._ids),
            "by_severity": sev_counts,
            "product_count": len(products),
            "cve_count": len(cves),
        }

    def reset(self):
        """重置数据库"""
        self._embeddings = None
        self._ids = []
        self._metadata = []
        if self.embeddings_file.exists():
            self.embeddings_file.unlink()
        if self.metadata_file.exists():
            self.metadata_file.unlink()
        print("[VectorStore] 数据库已重置")


# ===========================================
# 全局单例
# ===========================================
_vector_store: Optional[SimpleVectorStore] = None


def get_vector_store() -> SimpleVectorStore:
    global _vector_store
    if _vector_store is None:
        _vector_store = SimpleVectorStore()
    return _vector_store
