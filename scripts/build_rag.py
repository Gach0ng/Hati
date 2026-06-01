"""
Build RAG knowledge base from wpoc/ markdown files.
Uses SimpleVectorStore (numpy-based, no ChromaDB) — zero DLL conflicts.
"""
import os
import sys
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure env vars before any imports
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

from rag.vector_store import SimpleVectorStore


def main():
    parser = argparse.ArgumentParser(description="Build RAG vector database")
    parser.add_argument("--limit", type=int, default=0, help="Max files (0=all)")
    parser.add_argument("--db-path", default="./data/poc_knowledge_base", help="Output DB path")
    parser.add_argument("--repo-path", default="./poc/wpoc", help="POC markdown repo path")
    args = parser.parse_args()

    store = SimpleVectorStore(db_path=args.db_path)
    store.reset()  # Start fresh
    store.build_index(repo_path=args.repo_path, limit=args.limit)

    print(f"\nBuild complete: {store.count()} POCs indexed")
    stats = store.get_stats()
    print(f"  By severity: {stats['by_severity']}")
    print(f"  Products: {stats['product_count']}")
    print(f"  CVEs: {stats['cve_count']}")


if __name__ == "__main__":
    main()
