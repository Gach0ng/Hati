#!/usr/bin/env python3
"""
Pentest Agent - POC 知识库加载脚本
将本地 POC 仓库加载到 ChromaDB 向量数据库
"""

import sys
import os

# 添加项目根目录到 path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.poc_loader import POCLoader


def main():
    """主函数"""
    print("=" * 60)
    print("Pentest Agent - POC 知识库加载")
    print("=" * 60)

    # 创建加载器
    loader = POCLoader()

    # 检查仓库是否存在
    if not loader.repo_path.exists():
        print(f"❌ POC 仓库路径不存在: {loader.repo_path}")
        print("\n请先克隆 POC 仓库:")
        print("  git clone https://github.com/eeeeeeeeee-code/POC.git poc")
        return 1

    # 确认加载
    print(f"\n📁 POC 仓库: {loader.repo_path}")
    print(f"📊 ChromaDB: {loader.db_path}")

    existing_count = loader.count()
    if existing_count > 0:
        print(f"\n⚠️  知识库已有 {existing_count} 条记录")
        response = input("是否要重建知识库? (y/N): ")
        if response.lower() != "y":
            print("取消加载")
            return 0
        print("正在重置知识库...")
        loader.reset()

    # 统计文件数
    md_files = list(loader.repo_path.rglob("*.md"))
    print(f"\n📝 发现 {len(md_files)} 个 POC 文件")

    # 开始加载
    print("\n" + "=" * 60)
    print("开始加载 POC 到向量数据库...")
    print("=" * 60 + "\n")

    def progress_callback(poc_data: dict):
        pass  # 简化回调

    count = loader.load_pocs()

    print("\n" + "=" * 60)
    print("✅ POC 知识库加载完成!")
    print("=" * 60)
    print(f"\n📊 知识库统计:")
    print(f"   总条目: {count}")
    print(f"   存储路径: {loader.db_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
