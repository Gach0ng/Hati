"""
Pentest Agent - 全局配置文件
"""

import os
from pydantic_settings import BaseSettings
from typing import Optional


# ===========================================
# 环境变量配置
# ===========================================
class Settings(BaseSettings):
    """应用配置"""

    # API 配置
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False

    # HexStrike MCP Server (runs in Kali VM, accessed via network)
    hexstrike_server_url: str = "http://localhost:9999"

    # MiniMax API
    minimax_api_key: str = ""
    minimax_group_id: str = ""
    minimax_model: str = "abab6.5s-chat"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_db_progress: int = 2

    # Elasticsearch
    elasticsearch_host: str = "localhost"
    elasticsearch_port: int = 9200

    # Docker (Windows: docker_host is unused, tools run on VM via MCP)
    docker_host: str = "unix:///var/run/docker.sock"
    toolkit_image: str = "kalilinux/kali-rolling:latest"

    # RAG 知识库
    chroma_db_path: str = "./data/cve_knowledge_base"
    cve_kb_path: str = "./data/cve_knowledge_base"
    poc_kb_path: str = "./data/poc_knowledge_base"
    poc_repo_path: str = "./poc/wpoc"
    embedding_model: str = "all-MiniLM-L6-v2"

    # SSH Tunnel (for accessing VM MCP securely)
    ssh_tunnel_host: str = ""
    ssh_tunnel_port: int = 22
    ssh_tunnel_user: str = "root"
    ssh_tunnel_password: str = ""
    ssh_tunnel_local_port: int = 9999
    ssh_tunnel_remote_port: int = 9999

    # 安全配置
    approval_required: bool = True
    audit_logging_enabled: bool = True
    jwt_secret_key: str = "change-me-in-production"

    # 任务配置
    max_concurrent_tasks: int = 5
    task_timeout_seconds: int = 3600

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"  # 允许额外的环境变量（如部署特定配置）


# 全局配置实例
settings = Settings()
