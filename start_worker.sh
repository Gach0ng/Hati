#!/bin/bash
# ===========================================
# Pentest Agent - Celery Worker 启动脚本
# ===========================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(dirname "$0")"

echo -e "${BLUE}"
echo "=========================================="
echo "   Pentest Agent - Celery Worker"
echo "=========================================="
echo -e "${NC}"

# 激活虚拟环境
if [ -d "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

cd "$PROJECT_ROOT"

# 检查 Redis
if ! nc -z localhost 6379 2>/dev/null; then
    echo -e "${RED}❌ Redis 未运行，请先启动 Docker 服务${NC}"
    echo -e "${YELLOW}   cd $PROJECT_ROOT/docker && docker-compose up -d redis${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Redis 连接正常${NC}"

# 启动 Worker
echo -e "${YELLOW}启动 Celery Worker...${NC}"

exec celery -A config.celery_config worker \
    --queues=orchestrator,recon,vuln,exploit,report \
    --concurrency=4 \
    --loglevel=info
