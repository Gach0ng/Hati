#!/bin/bash
# ===========================================
# Pentest Agent - 启动脚本
# ===========================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目根目录 (修改为你本地的实际路径)
PROJECT_ROOT="$(dirname "$0")"

echo -e "${BLUE}"
echo "=========================================="
echo "   Pentest Agent - 渗透测试 Agent 系统"
echo "=========================================="
echo -e "${NC}"

# ===========================================
# 检查环境
# ===========================================
echo -e "${YELLOW}[1/6] 检查环境...${NC}"

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 未安装${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python3: $(python3 --version)${NC}"

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker 未安装，部分功能可能不可用${NC}"
else
    echo -e "${GREEN}✅ Docker: $(docker --version)${NC}"
fi

# 检查 Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker Compose 未安装${NC}"
else
    echo -e "${GREEN}✅ Docker Compose 可用${NC}"
fi

# ===========================================
# 激活虚拟环境
# ===========================================
echo -e "${YELLOW}[2/6] 激活虚拟环境...${NC}"

if [ -d "$PROJECT_ROOT/venv" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
    echo -e "${GREEN}✅ 虚拟环境已激活${NC}"
else
    echo -e "${YELLOW}⚠️  未找到虚拟环境，使用系统 Python${NC}"
fi

# 复制 .env 文件
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    echo -e "${YELLOW}⚠️  已创建 .env 文件，请编辑并填入 API Key${NC}"
fi

# ===========================================
# 启动 Docker 服务
# ===========================================
echo -e "${YELLOW}[3/6] 启动 Docker 服务 (Redis + ES)...${NC}"

cd "$PROJECT_ROOT/docker"

# 检查 docker-compose
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    echo -e "${RED}❌ Docker Compose 不可用${NC}"
    exit 1
fi

# 启动服务
$DOCKER_COMPOSE up -d redis elasticsearch 2>/dev/null || true

# 等待服务就绪
echo -e "${YELLOW}等待服务启动...${NC}"
sleep 5

echo -e "${GREEN}✅ Docker 服务已启动${NC}"

# ===========================================
# 初始化 Elasticsearch
# ===========================================
echo -e "${YELLOW}[4/6] 初始化 Elasticsearch...${NC}"

echo -e "${YELLOW}⚠️  Elasticsearch 未配置，将使用本地文件日志${NC}"

# ===========================================
# 检查 HexStrike MCP Server
# ===========================================
echo -e "${YELLOW}[5/6] 检查 HexStrike MCP Server...${NC}"

# 检查 HexStrike 是否运行
if curl -s http://localhost:9999/health &> /dev/null; then
    echo -e "${GREEN}✅ HexStrike MCP Server 运行中 (localhost:9999)${NC}"
else
    echo -e "${YELLOW}⚠️  HexStrike MCP Server 未运行${NC}"
    echo -e "${YELLOW}   请在另一个终端运行:${NC}"
    echo -e "${YELLOW}   cd hexstrike && python3 hexstrike_server.py --port 9999${NC}"
fi

# ===========================================
# 启动 API 服务
# ===========================================
echo -e "${YELLOW}[6/6] 启动 API 服务...${NC}"

cd "$PROJECT_ROOT"

# 检查端口是否占用
if lsof -i:8000 &> /dev/null; then
    echo -e "${YELLOW}⚠️  端口 8000 已被占用${NC}"
    API_PORT=8001
else
    API_PORT=8000
fi

echo -e "${GREEN}✅ API 服务将在端口 $API_PORT 启动${NC}"
echo ""
echo -e "${BLUE}==========================================${NC}"
echo -e "${GREEN}启动完成！${NC}"
echo ""
echo -e "服务地址:"
echo -e "  • API:     http://localhost:$API_PORT"
echo -e "  • Docs:    http://localhost:$API_PORT/docs"
echo -e "  • Redoc:   http://localhost:$API_PORT/redoc"
echo -e "  • Redis:   localhost:6379"
echo -e "  • ES:      localhost:9200"
echo ""
echo -e "${BLUE}==========================================${NC}"
echo ""

# 启动服务
exec uvicorn api.main:app --host 0.0.0.0 --port $API_PORT --reload
