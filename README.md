# Hati — 智能渗透测试系统

基于 **HexStrike MCP** + **MiniMax LLM** + **RAG POC 知识库** 的多智能体渗透测试平台。
支持 Web UI 实时交互，47 个攻击技能自动匹配，RAG 知识库闭环 POC 验证。

> **Language**: [English](README_EN.md) | **中文**

---

## 关于名字

**Hati** 源自北欧神话中追逐月亮的魔狼。每逢月夜，它便跨越天空追猎明月，直到诸神黄昏降临将其吞噬。

渗透测试亦是如此 — 耐心追踪目标的每一寸攻击面，不放过任何隐藏的弱点，直至发现突破口。

```
         /\___/\
        (  o o  )     🐺 Hati — 追月的狼
        /   V   \
        \  ---  /     追猎漏洞，永不停歇
         \_____/
```

---

## 核心组件来源

| 组件 | 说明 | 来源 |
|------|------|------|
| **HexStrike MCP** | 54+ 安全工具调用服务，部署在 Kali VM 中隔离运行 | [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) |
| **Hack Skills** | 47 个攻击技能模板 (SKILL.md) | [yaklang/hack-skills](https://github.com/yaklang/hack-skills) |
| **wpoc (POC)** | 799+ 产品漏洞 POC 知识库 | 集成自公开 POC 仓库 |

> **安全隔离说明**: HexStrike MCP Server 部署在独立的 Kali Linux 虚拟机中运行，与宿主机通过网络隔离。所有渗透测试工具（nmap、nuclei、sqlmap、hydra 等）的实际执行均在 VM 沙箱内完成，宿主机仅负责 LLM 推理和任务调度。这种架构确保了即使工具执行出现意外，也不会影响宿主机安全。

---

## 目录

- [系统架构](#系统架构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [配置详解](#配置详解)
- [Kali VM 端配置](#kali-vm-端配置)
- [RAG 知识库](#rag-知识库)
- [使用指南](#使用指南)
- [目录结构](#目录结构)
- [故障排除](#故障排除)
- [开发指南](#开发指南)

---

## 系统架构

```
┌──────────────────────────────────────────────────────────────────┐
│                    Windows / Linux 主机                            │
│                                                                  │
│  ┌─────────────────────┐    ┌──────────────────────────────┐    │
│  │  static/index.html   │    │   FastAPI (api/main.py)      │    │
│  │  Web UI (SPA)        │◄──►│   REST API + WebSocket      │    │
│  │  流式输出 / 进度显示   │    │   端口: 8000                 │    │
│  └─────────────────────┘    └──────────┬───────────────────┘    │
│                                        │                         │
│                  ┌─────────────────────┤                         │
│                  │                     │                         │
│          ┌───────▼───────┐   ┌────────▼──────────────┐         │
│          │  Redis :6379   │   │  ThreadPoolExecutor    │         │
│          │  进度追踪 (DB2) │   │  (Windows 无 Celery)   │         │
│          └───────────────┘   └────────┬──────────────┘         │
│                                       │                         │
│                                       ▼                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              run_single_phase_standalone()                  │  │
│  │              ReAct 决策循环 (8 轮迭代)                       │  │
│  │                                                            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐            │  │
│  │  │ LLM 决策  │  │ Skill 匹配│  │ RAG POC 查询  │            │  │
│  │  │ (MiniMax) │  │ (47技能) │  │ (799+ 产品)   │            │  │
│  │  └──────────┘  └──────────┘  └──────────────┘            │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │ HTTP / SSH Tunnel                 │
│                             ▼                                   │
│                  ┌──────────────────────┐                       │
│                  │  SSH Tunnel (可选)    │                       │
│                  │  localhost:9999 → VM  │                       │
│                  └──────────────────────┘                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Kali VM (运行 HexStrike MCP)                   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           HexStrike MCP Server v6.0.0                    │    │
│  │           端口: 9999 (HTTP API)                           │    │
│  │           54+ 安全工具 (nmap/nuclei/sqlmap/ffuf/...)     │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### 核心数据流

```
用户输入 (自然语言)
  → ChatAgent 解析意图
  → run_single_phase_standalone() 启动 ReAct 循环
  → LLM 决策下一步行动 (execute_tool / execute_skill / query_rag / generate_poc)
  → execute_tool:  通过 HexStrike MCP 调用 nmap/nuclei/sqlmap 等工具
  → execute_skill: 匹配 47 个攻击技能 → 提取 HTTP POC 请求 → 直接发包验证
  → query_rag:     查询 RAG POC 知识库 → 自动链入 POC 验证流程
  → generate_poc:  基于 RAG 结果 + LLM 适配 → 发包 → 多模式漏洞确认
  → 每轮结果注入下一轮 LLM 决策 → 最多 8 轮
  → 生成 Markdown + JSON 报告 → 写入 reports/ 目录
  → WebSocket 实时推送进度到 Web UI
```

---

## 环境要求

| 组件 | 用途 | 必须 |
|------|------|------|
| **Python 3.10+** | 运行 API + Agent | 是 |
| **Docker Desktop** | 运行 Redis (Windows) | 是 |
| **Kali Linux VM** | HexStrike MCP 工具执行环境 | 是 |
| **MiniMax API Key** | LLM 推理 | 是 |
| **Git Bash / WSL** | SSH 隧道脚本 (可选) | 建议 |

### 网络要求

- 主机 ↔ Kali VM: 网络连通 (同一网段或 NAT)
- Kali VM 需开放端口 22 (SSH) 和 9999 (MCP)
- 主机需能访问 `api.minimax.chat:443` (LLM API)

---

## 快速开始

### 第一步：克隆项目

```bash
git clone <repo-url>
cd Hati
```

### 第二步：配置环境变量

```bash
# 复制配置模板
cp .env.example .env

# 编辑 .env，至少填入:
#   MINIMAX_API_KEY=sk-xxx...          (MiniMax API Key)
#   MINIMAX_GROUP_ID=xxxxxxxxx          (MiniMax Group ID)
#   HEXSTRIKE_SERVER_URL=http://<你的Kali VM IP>:9999
```

### 第三步：安装 Python 依赖

```bash
pip install -r requirements-agent.txt
```

> **注意**: Windows 上 `celery` 无法使用 (需要 Unix socket)，系统已自动降级为 ThreadPoolExecutor 方案。

### 第四步：启动 Redis

```bash
cd docker
docker-compose up -d redis

# 验证
docker ps | grep redis
redis-cli ping   # 返回 PONG
```

### 第五步：(首次) 构建 RAG 知识库

```bash
python scripts/build_rag.py
```

这将扫描 `poc/wpoc/` 目录下的 799+ 产品 POC 文件，构建向量索引存入 `data/poc_knowledge_base/`。首次构建约需 3-5 分钟。

### 第六步：配置 Kali VM 并启动 MCP 服务

参见 [Kali VM 端配置](#kali-vm-端配置)，在 Kali VM 上启动 HexStrike MCP Server。

测试连通性：

```bash
python scripts/connect_test.py

# 如果连接失败，建立 SSH 隧道:
bash scripts/ssh_tunnel.sh
# 或 (PowerShell):
powershell -File scripts/ssh_tunnel.ps1 -VmHost "<Kali VM IP>" -VmPassword "<密码>"
```

### 第七步：启动 API 服务

```bash
# Windows / Linux:
python -m api.main

# 或指定端口:
API_PORT=8765 python -m api.main
```

启动后访问:
- **Web UI**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs`
- **健康检查**: `http://localhost:8000/health`

### 第八步：开始渗透测试

在 Web UI 输入框中输入自然语言指令，例如:

```
对 http://testphp.vulnweb.com 进行渗透测试
检测 http://example.com 的 SQL 注入漏洞
```

或通过 API:

```bash
curl -X POST http://localhost:8000/api/pentest/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://testphp.vulnweb.com",
    "authorized_by": "security@company.com"
  }'
```

---

## 配置详解

### 必填配置

| 环境变量 | 说明 | 示例值 |
|----------|------|--------|
| `MINIMAX_API_KEY` | MiniMax API Key | `sk-cp-xxxx...` |
| `MINIMAX_GROUP_ID` | MiniMax Group ID | `xxxxxxxxx` |
| `HEXSTRIKE_SERVER_URL` | HexStrike MCP 地址 | `http://<Kali VM IP>:9999` |
| `REDIS_HOST` | Redis 地址 | `localhost` |

### LLM 配置

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `MINIMAX_API_KEY` | API Key (MiniMax 控制台获取) | — |
| `MINIMAX_GROUP_ID` | Group ID | — |
| `MINIMAX_MODEL` | 模型名称 | `MiniMax-M2.7` |

> MiniMax API 端点固定为 `https://api.minimax.chat/v1`，使用 OpenAI SDK 兼容格式。
> 注册地址: https://www.minimax.chat

### Redis 配置

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `REDIS_HOST` | Redis 主机地址 | `localhost` |
| `REDIS_PORT` | Redis 端口 | `6379` |
| `REDIS_DB` | 通用数据 DB | `0` |
| `REDIS_DB_PROGRESS` | 任务进度追踪 DB | `2` |

### HexStrike MCP 连接

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `HEXSTRIKE_SERVER_URL` | MCP 服务完整 URL | — |
| `SSH_TUNNEL_HOST` | Kali VM IP | — |
| `SSH_TUNNEL_PORT` | SSH 端口 | `22` |
| `SSH_TUNNEL_USER` | SSH 用户名 | `root` |
| `SSH_TUNNEL_PASSWORD` | SSH 密码 | — |
| `SSH_TUNNEL_LOCAL_PORT` | 本地转发端口 | `9999` |
| `SSH_TUNNEL_REMOTE_PORT` | 远程 MCP 端口 | `9999` |

> 如果使用 SSH 隧道，需将 `HEXSTRIKE_SERVER_URL` 改为 `http://localhost:9999`。

### RAG 知识库

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `CVE_KB_PATH` | CVE 库路径 | `./data/cve_knowledge_base` |
| `POC_KB_PATH` | POC 向量库路径 | `./data/poc_knowledge_base` |
| `POC_REPO_PATH` | POC 原始文件路径 | `./poc/wpoc` |
| `CHROMA_DB_PATH` | ChromaDB 持久化路径 | `./data/poc_knowledge_base` |
| `EMBEDDING_MODEL` | 文本嵌入模型 | `all-MiniLM-L6-v2` |

### API 服务

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `API_HOST` | 监听地址 | `0.0.0.0` |
| `API_PORT` | 监听端口 | `8000` |
| `JWT_SECRET_KEY` | JWT 签名密钥 | (请修改) |

### 安全配置

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `APPROVAL_REQUIRED` | 是否启用高危操作审批 | `true` |
| `AUDIT_LOGGING_ENABLED` | 是否启用审计日志 | `true` |

### 可选组件

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `ELASTICSEARCH_HOST` | ES 地址 (审计日志) | `localhost` |
| `ELASTICSEARCH_PORT` | ES 端口 | `9200` |
| `DOCKER_HOST` | Docker 守护进程 | `unix:///var/run/docker.sock` |

> Elasticsearch 是可选组件。如果未安装 ES Python 包或 ES 服务未运行，系统自动降级为本地 JSON 文件日志。

---

## Kali VM 端配置

HexStrike MCP Server 需要在 Kali Linux VM 中运行。以下是 VM 端的操作步骤。

### 1. 确认 VM 网络可达

```bash
# 主机端测试
ping <Kali VM IP>

# 或直接测试 MCP 端口
curl http://<Kali VM IP>:9999/health
```

### 2. Kali VM 端口配置

```bash
# SSH 到 VM
ssh root@<Kali VM IP>

# 检查防火墙
ufw status

# 开放 MCP 端口 (如使用防火墙)
ufw allow 9999/tcp
ufw allow 22/tcp
```

### 3. 启动 HexStrike MCP Server

```bash
# SSH 到 VM
ssh root@<Kali VM IP>

# 进入 HexStrike 目录
cd hexstrike-ai
pip install -r requirements.txt

# 启动 MCP Server (端口 9999)
python3 hexstrike_server.py --port 9999

# 或者使用 systemd 服务 (推荐长期运行)
```

### 4. 验证 MCP 可用

```bash
# VM 本地验证
curl http://localhost:9999/health

# 期望返回:
# {"version": "6.0.0", "total_tools_available": 54, "status": "healthy"}
```

### 5. (可选) 建立 SSH 隧道

如果 VM 的 9999 端口不直接暴露或需要加密传输:

**Windows 端 (Git Bash)**:
```bash
bash scripts/ssh_tunnel.sh
```

**Windows 端 (PowerShell)**:
```powershell
.\scripts\ssh_tunnel.ps1 -VmHost "<Kali VM IP>" -VmPassword "<密码>"
```

建立隧道后，修改 `.env`:
```bash
HEXSTRIKE_SERVER_URL=http://localhost:9999
```

### 6. 使用 connect_test.py 诊断

```bash
python scripts/connect_test.py
```

该脚本会测试:
1. TCP 端口连通性
2. MCP 健康端点
3. 命令执行功能

---

## RAG 知识库

### 数据来源

- **POC 仓库**: 799+ 产品漏洞 POC
- **位置**: `poc/wpoc/`
- **向量模型**: `all-MiniLM-L6-v2` (Sentence Transformers)

### 构建/重建

```bash
# 初次构建
python scripts/build_rag.py

# 如果 POC 仓库已更新，重新构建:
rm -rf data/poc_knowledge_base
python scripts/build_rag.py
```

### 验证

```bash
python -c "
from rag.query_interface import get_rag_interface
r = get_rag_interface()
print(f'条目数: {r.get_stats()[\"total_count\"]}')
result = r.query('Apache SQL injection', n_results=3)
for v in result.vulnerabilities:
    print(f'  [{v.severity}] {v.name} (相似度: {v.similarity:.2f})')
"
```

### 工作原理

```
渗透测试中 → 技能匹配 (match_skills)
         → RAG 查询 (基于目标技术栈/关键词)
         → LLM 将 RAG 中的真实 POC 适配到具体目标
         → 直接发包验证
         → 多模式确认漏洞 (SQL错误回显/XSS回显/LFI特征等)
```

---

## 使用指南

### Web UI

访问 `http://localhost:8000`，在输入框输入渗透测试需求:

```
对 http://example.com 进行渗透测试
扫描 http://testphp.vulnweb.com 的漏洞
对 https://target.com 做 SQL 注入测试
```

界面实时显示:
- 初始化 → 信息收集 → 技能匹配 → 漏洞扫描 → POC 验证 → 报告生成
- 工具调用的实时输出
- 技能执行的 POC 结果
- RAG 匹配的漏洞确认状态
- 最终生成报告链接

### REST API

```bash
# 启动渗透测试
curl -X POST http://localhost:8000/api/pentest/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://example.com",
    "authorized_by": "security@company.com"
  }'

# 查询任务状态 (task_id 从启动响应中获取)
curl http://localhost:8000/api/pentest/status/{task_id}

# 获取报告
curl http://localhost:8000/api/pentest/report/{task_id}

# 健康检查
curl http://localhost:8000/health
```

### WebSocket (实时流式)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/client_xxx');
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg.type: "progress" | "result" | "ai_token" | "complete"
  console.log(msg);
};
```

### 报告输出

任务完成后，报告保存在 `reports/` 目录:

```
reports/
├── 20260601_085556_target_xxxxxxxx.md    # Markdown 报告
└── 20260601_085556_target_xxxxxxxx.json  # JSON 详情
```

文件名格式: `{日期}_{时间}_{目标}_{任务ID}.{md|json}`

---

## 目录结构

```
Hati/
├── api/
│   ├── main.py                 # FastAPI 入口 (REST + WebSocket)
│   └── websocket.py            # WebSocket 管理器
├── agents/
│   ├── chat_agent.py           # 交互式聊天 Agent (任务调度)
│   ├── orchestrator.py         # 主控 Agent (ReAct 决策循环)
│   ├── recon_agent.py          # 信息收集 (MCP 客户端)
│   ├── vuln_agent.py           # 漏洞扫描
│   ├── exploit_agent.py        # 漏洞利用
│   ├── report_agent.py         # 报告生成
│   ├── skill_loader.py         # 攻击技能加载 + 匹配
│   ├── poc_generator.py        # POC 生成器
│   ├── sub_agents.py           # 子 Agent 管理
│   ├── intent_parser.py        # 用户意图解析
│   └── skill_scheduler.py      # 技能调度
├── config/
│   ├── settings.py             # 全局配置 (pydantic-settings)
│   ├── minimax_config.py       # MiniMax LLM 配置 + System Prompts
│   ├── celery_config.py        # Celery 配置 (Linux)
│   ├── model_router.py         # LLM 模型路由
│   └── prompts_layered.py      # 分层提示词模板
├── state/
│   ├── pentest_state.py        # 渗透测试状态机
│   ├── progress_tracker.py     # Redis 进度追踪器
│   ├── context_compressor.py   # 上下文压缩
│   └── diversity_injector.py   # 多样性注入
├── rag/
│   ├── query_interface.py      # RAG 统一查询接口
│   ├── vector_store.py         # ChromaDB/SimpleVectorStore
│   └── poc_loader.py           # POC 加载器
├── skills/
│   └── hack-skills/skills/     # 47 个攻击技能 (SKILL.md)
├── tools/
│   ├── langchain_adapter.py    # HexStrike MCP 客户端适配
│   └── composite_tools.py      # 复合工具
├── security/
│   ├── audit_logger.py         # ES 审计日志
│   └── container_runner.py     # Docker 容器隔离
├── scripts/
│   ├── build_rag.py            # 构建 RAG 向量数据库
│   ├── connect_test.py         # MCP 连接测试
│   ├── ssh_tunnel.sh           # SSH 隧道 (Bash/WSL)
│   ├── ssh_tunnel.ps1          # SSH 隧道 (PowerShell)
│   ├── setup_elasticsearch.py  # ES 索引初始化
│   └── load_poc_kb.py          # POC 知识库加载
├── static/
│   └── index.html              # Web UI (SPA)
├── docker/
│   ├── docker-compose.yml      # Redis + ES + Kibana
│   └── Dockerfile.toolkit       # Kali 工具容器
├── hexstrike/                   # HexStrike MCP Server
├── poc/wpoc/                    # POC 原始文件 (799+ 产品)
├── data/                        # 向量数据库 / 缓存 (运行时生成)
├── reports/                     # 生成的渗透测试报告 (运行时生成)
├── .env.example                 # 环境变量模板
├── requirements-agent.txt       # Python 依赖
├── start.sh                     # Linux 启动脚本
├── start_celery.sh              # Celery Worker 启动
├── start_worker.sh              # Worker 启动 (Linux)
└── README.md                    # 本文件
```

---

## 故障排除

### Redis 未运行

```bash
# 症状: "Error 10061 connecting to localhost:6379"
# 解决:
cd docker
docker-compose up -d redis
docker ps | grep redis          # 确认容器在运行
redis-cli ping                  # 应返回 PONG
```

### MCP 连接超时

```bash
# 症状: "Read timed out" 或 "Connection refused"
# 检查:
# 1. VM 是否在运行
ping <Kali VM IP>

# 2. MCP 端口是否开放
curl http://<Kali VM IP>:9999/health

# 3. VM 上的 MCP 是否启动
ssh root@<Kali VM IP>
curl http://localhost:9999/health

# 4. 建立 SSH 隧道作为备选
bash scripts/ssh_tunnel.sh
# 然后修改 .env: HEXSTRIKE_SERVER_URL=http://localhost:9999
```

### MiniMax API 调用失败

```bash
# 症状: "MINIMAX_API_KEY 环境变量未设置" 或 HTTP 401/403
# 检查:
echo $MINIMAX_API_KEY

# 确认 .env 文件在项目根目录下且格式正确
# API Key 应以 sk-cp- 开头

# 测试 API 连通性:
curl -X POST "https://api.minimax.chat/v1/chat/completions" \
  -H "Authorization: Bearer $MINIMAX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MiniMax-M2.7","messages":[{"role":"user","content":"hi"}]}'
```

### RAG 知识库为空

```bash
# 症状: "[RAG] POC 知识库已加载: 0 条"
# 解决:
python scripts/build_rag.py
# 如果构建失败，检查:
# 1. poc/wpoc/ 目录是否有 POC 文件
# 2. pip install chromadb sentence-transformers
```

### 端口被占用

```bash
# 症状: "Address already in use" 或端口冲突
# 查看端口占用:
netstat -ano | grep 8000
# 更换端口:
API_PORT=8766 python -m api.main
```

### Windows 编码问题

```bash
# 症状: UnicodeEncodeError 或终端乱码
# 系统已内置 UTF-8 编码修复
# 如仍有问题，在 PowerShell 中:
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
```

---

## 开发指南

### 添加新的攻击技能

在 `skills/hack-skills/skills/` 下创建目录:

```
skills/hack-skills/skills/my-new-skill/
└── SKILL.md   # 包含完整的攻击 payload、HTTP 请求示例、成功标准
```

`match_skills()` 会自动发现并匹配新技能。

### 添加新的 MCP 工具

1. 确保 HexStrike MCP Server 支持该工具
2. 工具直接通过 `client.execute_command(command, category=...)` 调用
3. LLM 通过 ReAct 循环自动发现并使用新工具

### 修改 ReAct 循环

关键函数位于 `agents/orchestrator.py`:
- `run_single_phase_standalone()` — ReAct 主循环
- `_llm_decide_next_action()` — LLM 决策引擎
- `_execute_react_action()` — 行动分发 (execute_tool / execute_skill / query_rag / generate_poc)
- `_llm_adapt_skill_to_target()` — 技能内容 → HTTP POC 请求
- `_llm_adapt_and_test_poc()` — RAG POC → LLM 适配 → 发包验证

### 代码规范

- Python 文件行数: 建议 200-400 行，上限 800 行
- 编码: UTF-8
- 字符串: 中文注释允许，代码使用英文
- LLM 调用: 通过 `get_llm()` 获取全局单例

---

## 贡献

欢迎提交 Issue 和 Pull Request。

## 免责声明

本工具仅供合法的安全测试和学术研究使用。使用前请确保已获得目标系统所有者的书面授权。使用者需遵守当地法律法规，作者不承担任何因滥用本工具而导致的法律责任。

## License

MIT License
