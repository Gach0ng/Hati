# Hati — Intelligent Penetration Testing System

A multi-agent penetration testing platform based on **HexStrike MCP** + **MiniMax LLM** + **RAG POC Knowledge Base**.
Features real-time Web UI interaction, 47 auto-matched attack skills, and closed-loop POC verification via RAG.

> **Language**: [中文](README.md) | **English**

---

## About the Name

**Hati** is a wolf from Norse mythology who chases the moon across the night sky. He pursues his prey relentlessly, and at Ragnarök he will finally catch and devour it.

Penetration testing embodies the same spirit — methodically stalking every inch of the attack surface, never overlooking a hidden weakness, until the breach is found.

```
         /\___/\
        (  o o  )     🐺 Hati — The Moon-Chasing Wolf
        /   V   \
        \  ---  /     Hunt vulnerabilities, never stop
         \_____/
```

---

## Core Components

| Component | Description | Source |
|-----------|-------------|--------|
| **HexStrike MCP** | 54+ security tool execution service, deployed in isolated Kali VM | [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) |
| **Hack Skills** | 47 attack skill templates (SKILL.md) | [yaklang/hack-skills](https://github.com/yaklang/hack-skills) |
| **wpoc (POC)** | 799+ product vulnerability POC knowledge base | Integrated from public POC repos |

> **Isolation Note**: The HexStrike MCP Server runs inside a dedicated Kali Linux VM, network-isolated from the host. All penetration testing tools (nmap, nuclei, sqlmap, hydra, etc.) execute within the VM sandbox. The host machine only handles LLM inference and task orchestration. This architecture ensures host safety even if tool execution goes wrong.

---

## Table of Contents

- [System Architecture](#system-architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration Details](#configuration-details)
- [Kali VM Setup](#kali-vm-setup)
- [RAG Knowledge Base](#rag-knowledge-base)
- [Usage Guide](#usage-guide)
- [Directory Structure](#directory-structure)
- [Troubleshooting](#troubleshooting)
- [Development Guide](#development-guide)

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Windows / Linux Host                            │
│                                                                  │
│  ┌─────────────────────┐    ┌──────────────────────────────┐    │
│  │  static/index.html   │    │   FastAPI (api/main.py)      │    │
│  │  Web UI (SPA)        │◄──►│   REST API + WebSocket      │    │
│  │  Streaming output     │    │   Port: 8000                 │    │
│  └─────────────────────┘    └──────────┬───────────────────┘    │
│                                        │                         │
│                  ┌─────────────────────┤                         │
│                  │                     │                         │
│          ┌───────▼───────┐   ┌────────▼──────────────┐         │
│          │  Redis :6379   │   │  ThreadPoolExecutor    │         │
│          │  Progress (DB2) │   │  (Windows, no Celery)  │         │
│          └───────────────┘   └────────┬──────────────┘         │
│                                       │                         │
│                                       ▼                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │           run_single_phase_standalone()                     │  │
│  │           ReAct Decision Loop (8 iterations)                │  │
│  │                                                            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐            │  │
│  │  │ LLM       │  │ Skill    │  │ RAG POC      │            │  │
│  │  │ Decision  │  │ Matching │  │ Query        │            │  │
│  │  │ (MiniMax) │  │ (47)     │  │ (799+ prod.) │            │  │
│  │  └──────────┘  └──────────┘  └──────────────┘            │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │ HTTP / SSH Tunnel                 │
│                             ▼                                   │
│                  ┌──────────────────────┐                       │
│                  │  SSH Tunnel (opt.)   │                       │
│                  │  localhost:9999 → VM │                       │
│                  └──────────────────────┘                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                 Kali VM (Running HexStrike MCP)                   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           HexStrike MCP Server v6.0.0                    │    │
│  │           Port: 9999 (HTTP API)                           │    │
│  │           54+ Security Tools (nmap/nuclei/sqlmap/...)    │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### Core Data Flow

```
User Input (natural language)
  → ChatAgent parses intent
  → run_single_phase_standalone() starts ReAct loop
  → LLM decides next action (execute_tool / execute_skill / query_rag / generate_poc)
  → execute_tool:  Invoke nmap/nuclei/sqlmap via HexStrike MCP
  → execute_skill: Match 47 attack skills → extract HTTP POC → send requests
  → query_rag:     Query RAG POC knowledge base → chain into POC verification
  → generate_poc:  Based on RAG results + LLM adaptation → send → multi-mode confirmation
  → Each round feeds into next LLM decision → max 8 rounds
  → Generate Markdown + JSON reports → write to reports/ directory
  → WebSocket pushes real-time progress to Web UI
```

---

## Requirements

| Component | Purpose | Required |
|-----------|---------|----------|
| **Python 3.10+** | Run API + Agent | Yes |
| **Docker Desktop** | Run Redis (Windows) | Yes |
| **Kali Linux VM** | HexStrike MCP tool execution environment | Yes |
| **MiniMax API Key** | LLM inference | Yes |
| **Git Bash / WSL** | SSH tunnel scripts (optional) | Recommended |

### Network Requirements

- Host ↔ Kali VM: network connectivity (same subnet or NAT)
- Kali VM must expose port 22 (SSH) and 9999 (MCP)
- Host must be able to reach `api.minimax.chat:443` (LLM API)

---

## Quick Start

### Step 1: Clone the project

```bash
git clone <repo-url>
cd Hati
```

### Step 2: Configure environment variables

```bash
# Copy the configuration template
cp .env.example .env

# Edit .env, fill in at minimum:
#   MINIMAX_API_KEY=sk-xxx...              (MiniMax API Key)
#   MINIMAX_GROUP_ID=xxxxxxxxx              (MiniMax Group ID)
#   HEXSTRIKE_SERVER_URL=http://<Kali VM IP>:9999
```

### Step 3: Install Python dependencies

```bash
pip install -r requirements-agent.txt
```

> **Note**: `celery` is unavailable on Windows (requires Unix sockets). The system automatically falls back to ThreadPoolExecutor.

### Step 4: Start Redis

```bash
cd docker
docker-compose up -d redis

# Verify
docker ps | grep redis
redis-cli ping   # should return PONG
```

### Step 5: (First time) Build RAG knowledge base

```bash
python scripts/build_rag.py
```

This scans POC files for 799+ products under `poc/wpoc/` and builds vector indices into `data/poc_knowledge_base/`. First build takes ~3-5 minutes.

### Step 6: Configure Kali VM and start MCP service

See [Kali VM Setup](#kali-vm-setup) for detailed instructions on starting the HexStrike MCP Server.

Test connectivity:

```bash
python scripts/connect_test.py

# If connection fails, establish SSH tunnel:
bash scripts/ssh_tunnel.sh
# or (PowerShell):
powershell -File scripts/ssh_tunnel.ps1 -VmHost "<Kali VM IP>" -VmPassword "<password>"
```

### Step 7: Start API server

```bash
# Windows / Linux:
python -m api.main

# Or specify a custom port:
API_PORT=8765 python -m api.main
```

After starting, visit:
- **Web UI**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/health`

### Step 8: Start penetration testing

Enter natural language commands in the Web UI, for example:

```
Penetration test http://testphp.vulnweb.com
Check http://example.com for SQL injection vulnerabilities
```

Or via API:

```bash
curl -X POST http://localhost:8000/api/pentest/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://testphp.vulnweb.com",
    "authorized_by": "security@company.com"
  }'
```

---

## Configuration Details

### Required Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `MINIMAX_API_KEY` | MiniMax API Key | `sk-cp-xxxx...` |
| `MINIMAX_GROUP_ID` | MiniMax Group ID | `xxxxxxxxx` |
| `HEXSTRIKE_SERVER_URL` | HexStrike MCP address | `http://<Kali VM IP>:9999` |
| `REDIS_HOST` | Redis address | `localhost` |

### LLM Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MINIMAX_API_KEY` | API Key (from MiniMax console) | — |
| `MINIMAX_GROUP_ID` | Group ID | — |
| `MINIMAX_MODEL` | Model name | `MiniMax-M2.7` |

> MiniMax API endpoint is fixed at `https://api.minimax.chat/v1`, using OpenAI SDK-compatible format.
> Register at: https://www.minimax.chat

### Redis Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_HOST` | Redis host address | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_DB` | General data DB | `0` |
| `REDIS_DB_PROGRESS` | Task progress DB | `2` |

### HexStrike MCP Connection

| Variable | Description | Default |
|----------|-------------|---------|
| `HEXSTRIKE_SERVER_URL` | Full MCP service URL | — |
| `SSH_TUNNEL_HOST` | Kali VM IP | — |
| `SSH_TUNNEL_PORT` | SSH port | `22` |
| `SSH_TUNNEL_USER` | SSH username | `root` |
| `SSH_TUNNEL_PASSWORD` | SSH password | — |
| `SSH_TUNNEL_LOCAL_PORT` | Local forwarding port | `9999` |
| `SSH_TUNNEL_REMOTE_PORT` | Remote MCP port | `9999` |

> If using SSH tunnel, set `HEXSTRIKE_SERVER_URL` to `http://localhost:9999`.

### RAG Knowledge Base

| Variable | Description | Default |
|----------|-------------|---------|
| `CVE_KB_PATH` | CVE library path | `./data/cve_knowledge_base` |
| `POC_KB_PATH` | POC vector library path | `./data/poc_knowledge_base` |
| `POC_REPO_PATH` | Raw POC file path | `./poc/wpoc` |
| `CHROMA_DB_PATH` | ChromaDB persistence path | `./data/poc_knowledge_base` |
| `EMBEDDING_MODEL` | Text embedding model | `all-MiniLM-L6-v2` |

### API Service

| Variable | Description | Default |
|----------|-------------|---------|
| `API_HOST` | Listen address | `0.0.0.0` |
| `API_PORT` | Listen port | `8000` |
| `JWT_SECRET_KEY` | JWT signing key | (change this) |

### Security Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `APPROVAL_REQUIRED` | Require approval for high-risk ops | `true` |
| `AUDIT_LOGGING_ENABLED` | Enable audit logging | `true` |

### Optional Components

| Variable | Description | Default |
|----------|-------------|---------|
| `ELASTICSEARCH_HOST` | ES address (audit logs) | `localhost` |
| `ELASTICSEARCH_PORT` | ES port | `9200` |
| `DOCKER_HOST` | Docker daemon | `unix:///var/run/docker.sock` |

> Elasticsearch is optional. If the ES Python package is not installed or the ES service is not running, the system automatically falls back to local JSON file logging.

---

## Kali VM Setup

The HexStrike MCP Server must run inside a Kali Linux VM. Follow these steps on the VM.

### 1. Verify VM network reachability

```bash
# Test from host
ping <Kali VM IP>

# Or directly test MCP port
curl http://<Kali VM IP>:9999/health
```

### 2. Kali VM port configuration

```bash
# SSH into VM
ssh root@<Kali VM IP>

# Check firewall
ufw status

# Open MCP port (if using firewall)
ufw allow 9999/tcp
ufw allow 22/tcp
```

### 3. Start HexStrike MCP Server

```bash
# SSH into VM
ssh root@<Kali VM IP>

# Enter HexStrike directory
cd hexstrike-ai
pip install -r requirements.txt

# Start MCP Server (port 9999)
python3 hexstrike_server.py --port 9999

# Or use systemd service (recommended for long-running)
```

### 4. Verify MCP is working

```bash
# Local verification on VM
curl http://localhost:9999/health

# Expected response:
# {"version": "6.0.0", "total_tools_available": 54, "status": "healthy"}
```

### 5. (Optional) Establish SSH tunnel

If VM port 9999 is not directly exposed or encrypted transport is needed:

**Windows (Git Bash)**:
```bash
bash scripts/ssh_tunnel.sh
```

**Windows (PowerShell)**:
```powershell
.\scripts\ssh_tunnel.ps1 -VmHost "<Kali VM IP>" -VmPassword "<password>"
```

After establishing the tunnel, update `.env`:
```bash
HEXSTRIKE_SERVER_URL=http://localhost:9999
```

### 6. Diagnose with connect_test.py

```bash
python scripts/connect_test.py
```

This script tests:
1. TCP port connectivity
2. MCP health endpoint
3. Command execution functionality

---

## RAG Knowledge Base

### Data Sources

- **POC Repository**: 799+ product vulnerability POCs
- **Location**: `poc/wpoc/`
- **Vector Model**: `all-MiniLM-L6-v2` (Sentence Transformers)

### Build / Rebuild

```bash
# Initial build
python scripts/build_rag.py

# If POC repository has been updated, rebuild:
rm -rf data/poc_knowledge_base
python scripts/build_rag.py
```

### Verification

```bash
python -c "
from rag.query_interface import get_rag_interface
r = get_rag_interface()
print(f'Entry count: {r.get_stats()[\"total_count\"]}')
result = r.query('Apache SQL injection', n_results=3)
for v in result.vulnerabilities:
    print(f'  [{v.severity}] {v.name} (similarity: {v.similarity:.2f})')
"
```

### How It Works

```
During pentest → Skill matching (match_skills)
              → RAG query (based on target tech stack/keywords)
              → LLM adapts real POC from RAG to specific target
              → Send HTTP requests directly
              → Multi-mode vulnerability confirmation (SQL error/XSS echo/LFI patterns)
```

---

## Usage Guide

### Web UI

Visit `http://localhost:8000` and enter penetration testing commands:

```
Penetration test http://example.com
Scan http://testphp.vulnweb.com for vulnerabilities
SQL injection test on https://target.com
```

Real-time display:
- Init → Recon → Skill Matching → Vulnerability Scan → POC Verification → Report Generation
- Real-time tool execution output
- Skill execution POC results
- RAG-matched vulnerability confirmation status
- Final report link

### REST API

```bash
# Start penetration test
curl -X POST http://localhost:8000/api/pentest/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://example.com",
    "authorized_by": "security@company.com"
  }'

# Query task status (task_id from start response)
curl http://localhost:8000/api/pentest/status/{task_id}

# Get report
curl http://localhost:8000/api/pentest/report/{task_id}

# Health check
curl http://localhost:8000/health
```

### WebSocket (Real-time Streaming)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/client_xxx');
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg.type: "progress" | "result" | "ai_token" | "complete"
  console.log(msg);
};
```

### Report Output

After task completion, reports are saved in the `reports/` directory:

```
reports/
├── 20260601_085556_target_xxxxxxxx.md    # Markdown report
└── 20260601_085556_target_xxxxxxxx.json  # JSON details
```

File naming: `{date}_{time}_{target}_{task_id}.{md|json}`

---

## Directory Structure

```
Hati/
├── api/
│   ├── main.py                 # FastAPI entry point (REST + WebSocket)
│   └── websocket.py            # WebSocket manager
├── agents/
│   ├── chat_agent.py           # Interactive chat agent (task dispatch)
│   ├── orchestrator.py         # Main orchestrator (ReAct decision loop)
│   ├── recon_agent.py          # Reconnaissance (MCP client)
│   ├── vuln_agent.py           # Vulnerability scanning
│   ├── exploit_agent.py        # Exploitation
│   ├── report_agent.py         # Report generation
│   ├── skill_loader.py         # Attack skill loading + matching
│   ├── poc_generator.py        # POC generator
│   ├── sub_agents.py           # Sub-agent management
│   ├── intent_parser.py        # User intent parsing
│   └── skill_scheduler.py      # Skill scheduling
├── config/
│   ├── settings.py             # Global config (pydantic-settings)
│   ├── minimax_config.py       # MiniMax LLM config + System Prompts
│   ├── celery_config.py        # Celery config (Linux)
│   ├── model_router.py         # LLM model routing
│   └── prompts_layered.py      # Layered prompt templates
├── state/
│   ├── pentest_state.py        # Pentest state machine
│   ├── progress_tracker.py     # Redis progress tracker
│   ├── context_compressor.py   # Context compression
│   └── diversity_injector.py   # Diversity injection
├── rag/
│   ├── query_interface.py      # RAG unified query interface
│   ├── vector_store.py         # ChromaDB/SimpleVectorStore
│   └── poc_loader.py           # POC loader
├── skills/
│   └── hack-skills/skills/     # 47 attack skills (SKILL.md)
├── tools/
│   ├── langchain_adapter.py    # HexStrike MCP client adapter
│   └── composite_tools.py      # Composite tools
├── security/
│   ├── audit_logger.py         # ES audit logger
│   └── container_runner.py     # Docker container isolation
├── scripts/
│   ├── build_rag.py            # Build RAG vector database
│   ├── connect_test.py         # MCP connection test
│   ├── ssh_tunnel.sh           # SSH tunnel (Bash/WSL)
│   ├── ssh_tunnel.ps1          # SSH tunnel (PowerShell)
│   ├── setup_elasticsearch.py  # ES index initialization
│   └── load_poc_kb.py          # POC knowledge base loader
├── static/
│   └── index.html              # Web UI (SPA)
├── docker/
│   ├── docker-compose.yml      # Redis + ES + Kibana
│   └── Dockerfile.toolkit       # Kali tools container
├── hexstrike/                   # HexStrike MCP Server
├── poc/wpoc/                    # Raw POC files (799+ products)
├── data/                        # Vector DB / cache (runtime generated)
├── reports/                     # Generated pentest reports (runtime generated)
├── .env.example                 # Environment variable template
├── requirements-agent.txt       # Python dependencies
├── start.sh                     # Linux startup script
├── start_celery.sh              # Celery Worker startup
├── start_worker.sh              # Worker startup (Linux)
└── README.md                    # This file
```

---

## Troubleshooting

### Redis not running

```bash
# Symptom: "Error 10061 connecting to localhost:6379"
# Fix:
cd docker
docker-compose up -d redis
docker ps | grep redis          # Confirm container is running
redis-cli ping                  # Should return PONG
```

### MCP connection timeout

```bash
# Symptom: "Read timed out" or "Connection refused"
# Check:
# 1. Is VM running?
ping <Kali VM IP>

# 2. Is MCP port open?
curl http://<Kali VM IP>:9999/health

# 3. Is MCP running on VM?
ssh root@<Kali VM IP>
curl http://localhost:9999/health

# 4. Fallback: establish SSH tunnel
bash scripts/ssh_tunnel.sh
# Then update .env: HEXSTRIKE_SERVER_URL=http://localhost:9999
```

### MiniMax API call failure

```bash
# Symptom: "MINIMAX_API_KEY not set" or HTTP 401/403
# Check:
echo $MINIMAX_API_KEY

# Ensure .env exists in project root with correct format
# API Key should start with sk-cp-

# Test API connectivity:
curl -X POST "https://api.minimax.chat/v1/chat/completions" \
  -H "Authorization: Bearer $MINIMAX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MiniMax-M2.7","messages":[{"role":"user","content":"hi"}]}'
```

### Empty RAG knowledge base

```bash
# Symptom: "[RAG] POC knowledge base loaded: 0 entries"
# Fix:
python scripts/build_rag.py
# If build fails, check:
# 1. poc/wpoc/ directory has POC files
# 2. pip install chromadb sentence-transformers
```

### Port conflict

```bash
# Symptom: "Address already in use" or port conflict
# Check port usage:
netstat -ano | grep 8000
# Use a different port:
API_PORT=8766 python -m api.main
```

### Windows encoding issues

```bash
# Symptom: UnicodeEncodeError or terminal garbled text
# The system has built-in UTF-8 encoding fixes
# If issues persist, in PowerShell:
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
```

---

## Development Guide

### Adding a new attack skill

Create a directory under `skills/hack-skills/skills/`:

```
skills/hack-skills/skills/my-new-skill/
└── SKILL.md   # Contains complete attack payload, HTTP request examples, success criteria
```

`match_skills()` will automatically discover and match new skills.

### Adding a new MCP tool

1. Ensure HexStrike MCP Server supports the tool
2. Tools are invoked via `client.execute_command(command, category=...)`
3. LLM auto-discovers and uses new tools through the ReAct loop

### Modifying the ReAct loop

Key functions in `agents/orchestrator.py`:
- `run_single_phase_standalone()` — Main ReAct loop
- `_llm_decide_next_action()` — LLM decision engine
- `_execute_react_action()` — Action dispatch (execute_tool / execute_skill / query_rag / generate_poc)
- `_llm_adapt_skill_to_target()` — Skill content → HTTP POC request
- `_llm_adapt_and_test_poc()` — RAG POC → LLM adaptation → request verification

### Code Conventions

- Python file length: recommended 200-400 lines, max 800 lines
- Encoding: UTF-8
- Comments: English or Chinese (code in English)
- LLM calls: use `get_llm()` for global singleton

---

## Contributing

Issues and Pull Requests are welcome.

## Disclaimer

This tool is intended for authorized security testing and academic research only. Ensure you have obtained written authorization from the target system owner before use. Users must comply with local laws and regulations. The author assumes no liability for any misuse of this tool.

## License

MIT License
