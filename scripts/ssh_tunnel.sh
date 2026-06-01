#!/bin/bash
# ===========================================
# SSH Tunnel - Windows端 (Git Bash / WSL)
# 建立到 Kali VM 的 SSH 隧道，转发 HexStrike MCP 端口
# ===========================================

VM_HOST="${VM_HOST:-}"
VM_PORT="${VM_PORT:-22}"
VM_USER="${VM_USER:-root}"
VM_PASSWORD="${VM_PASSWORD:-}"
LOCAL_PORT="${LOCAL_PORT:-9999}"
REMOTE_PORT="${REMOTE_PORT:-9999}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  SSH Tunnel to Kali VM${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check SSH
if ! command -v ssh &> /dev/null; then
    echo -e "${RED}[ERROR] SSH client not found!${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] SSH client found${NC}"

# Check if port is already in use
if netstat -ano 2>/dev/null | grep -q ":${LOCAL_PORT} .*LISTENING"; then
    echo -e "${YELLOW}[WARN] Port ${LOCAL_PORT} is already in use${NC}"
    read -p "Kill existing? (y/n): " choice
    if [ "$choice" = "y" ]; then
        pid=$(netstat -ano | grep ":${LOCAL_PORT}.*LISTENING" | awk '{print $NF}')
        taskkill //F //PID "$pid" 2>/dev/null
        sleep 1
        echo -e "${GREEN}[OK] Killed existing process${NC}"
    else
        echo -e "${CYAN}[INFO] Testing existing connection...${NC}"
        curl -s "http://localhost:${LOCAL_PORT}/health" && echo ""
        exit 0
    fi
fi

# Test VM connectivity
echo -e "${CYAN}[INFO] Testing VM...${NC}"
ping -n 2 "${VM_HOST}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARN] Cannot ping ${VM_HOST}${NC}"
else
    echo -e "${GREEN}[OK] VM is reachable${NC}"
fi

# Check for sshpass
if command -v sshpass &> /dev/null; then
    echo -e "${CYAN}[INFO] Using sshpass for password auth${NC}"
    SSH_CMD="sshpass -p '${VM_PASSWORD}' ssh -o StrictHostKeyChecking=no -N -L ${LOCAL_PORT}:localhost:${REMOTE_PORT} ${VM_USER}@${VM_HOST} -p ${VM_PORT}"
else
    echo -e "${YELLOW}[WARN] sshpass not found, using key-based auth${NC}"
    echo -e "${YELLOW}       Install sshpass or run: ssh-copy-id ${VM_USER}@${VM_HOST}${NC}"
    echo ""
    SSH_CMD="ssh -o StrictHostKeyChecking=no -N -L ${LOCAL_PORT}:localhost:${REMOTE_PORT} ${VM_USER}@${VM_HOST} -p ${VM_PORT}"
fi

echo ""
echo -e "  Local:  ${GREEN}localhost:${LOCAL_PORT}${NC}"
echo -e "  Remote: ${GREEN}${VM_HOST}:${REMOTE_PORT}${NC}"
echo ""

# Start tunnel in background
echo -e "${CYAN}[INFO] Starting tunnel...${NC}"
eval "${SSH_CMD}" &
TUNNEL_PID=$!
echo -e "${GREEN}[OK] Tunnel started (PID: ${TUNNEL_PID})${NC}"

# Save PID
echo "${TUNNEL_PID}" > "$(dirname "$0")/.tunnel_pid"

# Wait for tunnel
sleep 3

# Test MCP
echo -e "${CYAN}[INFO] Testing MCP connection...${NC}"
HEALTH=$(curl -s "http://localhost:${LOCAL_PORT}/health" 2>/dev/null)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[OK] MCP is reachable!${NC}"
    echo "  Response: ${HEALTH}"
else
    echo -e "${YELLOW}[WARN] Cannot reach MCP${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check VM firewall: ssh ${VM_USER}@${VM_HOST} 'ufw allow 9999'"
    echo "  2. Check MCP is running on VM"
    echo "  3. Try direct connect: curl http://${VM_HOST}:9999/health"
fi

echo ""
echo -e "${CYAN}To stop tunnel: kill ${TUNNEL_PID}${NC}"

# Keep running
wait "${TUNNEL_PID}"
