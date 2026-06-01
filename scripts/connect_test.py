#!/usr/bin/env python3
"""
Pentest Agent - MCP Connection Tester
测试与 Kali VM 中 HexStrike MCP 服务的网络连通性
"""

import os
import sys
import socket
import requests
from urllib.parse import urlparse


def test_tcp_connect(host: str, port: int, timeout: int = 3) -> bool:
    """测试 TCP 端口连通性"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"  TCP connect failed: {e}")
        return False


def test_mcp_health(url: str, timeout: int = 5) -> dict:
    """测试 MCP 服务健康状态"""
    try:
        resp = requests.get(f"{url}/health", timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def main():
    # 从环境读取配置
    mcp_url = os.getenv("HEXSTRIKE_SERVER_URL", "http://localhost:9999")
    vm_ip = os.getenv("SSH_TUNNEL_HOST", "")
    vm_user = os.getenv("SSH_TUNNEL_USER", "root")

    parsed = urlparse(mcp_url)
    host = parsed.hostname
    port = parsed.port or 9999

    print("=" * 50)
    print("  Pentest Agent - MCP Connection Test")
    print("=" * 50)
    print(f"\n  Target: {mcp_url}")
    print(f"  VM IP:  {vm_ip}")

    # Test 1: TCP connectivity
    print(f"\n[1] Testing TCP connectivity to {host}:{port}...")
    if test_tcp_connect(host, port):
        print(f"    [OK] Port {port} is open")
    else:
        print(f"    [FAIL] Cannot reach {host}:{port}")
        print(f"\n  Troubleshooting:")
        print(f"    1. Check VM firewall: ssh {vm_user}@{vm_ip} 'ufw status'")
        print(f"    2. Allow port 9999:  ssh {vm_user}@{vm_ip} 'ufw allow 9999'")
        print(f"    3. Check MCP is running: ssh {vm_user}@{vm_ip} 'systemctl status hexstrike'")
        print(f"    4. Try SSH tunnel: powershell -File scripts/ssh_tunnel.ps1")
        sys.exit(1)

    # Test 2: MCP health check
    print(f"\n[2] Testing MCP health endpoint...")
    health = test_mcp_health(mcp_url)
    if "error" not in health:
        print(f"    [OK] MCP is healthy!")
        print(f"    Version: {health.get('version', 'unknown')}")
        print(f"    Tools:   {health.get('total_tools_available', 0)}")
        print(f"\n  All tests passed! MCP is ready.")
    else:
        print(f"    [FAIL] MCP health check failed: {health['error']}")
        print(f"\n  Troubleshooting:")
        print(f"    1. Start MCP on VM: ssh {vm_user}@{vm_ip} 'cd /root/Project/hex/hexstrike-ai && docker-compose up -d'")
        print(f"    2. Or use: ssh {vm_user}@{vm_ip} 'systemctl start hexstrike-mcp'")
        sys.exit(1)

    # Test 3: Command execution
    print(f"\n[3] Testing basic command execution...")
    try:
        resp = requests.post(
            f"{mcp_url}/api/command",
            json={"command": "echo 'pong'", "category": "essential"},
            timeout=10,
        )
        result = resp.json()
        if result.get("success") and "pong" in result.get("stdout", ""):
            print(f"    [OK] Command execution works!")
        else:
            print(f"    [WARN] Unexpected response: {result}")
    except Exception as e:
        print(f"    [FAIL] Command execution failed: {e}")

    print(f"\n{'=' * 50}")
    print(f"  Setup complete! Run: python -m api.main")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()
