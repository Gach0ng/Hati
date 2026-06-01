# ===========================================
# SSH Tunnel - Windows端建立到Kali VM的SSH隧道
# 将本地端口转发到 VM 的 HexStrike MCP 服务
# ===========================================
param(
    [string]$VmHost = "",
    [int]$VmPort = 22,
    [string]$VmUser = "root",
    [string]$VmPassword = "",
    [int]$LocalPort = 9999,
    [int]$RemotePort = 9999,
    [switch]$Background = $true
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SSH Tunnel to Kali VM" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查 SSH 客户端
$sshPath = Get-Command ssh.exe -ErrorAction SilentlyContinue
if (-not $sshPath) {
    Write-Host "[ERROR] SSH client not found!" -ForegroundColor Red
    Write-Host "Please install OpenSSH Client:" -ForegroundColor Yellow
    Write-Host "  Settings > Apps > Optional Features > Add a feature > OpenSSH Client" -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] SSH client found: $($sshPath.Source)" -ForegroundColor Green

# 检查端口是否已被占用
$portInUse = netstat -ano | Select-String ":$LocalPort " | Select-String "LISTENING"
if ($portInUse) {
    Write-Host "[WARN] Port $LocalPort is already in use" -ForegroundColor Yellow
    Write-Host "  $portInUse" -ForegroundColor Yellow
    $choice = Read-Host "Kill existing connection? (y/n)"
    if ($choice -eq 'y') {
        $pidMatch = [regex]::Match($portInUse, '\s+(\d+)\s*$')
        if ($pidMatch.Success) {
            $existingPid = $pidMatch.Groups[1].Value
            Stop-Process -Id $existingPid -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Killed process $existingPid" -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
    } else {
        Write-Host "[INFO] Tunnel may already be running, checking connection..." -ForegroundColor Cyan
        Test-McpConnection -Port $LocalPort
        return
    }
}

# 测试 VM 连通性
Write-Host ""
Write-Host "[INFO] Testing VM connectivity..." -ForegroundColor Cyan
$pingResult = Test-Connection -ComputerName $VmHost -Count 2 -Quiet
if (-not $pingResult) {
    Write-Host "[WARN] Cannot ping $VmHost, trying to connect anyway..." -ForegroundColor Yellow
} else {
    Write-Host "[OK] VM is reachable" -ForegroundColor Green
}

# 建立 SSH 隧道
Write-Host ""
Write-Host "[INFO] Establishing SSH tunnel..." -ForegroundColor Cyan
Write-Host "  Local:  localhost:$LocalPort" -ForegroundColor Gray
Write-Host "  Remote: $VmHost`:$RemotePort" -ForegroundColor Gray
Write-Host ""

# 使用 plink 或 sshpass 处理密码
$plinkPath = Get-Command plink.exe -ErrorAction SilentlyContinue
$sshpassPath = Get-Command sshpass -ErrorAction SilentlyContinue

if ($sshpassPath) {
    # 使用 sshpass (Git Bash / WSL)
    Write-Host "[INFO] Using sshpass for password authentication" -ForegroundColor Cyan
    $sshCmd = "sshpass -p '$VmPassword' ssh -o StrictHostKeyChecking=no -N -L ${LocalPort}:localhost:${RemotePort} ${VmUser}@${VmHost} -p ${VmPort}"
} elseif ($plinkPath) {
    # 使用 PuTTY plink
    Write-Host "[INFO] Using plink for SSH tunnel" -ForegroundColor Cyan
    $sshCmd = "echo y | plink -ssh -N -L ${LocalPort}:localhost:${RemotePort} ${VmUser}@${VmHost} -P ${VmPort} -pw ${VmPassword}"
} else {
    # 使用 OpenSSH + 密钥方式，或提示需要 sshpass
    Write-Host "[WARN] sshpass not found, attempting key-based auth..." -ForegroundColor Yellow
    Write-Host "[INFO] If this fails, install sshpass or set up SSH key auth:" -ForegroundColor Yellow
    Write-Host "  ssh-copy-id ${VmUser}@${VmHost}" -ForegroundColor Yellow
    Write-Host ""
    $sshCmd = "ssh -o StrictHostKeyChecking=no -N -L ${LocalPort}:localhost:${RemotePort} ${VmUser}@${VmHost} -p ${VmPort}"
}

Write-Host "[CMD] $sshCmd" -ForegroundColor DarkGray
Write-Host ""

if ($Background) {
    # 后台运行
    Write-Host "[INFO] Starting tunnel in background..." -ForegroundColor Cyan

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = "cmd.exe"
    $processInfo.Arguments = "/c `"$sshCmd`""
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($processInfo)

    Write-Host "[OK] SSH tunnel started (PID: $($process.Id))" -ForegroundColor Green
    Write-Host ""

    # 等待隧道建立
    Start-Sleep -Seconds 3

    # 测试 MCP 连接
    Test-McpConnection -Port $LocalPort
} else {
    # 前台运行
    Write-Host "[INFO] Starting tunnel in foreground (Ctrl+C to stop)..." -ForegroundColor Cyan
    Invoke-Expression $sshCmd
}

# ===========================================
# Helper: Test MCP connection
# ===========================================
function Test-McpConnection {
    param([int]$Port = 9999)

    Write-Host "[INFO] Testing HexStrike MCP connection..." -ForegroundColor Cyan

    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$Port/health" -TimeoutSec 5 -ErrorAction Stop
        Write-Host "[OK] HexStrike MCP is reachable!" -ForegroundColor Green
        Write-Host "  Version: $($response.version)" -ForegroundColor Gray
        Write-Host "  Tools: $($response.total_tools_available)" -ForegroundColor Gray
        return $true
    } catch {
        Write-Host "[WARN] Cannot reach MCP at localhost:$Port" -ForegroundColor Yellow
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Check VM firewall: ufw allow 9999" -ForegroundColor Yellow
        Write-Host "  2. Check MCP is running: ssh root@$VmHost 'curl localhost:9999/health'" -ForegroundColor Yellow
        Write-Host "  3. Try direct connect: curl http://$VmHost`:9999/health" -ForegroundColor Yellow
        return $false
    }
}

# 保存 PID 供后续停止
$pidFile = Join-Path $PSScriptRoot ".tunnel_pid"
if ($process) {
    $process.Id | Out-File -FilePath $pidFile
    Write-Host "[INFO] Tunnel PID saved to: $pidFile" -ForegroundColor Gray
    Write-Host "[INFO] To stop: Get-Process -Id $($process.Id) | Stop-Process" -ForegroundColor Gray
}
