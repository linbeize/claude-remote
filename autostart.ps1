# 开机自动启动 Claude Remote（计划任务）
#   安装：powershell -ExecutionPolicy Bypass -File autostart.ps1
#   卸载：powershell -ExecutionPolicy Bypass -File autostart.ps1 -Remove
#
# 任务以当前用户身份运行（Claude 的登录信息在这个用户目录里），开机就启动，不用先登录 Windows，也不弹窗口。
# 实际运行的是 run.mjs（崩溃后自动重启），输出在 data\logs\server.log。
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$TaskName = 'Claude Remote'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
  Write-Host '需要管理员权限：右键开始菜单 → “终端（管理员）”，再运行这条命令。' -ForegroundColor Yellow
  exit 1
}

if ($Remove) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "已删除计划任务“$TaskName”，服务已停止。"
  } else {
    Write-Host "没有找到计划任务“$TaskName”。"
  }
  return
}

$dir  = $PSScriptRoot
$node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = 'C:\Program Files\nodejs\node.exe' }
if (-not (Test-Path $node)) { throw "找不到 node.exe" }

$user = "$env:USERDOMAIN\$env:USERNAME"
$action    = New-ScheduledTaskAction -Execute $node -Argument 'run.mjs' -WorkingDirectory $dir
$trigger   = New-ScheduledTaskTrigger -AtStartup
# S4U：不保存密码，不登录也能运行，没有窗口
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
  -Description 'Claude Remote 网页服务（开机启动，崩溃自动重启）' -Force | Out-Null
Write-Host "已创建计划任务“$TaskName”：开机自动启动，以 $user 身份在后台运行。"

Start-ScheduledTask -TaskName $TaskName
Write-Host "已启动。日志：$dir\data\logs\server.log"
