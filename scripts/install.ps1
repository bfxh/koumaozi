<#
.SYNOPSIS
  装扣帽子工程到 WorkBuddy skill 目录（Windows）。

.EXAMPLE
  .\install.ps1
.EXAMPLE
  .\install.ps1 -Version v1.4.0
.EXAMPLE
  .\install.ps1 -From dist\koumaozi-1.4.0.zip
.EXAMPLE
  .\install.ps1 -FromDir .          # 开发态：Junction 指向当前目录，改代码立即生效

.NOTES
  目标目录已存在时先改名成 koumaozi.bak-<时间戳>，不直接删。
  装脚本把人原来的安装干掉，比装不上更糟。
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$From = "",
    [string]$FromDir = "",
    [string]$Target = "",
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
# Expand-Archive / Invoke-WebRequest 的进度条会把输出冲成一坨，安装脚本不该这样刷屏
$ProgressPreference = "SilentlyContinue"
$Repo = "bfxh/koumaozi"
$Skill = "koumaozi"

if (-not $Target) {
    $base = $env:WORKBUDDY_SKILLS
    if (-not $base) { $base = Join-Path $HOME ".workbuddy\skills" }
    $Target = Join-Path $base $Skill
}

function Find-Python {
    foreach ($candidate in @("python", "python3", "py")) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            if ($candidate -eq "py") { return @("py", "-3") }
            return @($candidate)
        }
    }
    throw "找不到 Python 3，先装它（https://www.python.org/downloads/）"
}

# 必须用 @() 包住：PowerShell 函数返回单元素数组时会被展开成字符串，
# 那样 $py[0] 取到的是首字母 "p"，报错会莫名其妙地变成"无法将 p 项识别为 cmdlet"
$py = @(Find-Python)

function Invoke-Python {
    param([string[]]$Arguments)
    if ($py.Count -gt 1) {
        & $py[0] $py[1] @Arguments
    } else {
        & $py[0] @Arguments
    }
}

function Move-Aside {
    param([string]$Path)
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $backup = "$Path.bak-$stamp"
    Move-Item -LiteralPath $Path -Destination $backup
    Write-Host "原有目录已备份: $backup"
    return $backup
}

# ---- 开发态：Junction 指向源码目录 ----
if ($FromDir) {
    $src = (Resolve-Path $FromDir).Path
    if (-not (Test-Path (Join-Path $src "SKILL.md"))) {
        throw "$src 不是 skill 目录（缺 SKILL.md）"
    }
    $parent = Split-Path -Parent $Target
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (Test-Path $Target) {
        if (-not $Yes) {
            $answer = Read-Host "目标已存在: $Target`n覆盖会先备份。继续？[y/N]"
            if ($answer -notmatch "^[yY]") { throw "已取消，目标目录未改动" }
        }
        Move-Aside $Target | Out-Null
    }
    New-Item -ItemType Junction -Path $Target -Target $src | Out-Null
    Write-Host "已建立 Junction $Target -> $src"
    Invoke-Python @((Join-Path $Target "scripts\verify_data.py")) | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "自检通过" } else { throw "自检不通过" }
    return
}

# ---- 取包 ----
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("koumaozi-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    if ($From) {
        if (-not (Test-Path $From)) { throw "找不到包: $From" }
        $zipPath = (Resolve-Path $From).Path
        Write-Host "使用本地包 $zipPath"
    } else {
        if (-not $Version) {
            Write-Host "查询最新 Release…"
            $api = "https://api.github.com/repos/$Repo/releases/latest"
            $rel = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "koumaozi-installer" }
            $Version = $rel.tag_name
            if (-not $Version) { throw "查不到最新版本，用 -Version 指定" }
        }
        if ($Version -notmatch "^v") { $Version = "v$Version" }
        $zipName = "koumaozi-" + ($Version -replace "^v", "") + ".zip"
        $baseUrl = "https://github.com/$Repo/releases/download/$Version"
        $zipPath = Join-Path $work $zipName
        Write-Host "下载 $Version"
        Invoke-WebRequest -Uri "$baseUrl/$zipName" -OutFile $zipPath -UseBasicParsing

        $shaPath = "$zipPath.sha256"
        try {
            Invoke-WebRequest -Uri "$baseUrl/$zipName.sha256" -OutFile $shaPath -UseBasicParsing
            $expected = ((Get-Content $shaPath -Raw) -split "\s+")[0].ToLower()
            $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
            if ($expected -ne $actual) { throw "sha256 校验不通过，包被动过" }
            Write-Host "sha256 校验通过"
        } catch {
            if ($_.Exception.Message -like "*校验不通过*") { throw }
            Write-Host "警告: 没有 .sha256 文件，跳过校验"
        }
    }

    $unpacked = Join-Path $work "unpacked"
    # Expand-Archive 在 PowerShell 5.1 上又慢又刷进度条，直接走 .NET
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $unpacked)
    if (-not (Test-Path (Join-Path $unpacked "SKILL.md"))) { throw "包里没有 SKILL.md，不是有效 skill 包" }

    # 先在临时目录自检，通过了才动目标目录
    $verifyArgs = @()
    if ($py.Count -gt 1) { $verifyArgs += $py[1] }
    $verifyArgs += (Join-Path $unpacked "scripts\verify_data.py")
    $verifyOut = & $py[0] @verifyArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $verifyOut | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
        throw "包自检不通过，未安装（目标目录未改动）"
    }
    Write-Host "包自检通过"

    if (Test-Path $Target) {
        if (-not $Yes) {
            $answer = Read-Host "目标已存在: $Target`n覆盖会先备份。继续？[y/N]"
            if ($answer -notmatch "^[yY]") { throw "已取消，目标目录未改动" }
        }
        Move-Aside $Target | Out-Null
    }

    $parent = Split-Path -Parent $Target
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Copy-Item -LiteralPath $unpacked -Destination $Target -Recurse -Force

    $ver = (Get-Content (Join-Path $Target "VERSION") -Raw).Trim()
    Write-Host "已安装 $Skill $ver -> $Target"
    Write-Host "自检: python `"$Target\scripts\hat_scan.py`" --text `"典型的带节奏，一条多少钱？`""
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
