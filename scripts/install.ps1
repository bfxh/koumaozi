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
  .\install.ps1 -Check              # 只查版本差与本地完整性，不动磁盘
.EXAMPLE
  .\install.ps1 -FromDir .          # 开发态：Junction 指向当前目录，改代码立即生效

.NOTES
  目标目录已存在时先改名成 koumaozi.bak-<时间戳>，不直接删。
  装脚本把人原来的安装干掉，比装不上更糟。

  -Check 退出码：0 已是最新  1 需要动作（有更新/未装/本地被改）  2 查询失败。
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$From = "",
    [string]$FromDir = "",
    [string]$Target = "",
    [switch]$Yes,
    [switch]$Check
)

$ErrorActionPreference = "Stop"
# Expand-Archive / Invoke-WebRequest 的进度条会把输出冲成一坨，安装脚本不该这样刷屏
$ProgressPreference = "SilentlyContinue"
# PowerShell 5.1 默认可能还停在 TLS 1.0，GitHub API 会直接拒握手
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # 老 .NET 上没有 Tls12 枚举就随它去，别为了这行把安装挡死
}
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

function ConvertTo-Part {
    param([string]$Text)
    if ($Text -match "^(\d+)") { return [int]$Matches[1] }
    return 0
}

# 1.10.0 与 1.9.0 按字符串比会判反，必须按数字段比。
# 末尾的 -rc1 之类后缀不参与比较（安装脚本不需要完整的 semver 语义）。
# 注意：PowerShell 变量名大小写不敏感，函数里再写 $a = ... 会直接赋给 [string]$A 参数，
# 数组被强转成 "1 10 0" 这样一串，Count 恒为 1，比较结果永远是"相等"。所以局部变量一律加前缀。
function Compare-Version {
    param([string]$Left, [string]$Right)
    $leftParts = ($Left -replace "^[vV]", "") -split "\."
    $rightParts = ($Right -replace "^[vV]", "") -split "\."
    $n = [Math]::Max($leftParts.Count, $rightParts.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = 0
        $y = 0
        if ($i -lt $leftParts.Count) { $x = ConvertTo-Part $leftParts[$i] }
        if ($i -lt $rightParts.Count) { $y = ConvertTo-Part $rightParts[$i] }
        if ($x -gt $y) { return 1 }
        if ($x -lt $y) { return -1 }
    }
    return 0
}

function Invoke-Python {
    param([string[]]$Arguments)
    if ($py.Count -gt 1) {
        & $py[0] $py[1] @Arguments
    } else {
        & $py[0] @Arguments
    }
}

function Invoke-Utf8Child {
    # python 侧固定输出 UTF-8，本进程在中文 Windows 上默认 GBK。直接混在一条管道里
    # 两种编码会互相串码，所以调用期间临时对齐，收完字符串再恢复原样。
    param([scriptblock]$Child)
    $saved = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
        & $Child
    } finally {
        [Console]::OutputEncoding = $saved
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

# ---- 只查不装 ----
if ($Check) {
    $status = 0
    $local = ""
    $versionFile = Join-Path $Target "VERSION"
    if (Test-Path $versionFile) { $local = (Get-Content $versionFile -Raw).Trim() }

    try {
        if ($Version) {
            $remote = $Version -replace "^[vV]", ""
            $note = "指定"
        } else {
            Write-Host "查询最新 Release…"
            $api = "https://api.github.com/repos/$Repo/releases/latest"
            $rel = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "koumaozi-installer" }
            $remote = $rel.tag_name -replace "^[vV]", ""
            $note = $rel.tag_name
            if (-not $remote) { throw "查不到最新版本，用 -Version 指定要比的版本" }
        }
    } catch {
        Write-Host "错误: 查不到版本 —— $($_.Exception.Message)"
        exit 2
    }

    if (-not $local) {
        Write-Host "本地  未安装"
        Write-Host "线上  $remote  ($note)"
        Write-Host "→ 尚未安装：.\scripts\install.ps1"
        exit 1
    }

    $item = Get-Item -LiteralPath $Target -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        # .Target 在 PS 5.1 上对 Junction 未必有值，取不到就只报"是软链"
        $linkInfo = ""
        try {
            $linkTarget = @($item.Target)[0]
            if ($linkTarget) { $linkInfo = " -> $linkTarget" }
        } catch {
            $linkInfo = ""
        }
        Write-Host "本地  $local  (开发态 Junction$linkInfo)"
    } else {
        Write-Host "本地  $local  ($Target)"
    }
    Write-Host "线上  $remote  ($note)"

    # 装完被改过、被半路中断的拷贝覆盖过都不会报错，只会在某天扫不出东西时暴露。
    # 清单就在安装目录里，顺手核一遍——源码态没有 MANIFEST，脚本自己会说跳过。
    #
    # 编码：python 侧固定吐 UTF-8（common.ensure_utf8_stdout），本进程在中文 Windows 上
    # 默认是 GBK。直接透传会在同一条管道里混两种编码，两边都变乱码。所以调用期间临时
    # 把 Console.OutputEncoding 对齐到 UTF-8，收完字符串再恢复——这样用户看到的
    # 还是本进程原来的编码，不会因为这一句把整个控制台弄成乱码。
    $integrityFail = $false
    $manifest = Join-Path $Target "MANIFEST.sha256"
    $pkgScript = Join-Path $Target "scripts\package.py"
    if ((Test-Path $manifest) -and (Test-Path $pkgScript)) {
        $checkArgs = @()
        if ($py.Count -gt 1) { $checkArgs += $py[1] }
        $checkArgs += @($pkgScript, "--check-dir", $Target)
        $checkOut = @(Invoke-Utf8Child { & $py[0] @checkArgs 2>&1 })
        if ($LASTEXITCODE -ne 0) { $integrityFail = $true }
        $checkOut | ForEach-Object { Write-Host "$_" }
    }

    # 结论只谈"要不要动手"，版本与完整性各说一句，别互相盖掉
    $cmp = Compare-Version $remote $local
    $verdict = ""
    if ($cmp -eq 1) {
        $verdict = "→ 有更新：$local → $remote"
        $status = 1
    } elseif ($cmp -eq 0) {
        $verdict = "→ 版本已是最新"
    } else {
        $verdict = "→ 本地比线上新（开发态？）。要回退：.\scripts\install.ps1 -Version $remote -Yes"
    }
    if ($integrityFail) {
        # 本来就该往上装的时候，装最新版顺手就把内容修好了，别再劝人装回旧版
        if ($cmp -eq 1) {
            $fix = ".\scripts\install.ps1 -Yes"
        } else {
            $fix = ".\scripts\install.ps1 -Version $local -Yes"
        }
        $verdict = $verdict + "`n→ 但本地文件与清单不符（装后被改过或没装全），重装修好：$fix"
        $status = 1
    } elseif ($status -eq 1) {
        $verdict = $verdict + "`n  装新版：.\scripts\install.ps1 -Yes"
    }
    Write-Host $verdict
    exit $status
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
    $verifyOut = @(Invoke-Utf8Child { & $py[0] @verifyArgs 2>&1 })
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
