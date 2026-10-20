#!/usr/bin/env bash
# 装扣帽子工程到 WorkBuddy skill 目录。
#
#   ./install.sh                     装最新 Release
#   ./install.sh --check             只查版本差与本地完整性，不动磁盘
#   ./install.sh --version v1.4.0    装指定版本
#   ./install.sh --from dist/koumaozi-1.4.0.zip   装本地包
#   ./install.sh --from-dir .        开发态：软链当前目录（改代码立即生效）
#   ./install.sh --target /path      装到别处
#
# --check 退出码：0 已是最新   1 需要动作（有更新/未装/本地被改）
#                 2 查询失败。所以 `install.sh --check || install.sh -y`
#                 就是"有新版就装"，不需要人看输出。
#
# 目标目录已存在时会先改名成 koumaozi.bak-<时间戳>，不直接删——
# 装脚本把人原来的安装干掉，比装不上更糟。
set -euo pipefail

REPO="bfxh/koumaozi"
SKILL="koumaozi"
VERSION=""
SOURCE_ZIP=""
SOURCE_DIR=""
TARGET="${WORKBUDDY_SKILLS:-$HOME/.workbuddy/skills}/$SKILL"
ASSUME_YES=0
CHECK_ONLY=0

say() { printf '%s\n' "$*"; }
die() { printf '错误: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --from)    SOURCE_ZIP="${2:-}"; shift 2 ;;
    --from-dir) SOURCE_DIR="${2:-}"; shift 2 ;;
    --target)  TARGET="${2:-}"; shift 2 ;;
    --check)   CHECK_ONLY=1; shift ;;
    -y|--yes)  ASSUME_YES=1; shift ;;
    -h|--help) awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "$0"; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || die "需要 $1，先装它"; }
need python3

# 版本比较：1.10.0 与 1.9.0 用字符串比会判反，必须按数字段比。
# 末尾的 -rc1 之类后缀不参与比较（安装脚本不需要完整的 semver 语义）。
ver_cmp() {
  awk -v a="$1" -v b="$2" '
    function cmp(x, y,   i, n, xs, ys, nx, ny, xi, yi) {
      sub(/^[vV]/, "", x); sub(/^[vV]/, "", y)
      nx = split(x, xs, "."); ny = split(y, ys, ".")
      n = (nx > ny ? nx : ny)
      for (i = 1; i <= n; i++) {
        xi = (i <= nx ? xs[i] + 0 : 0); yi = (i <= ny ? ys[i] + 0 : 0)
        if (xi > yi) return 1
        if (xi < yi) return -1
      }
      return 0
    }
    BEGIN { print cmp(a, b) }'
}

# ---- 只查不装 ----
if [ "$CHECK_ONLY" -eq 1 ]; then
  LOCAL_VER=""
  if [ -f "$TARGET/VERSION" ]; then
    LOCAL_VER="$(tr -d ' \r\n' <"$TARGET/VERSION")"
  fi

  if [ -n "$VERSION" ]; then
    REMOTE_VER="${VERSION#v}"
    REMOTE_NOTE="指定"
  else
    need curl
    REMOTE_TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$REMOTE_TAG" ] || die "查不到最新版本（网络或 API 限流），用 --version 指定要比的版本"
    REMOTE_VER="${REMOTE_TAG#v}"
    REMOTE_NOTE="$REMOTE_TAG"
  fi

  STATUS=0
  if [ -z "$LOCAL_VER" ]; then
    say "本地  未安装"
    say "线上  $REMOTE_VER  ($REMOTE_NOTE)"
    say "→ 尚未安装：bash scripts/install.sh"
    STATUS=1
  else
    if [ -L "$TARGET" ]; then
      say "本地  $LOCAL_VER  (开发态软链 → $(readlink "$TARGET"))"
    else
      say "本地  $LOCAL_VER  ($TARGET)"
    fi
    say "线上  $REMOTE_VER  ($REMOTE_NOTE)"

    # 装完被改过、被半路中断的 cp 覆盖过，都不会报错，只会在某天扫不出东西时暴露。
    # 清单就在安装目录里，顺手核一遍——源码态没有 MANIFEST，脚本自己会说跳过。
    INTEGRITY_FAIL=0
    if [ -f "$TARGET/MANIFEST.sha256" ] && [ -f "$TARGET/scripts/package.py" ]; then
      python3 "$TARGET/scripts/package.py" --check-dir "$TARGET" || INTEGRITY_FAIL=1
    fi

    # 结论只谈"要不要动手"，版本与完整性各说一句，别互相盖掉
    CMP="$(ver_cmp "$REMOTE_VER" "$LOCAL_VER")"
    case "$CMP" in
      0)  VERDICT="→ 版本已是最新" ;;
      1)  VERDICT="→ 有更新：$LOCAL_VER → $REMOTE_VER"
          STATUS=1 ;;
      *)  VERDICT="→ 本地比线上新（开发态？）。要回退：bash scripts/install.sh --version $REMOTE_VER -y" ;;
    esac
    if [ "$INTEGRITY_FAIL" -eq 1 ]; then
      # 本来就该往上装的时候，装最新版顺手就把内容修好了，别再劝人装回旧版
      if [ "$CMP" = "1" ]; then
        FIX="bash scripts/install.sh -y"
      else
        FIX="bash scripts/install.sh --version $LOCAL_VER -y"
      fi
      VERDICT="$VERDICT
→ 但本地文件与清单不符（装后被改过或没装全），重装修好：$FIX"
      STATUS=1
    elif [ "$STATUS" -eq 1 ]; then
      VERDICT="$VERDICT
  装新版：bash scripts/install.sh -y"
    fi
    printf '%s\n' "$VERDICT"
  fi
  exit "$STATUS"
fi

# 开发态：软链，改代码立即生效，不用重装
if [ -n "$SOURCE_DIR" ]; then
  SRC="$(cd "$SOURCE_DIR" && pwd)"
  [ -f "$SRC/SKILL.md" ] || die "$SRC 不是 skill 目录（缺 SKILL.md）"
  mkdir -p "$(dirname "$TARGET")"
  if [ -e "$TARGET" ]; then
    BACKUP="$TARGET.bak-$(date +%Y%m%d%H%M%S)"
    mv "$TARGET" "$BACKUP"
    say "原有目录已改名: $BACKUP"
  fi
  ln -s "$SRC" "$TARGET"
  say "已软链 $TARGET -> $SRC"
  python3 "$TARGET/scripts/verify_data.py" >/dev/null && say "自检通过"
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

if [ -n "$SOURCE_ZIP" ]; then
  [ -f "$SOURCE_ZIP" ] || die "找不到包: $SOURCE_ZIP"
  ZIP_PATH="$(cd "$(dirname "$SOURCE_ZIP")" && pwd)/$(basename "$SOURCE_ZIP")"
  say "使用本地包 $ZIP_PATH"
else
  need curl
  if [ -z "$VERSION" ]; then
    say "查询最新 Release…"
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$VERSION" ] || die "查不到最新版本，用 --version 指定"
  fi
  case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
  ZIP_NAME="koumaozi-${VERSION#v}.zip"
  BASE="https://github.com/$REPO/releases/download/$VERSION"
  ZIP_PATH="$WORKDIR/$ZIP_NAME"
  say "下载 $VERSION"
  curl -fL --retry 3 -o "$ZIP_PATH" "$BASE/$ZIP_NAME" || die "下载失败: $BASE/$ZIP_NAME"
  if curl -fsL --retry 2 -o "$ZIP_PATH.sha256" "$BASE/$ZIP_NAME.sha256"; then
    ( cd "$WORKDIR" && (sha256sum -c "$ZIP_NAME.sha256" 2>/dev/null \
        || shasum -a 256 -c "$ZIP_NAME.sha256") ) || die "sha256 校验不通过，包被动过"
    say "sha256 校验通过"
  else
    say "警告: 没有 .sha256 文件，跳过校验"
  fi
fi

need unzip
mkdir -p "$WORKDIR/unpacked"
unzip -q -o "$ZIP_PATH" -d "$WORKDIR/unpacked" || die "解压失败"
[ -f "$WORKDIR/unpacked/SKILL.md" ] || die "包里没有 SKILL.md，不是有效 skill 包"

# 解压后先在临时目录自检，通过了才动目标目录
if ! python3 "$WORKDIR/unpacked/scripts/verify_data.py" >"$WORKDIR/verify.log" 2>&1; then
  tail -n 5 "$WORKDIR/verify.log" >&2
  die "包自检不通过，未安装（目标目录未改动）"
fi
say "包自检通过"

if [ -e "$TARGET" ]; then
  if [ "$ASSUME_YES" -eq 0 ]; then
    printf '目标已存在: %s\n覆盖安装会先备份为 .bak-<时间戳>。继续？[y/N] ' "$TARGET"
    read -r answer || answer=""
    case "$answer" in [yY]*) ;; *) die "已取消，目标目录未改动" ;; esac
  fi
  BACKUP="$TARGET.bak-$(date +%Y%m%d%H%M%S)"
  mv "$TARGET" "$BACKUP"
  say "原有目录已备份: $BACKUP"
fi

mkdir -p "$(dirname "$TARGET")"
cp -R "$WORKDIR/unpacked" "$TARGET"

ver="$(cat "$TARGET/VERSION" 2>/dev/null || echo unknown)"
say "已安装 $SKILL $ver → $TARGET"
say "自检: python3 $TARGET/scripts/hat_scan.py --text \"典型的带节奏，一条多少钱？\""
