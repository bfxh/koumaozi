#!/usr/bin/env python3
"""从 CHANGELOG 抽出发版说明，拼上安装方式，供 gh release create --notes-file 使用。

为什么不用 gh 的 --generate-notes：它只会罗列 commit 标题，读的人还是不知道
"这一版到底变了什么、装了怎么用"。CHANGELOG 是写给读的人看的，Release 就该用它。

用法:
    python3 scripts/release_notes.py                    # 用 VERSION
    python3 scripts/release_notes.py --version 1.4.0
    python3 scripts/release_notes.py --out notes.md
    python3 scripts/release_notes.py --section-only     # 只输出 CHANGELOG 段落

退出码: 0 找到；1 该版本在 CHANGELOG 里没有段落（视为没写说明，不许发）。
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import package  # noqa: E402

HEADING_RE = re.compile(r"^##\s+(\d+\.\d+\.\d+)\s*$", re.M)
TAG = "v{version}"
ZIP = "koumaozi-{version}.zip"

INSTALL_BLOCK = """
---

### 安装

解压到 skill 目录即可，无需依赖（Python 标准库）。

```bash
# Linux / macOS / WSL
curl -fL -O https://github.com/bfxh/koumaozi/releases/download/{tag}/{zip}
curl -fL -O https://github.com/bfxh/koumaozi/releases/download/{tag}/{zip}.sha256
sha256sum -c {zip}.sha256          # macOS: shasum -a 256 -c {zip}.sha256
mkdir -p ~/.workbuddy/skills/koumaozi
unzip -o {zip} -d ~/.workbuddy/skills/koumaozi
```

```powershell
# Windows
Invoke-WebRequest -Uri "https://github.com/bfxh/koumaozi/releases/download/{tag}/{zip}" -OutFile "{zip}"
Expand-Archive -Path "{zip}" -DestinationPath "$HOME\\.workbuddy\\skills\\koumaozi" -Force
```

或者直接跑仓库里的安装脚本：`scripts/install.sh` / `scripts/install.ps1`。

装完自检：

```bash
python3 ~/.workbuddy/skills/koumaozi/scripts/hat_scan.py --text "典型的带节奏，一条多少钱？"
```

完整清单见 `CHANGELOG.md`。
"""


def section(text, version):
    """取 `## <version>` 到下一个同级标题之间的内容。格式不符就报错，不猜。"""
    match = HEADING_RE.search(text, 0)
    headings = list(HEADING_RE.finditer(text))
    for index, heading in enumerate(headings):
        if heading.group(1) != version:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[heading.end():end].strip()
        if body:
            return body
    return ""


def notes(version, changelog_path=None):
    path = changelog_path or os.path.join(common.REPO_ROOT, "CHANGELOG.md")
    with open(path, "r", encoding="utf-8") as fh:
        body = section(fh.read(), version)
    if not body:
        return "", False
    block = INSTALL_BLOCK.format(tag=TAG.format(version=version),
                                 zip=ZIP.format(version=version))
    return f"## 扣帽子工程 {TAG.format(version=version)}\n\n{body}\n{block}", True


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="生成 Release 说明")
    parser.add_argument("--version", default=None, help="默认读 VERSION")
    parser.add_argument("--out", default=None, help="写入文件，默认打印到 stdout")
    parser.add_argument("--section-only", action="store_true", help="只要 CHANGELOG 段落")
    args = parser.parse_args(argv)

    version = args.version or package.read_version()
    if args.section_only:
        with open(os.path.join(common.REPO_ROOT, "CHANGELOG.md"), "r", encoding="utf-8") as fh:
            body = section(fh.read(), version)
        text = body
        ok = bool(body)
    else:
        text, ok = notes(version)

    if not ok:
        print(f"CHANGELOG.md 里没有 {version} 的段落，先补说明再发版", file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"写入 {args.out}（{len(text)} 字符）")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
