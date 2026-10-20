#!/usr/bin/env python3
"""内容量门禁：统计有效中文字数。

规则：
- 统计 .md 文件，跳过 .git / node_modules / _site
- 剔除 frontmatter、代码块、HTML 注释、纯标点行
- 中日韩统一表意文字按字计，英文按词计（英文权重 1 词 = 1）
- 表格分隔线、URL、路径不计入

用法:
    python3 scripts/wordcount.py
    python3 scripts/wordcount.py --min 10000 --json
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "_site", "__pycache__", ".github"}
FRONTMATTER_RE = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.S)
FENCE_RE = re.compile(r"```.*?```", re.S)
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
URL_RE = re.compile(r"https?://\S+|!\[[^\]]*\]\([^)]*\)|\[[^\]]*\]\([^)]*\)")
TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:|-]{3,}\|?\s*$", re.M)
CJK_RE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")
EN_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-']*")


def clean(text):
    text = FRONTMATTER_RE.sub(" ", text)
    text = FENCE_RE.sub(" ", text)
    text = COMMENT_RE.sub(" ", text)
    text = URL_RE.sub(" ", text)
    text = TABLE_SEP_RE.sub(" ", text)
    return text


def count(text):
    body = clean(text)
    return len(CJK_RE.findall(body)), len(EN_WORD_RE.findall(body))


def iter_markdown(root):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            if name.lower().endswith((".md", ".markdown")):
                yield os.path.join(current, name)


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="内容量统计")
    parser.add_argument("--root", default=common.REPO_ROOT)
    parser.add_argument("--min", type=int, default=10000, help="最低中文字数，低于则失败")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rows = []
    total_cjk = 0
    total_en = 0
    for path in iter_markdown(args.root):
        with open(path, "r", encoding="utf-8") as fh:
            cjk, en = count(fh.read())
        rows.append({"path": common.relpath(path), "cjk": cjk, "en_words": en})
        total_cjk += cjk
        total_en += en

    passed = total_cjk >= args.min
    payload = {
        "tool": "wordcount",
        "files": rows,
        "total_cjk": total_cjk,
        "total_en_words": total_en,
        "min_required": args.min,
        "passed": passed,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for row in sorted(rows, key=lambda r: -r["cjk"]):
            print(f"{row['cjk']:>7} 字  {row['path']}")
        print("-" * 40)
        print(f"中文合计 {total_cjk} 字 / 英文 {total_en} 词  (门槛 {args.min})")
        print("通过" if passed else f"不足：还差 {args.min - total_cjk} 字")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
