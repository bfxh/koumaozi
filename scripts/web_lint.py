#!/usr/bin/env python3
"""网页端静态检查：语法、引用闭合、DOM 契约。

`docs/app.js` 是全仓库唯一没有行为测试的地方——它只是把扫描结果画到页面上，
而这一层坏掉的方式非常安静：`getElementById` 拿不到元素就返回 null，
随后的赋值才抛错，控制台一行红字，页面还在，看着像"没数据"而不是"坏了"。
静态检查能挡掉其中真正高频的一类：改了 HTML 的 id、忘了改 JS。

查四件事：
1. 每个 js 都能过 `node --check`
2. index.html 里 `<script src>` 引用的文件都真实存在（改过文件名就会漏）
3. app.js 里 `getElementById("x")` 的 x 都能在 index.html 里找到
4. index.html 里每个 id 只出现一次（重复 id 会让 getElementById 拿到前面那个）

缺 node 时只跳过第 1 项，其余三项照样查——静态引用关系不依赖运行时。

退出码: 0 通过；1 有问题。
"""
import os
import re
import shutil
import subprocess
import sys

DOCS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")

SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc="([^"]+)"')
ID_ATTR_RE = re.compile(r'\bid="([^"]+)"')
GET_BY_ID_RE = re.compile(r'getElementById\(\s*"([^"]+)"\s*\)')


def read(name):
    with open(os.path.join(DOCS, name), "r", encoding="utf-8") as handle:
        return handle.read()


def node_path():
    for name in ("node", "nodejs"):
        found = shutil.which(name)
        if found:
            return found
    return None


def check_syntax(node, files):
    problems = []
    if not node:
        return problems, "缺 node，语法检查跳过"
    for name in files:
        proc = subprocess.run([node, "--check", os.path.join(DOCS, name)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace")
        if proc.returncode != 0:
            problems.append(f"{name} 语法错误: {(proc.stderr or '').strip().splitlines()[:1]}")
    return problems, ""


def check_script_refs(html):
    problems = []
    for src in SCRIPT_SRC_RE.findall(html):
        if src.startswith(("http://", "https://", "//")):
            continue
        if not os.path.isfile(os.path.join(DOCS, src)):
            problems.append(f"index.html 引用了不存在的脚本: {src}")
    return problems


def check_dom_contract(html, app):
    problems = []
    ids = ID_ATTR_RE.findall(html)
    duplicated = {item for item in ids if ids.count(item) > 1}
    for item in sorted(duplicated):
        problems.append(f"index.html 里 id=\"{item}\" 出现了 {ids.count(item)} 次，"
                        f"getElementById 只会拿到第一个")
    wanted = GET_BY_ID_RE.findall(app)
    missing = [item for item in sorted(set(wanted)) if item not in ids]
    for item in missing:
        problems.append(f"app.js 找 # {item}，index.html 里没有这个 id")
    return problems


def main(argv=None):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import common
    common.ensure_utf8_stdout()

    if not os.path.isdir(DOCS):
        print("网页端静态检查  跳过（没有 docs/，安装包不带网页）")
        return 0

    html = read("index.html")
    app = read("app.js")
    files = [name for name in ("rules.js", "scan.js", "app.js")
             if os.path.isfile(os.path.join(DOCS, name))]

    problems = []
    syntax_problems, note = check_syntax(node_path(), files)
    problems.extend(syntax_problems)
    problems.extend(check_script_refs(html))
    problems.extend(check_dom_contract(html, app))

    if problems:
        print(f"网页端静态检查  {len(problems)} 项有问题")
        for line in problems:
            print(f"  × {line}")
        return 1
    ids = len(set(ID_ATTR_RE.findall(html)))
    refs = len(GET_BY_ID_RE.findall(app))
    suffix = f"  |  {note}" if note else ""
    print(f"网页端静态检查  {len(files)} 个脚本  |  引用 {refs} 处 DOM / {ids} 个 id 全覆盖{suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
