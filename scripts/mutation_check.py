#!/usr/bin/env python3
"""变异验证：把已经修好的 bug 逐一改回去，看门禁会不会红。

为什么需要这一道：测试和门禁都会腐烂，而且是**静默**腐烂。一条断言写错了
对象、一个 `assertIn` 写成了永远成立的形式，跑起来照样一片绿，谁也不会去看
它到底在防什么。办法只有一个——把被防的那件事故意做错一次，看它红不红。
不红的门禁就是装饰品。

这一道守护的是「其他门禁有没有效」，所以它必须自己先证明有效：每条变异都在
预期范围内，改回去之后必须红，红不回来就报漏网。

用法:
    python3 scripts/mutation_check.py
    python3 scripts/mutation_check.py --list
    python3 scripts/mutation_check.py --only score,combo
    python3 scripts/mutation_check.py --verbose

退出码: 0 全部被抓到；1 有漏网或锚点失效。
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
import time

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPTS)

# 每条: 把 file 里能匹配 pattern 的第一处换成 replace，然后跑 verify。
# 期望 verify **失败**——失败才说明这条门禁在起作用。
#
# 锚点一律用"函数签名 / 整句断言"这种稳定的形状，不要锚在半行语法上：
# 锚点是字符串，而字符串里的反斜杠在正则里又有含义，很容易写成永不匹配
# 而看起来"通过"的空变异（这一版就踩过，`[^\n]` 被吃掉变成真的换行）。
MUTATIONS = [
    {
        "key": "score",
        "name": "标签分不再按 used 过滤",
        "breaks": "澄清文和攻击文拿同样的分",
        "file": "scripts/hat_scan.py",
        "pattern": r"    used = \[f for f in findings if f\.get\(\"role\", \"used\"\) == \"used\"\]\n",
        "replace": "    used = list(findings)\n",
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestScoreOnlyCountsUsed.test_score_parts_are_used_only"],
    },
    {
        "key": "combo",
        "name": "连招不再按 used 过滤",
        "breaks": "被引用的碎片被拼成 Critical 连招",
        "file": "scripts/hat_scan.py",
        "pattern": r"    usable = \[f for f in findings\n"
                   r"              if f\[\"kind\"\] in \(\"pattern\", \"hat\"\) "
                   r"and f\.get\(\"role\", \"used\"\) == \"used\"\]",
        "replace": '    usable = [f for f in findings if f["kind"] in ("pattern", "hat")]',
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestScoreOnlyCountsUsed"
                   ".test_combo_never_assembled_from_quoted_fragments"],
    },
    {
        "key": "docmode",
        "name": "标题和表格不再降级",
        "breaks": "讲解文章被判满分（工具直接不可用）",
        "file": "scripts/common.py",
        "pattern": r"    if slot in \(SLOT_HEADING, SLOT_TABLE\):",
        "replace": "    if False:",
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestDocMode.test_table_row_is_demoted"],
    },
    {
        "key": "overdemote",
        "name": "引用块也被降级（降过头）",
        "breaks": "粘原话扫描报 0 分，错在另一个方向",
        "file": "scripts/common.py",
        "pattern": r"    if slot == SLOT_LIST and ID_RE\.search\(line_text\(text, absolute\)\):",
        "replace": "    if slot in (SLOT_LIST, SLOT_QUOTE):",
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestDocMode"
                   ".test_heading_is_demoted_but_blockquote_is_not"],
    },
    {
        "key": "lines",
        "name": "清洗代码块时丢掉换行",
        "breaks": "报出的行号比真实位置小一大截，照着跳转会落到别的段落",
        "file": "scripts/common.py",
        "pattern": r"def _blank_same_shape\(match\):[\s\S]*?return [^\n]*\n",
        "replace": 'def _blank_same_shape(match):\n    return " " * len(match.group(0))\n',
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestStripCodeKeepsLines.test_line_count_is_preserved"],
    },
    {
        "key": "rhetoric",
        "name": "反问式定性不再识别",
        "breaks": "「这不是典型的公知话术吗」被当成否认句放行",
        "file": "scripts/common.py",
        "pattern": r"def _rhetorical_frame\(text, start, end\):\n",
        "replace": "def _rhetorical_frame(text, start, end):\n    return False\n",
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestScanner"
                   ".test_rhetorical_question_across_words_is_used"],
    },
    {
        "key": "report",
        "name": "报告不再分节",
        "breaks": "给人看的报告退化成一段裸文本",
        "file": "scripts/hat_scan.py",
        "pattern": r'    lines\.append\("## 证据"\)',
        "replace": '    lines.append("## 明细")',
        "verify": ["-m", "unittest",
                   "tests.test_koumaozi.TestReportOutput.test_report_has_expected_sections"],
    },
    {
        "key": "weblint",
        "name": "网页抓 DOM 时 id 写错",
        "breaks": "getElementById 返回 null，页面不报错但整块数据不显示",
        "file": "docs/app.js",
        "pattern": r'document\.getElementById\("meta"\)',
        "replace": 'document.getElementById("meta-info")',
        "verify": [os.path.join(SCRIPTS, "web_lint.py")],
    },
    {
        "key": "webparity",
        "name": "网页端评分与 Python 分叉",
        "breaks": "网页给出的结论不可信，而且两边都不报错",
        "file": "docs/scan.js",
        "pattern": r"      if \(!used\) \{ continue; \}\n",
        "replace": "",
        "verify": [os.path.join(SCRIPTS, "web_parity.py")],
    },
    {
        "key": "webdoc",
        "name": "网页端 doc-mode 不降级",
        "breaks": "网页勾了「按文档解读」还是判满分，与命令行不一致",
        "file": "docs/scan.js",
        "pattern": r'    if \(slot === "heading" \|\| slot === "table"\) \{ '
                   r'return \{ role: "quoted", slot: slot \}; \}',
        "replace": '    if (false) { return { role: "quoted", slot: slot }; }',
        "verify": [os.path.join(SCRIPTS, "web_parity.py")],
    },
]

KEYS = [item["key"] for item in MUTATIONS]


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def read_text(path):
    # newline="" 是必须的：默认的 universal newlines 会把 \r\n 读成 \n，
    # 写回去就变成 LF —— 变异恢复"成功"了，但文件的行尾被悄悄换了，
    # 校验和自然对不上。读和写必须用同一套换行语义。
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return handle.read()


def write_text(path, content):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def run_verify(argv):
    """返回 (是否通过, 末尾几行输出)。脚手架本身崩了也算没抓到。"""
    proc = subprocess.run([sys.executable] + argv, cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    return proc.returncode == 0, tail[-4:]


def run_one(item, verbose=False):
    path = os.path.join(ROOT, item["file"])
    if not os.path.isfile(path):
        return "missing", [f"文件不存在: {item['file']}"]

    original = read_text(path)
    before = digest(path)
    mutated, count = re.subn(item["pattern"], item["replace"], original,
                             count=1, flags=re.S)
    if count != 1:
        return "anchor", [f"锚点在 {item['file']} 里匹配到 {count} 处，变异没打上"]

    try:
        write_text(path, mutated)
        passed, tail = run_verify(item["verify"])
    finally:
        write_text(path, original)
        # 恢复必须逐字节一致，否则下一次门禁跑的就是半变异过的源码
        if digest(path) != before:
            return "restore", [f"{item['file']} 恢复后内容对不上，工作区可能已损坏"]

    if passed:
        return "escaped", tail if verbose else tail[-2:]
    return "caught", []


def main(argv=None):
    sys.path.insert(0, SCRIPTS)
    import common
    common.ensure_utf8_stdout()

    parser = argparse.ArgumentParser(description="变异验证：门禁到底有没有在防东西")
    parser.add_argument("--only", default=None, help="逗号分隔的变异 key")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="漏网时打印完整输出")
    args = parser.parse_args(argv)

    if args.list:
        for item in MUTATIONS:
            print(f"{item['key']:<12} {item['name']}")
        return 0

    selected = MUTATIONS
    if args.only:
        wanted = [part.strip() for part in args.only.split(",") if part.strip()]
        unknown = [part for part in wanted if part not in KEYS]
        if unknown:
            raise SystemExit(f"没有这些变异: {', '.join(unknown)}（用 --list 看）")
        selected = [item for item in MUTATIONS if item["key"] in wanted]

    started = time.perf_counter()
    caught, problems = [], []
    for item in selected:
        status, detail = run_one(item, verbose=args.verbose)
        mark = {"caught": "PASS", "escaped": "FAIL", "anchor": "FAIL",
                "missing": "FAIL", "restore": "FAIL"}[status]
        note = ""
        if status == "caught":
            note = f"改回去就红 → 挡的是「{item['breaks']}」"
            caught.append(item["key"])
        elif status == "escaped":
            note = "变异后仍然通过，这条门禁没在防它"
            problems.append((item["key"], detail))
        else:
            problems.append((item["key"], detail))
        print(f"{mark}  {item['key']:<12} {item['name']}")
        if note:
            print(f"      {note}")
        for line in detail if status != "caught" else []:
            print(f"      | {line}")

    elapsed = round(time.perf_counter() - started, 2)
    print("-" * 66)
    if problems:
        print(f"变异验证  {len(caught)}/{len(selected)} 抓到  |  {len(problems)} 项漏网  ({elapsed}s)")
        for key, detail in problems:
            item = next(entry for entry in MUTATIONS if entry["key"] == key)
            print(f"  {key}: {detail[0] if detail else '无输出'}")
            print(f"    这道门禁本该挡住「{item['breaks']}」，把 "
                  f"{item['file']} 改回去它却不红——先修门禁，再谈功能")
        return 1
    print(f"变异验证  {len(caught)}/{len(selected)} 抓到  |  全部有效  ({elapsed}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
