#!/usr/bin/env python3
"""网页端与 Python 端对拍：同一段文本，两边必须判出同一个结论。

网页是纯静态的，规则得在浏览器里跑，所以判定逻辑在 JS 里重写了一遍。
重写就有分叉风险，而且分叉是**静默**的——网页照样能打开、照样出结果，
只是判得和命令行不一样。所以这里拿真实语料逐条对拍：

    规则同步（docs/rules.js 是否还等于 data/ 派生物）
    → 102 条回归语料 + 文档样例 + 若干刁钻输入
    → 比对 字数 / 标签分 / 各类命中数 / 每条命中的 (类型, 编号, 命中片段, 严重度, 角色)

不比 offset：JS 的字符串下标按 UTF-16 计，Python 按码点计，遇到 emoji 会差一两位。
偏移只在自己实现内部用来定位高亮，跨实现对它没有意义。

用法:
    python3 scripts/web_parity.py
    python3 scripts/web_parity.py --verbose
    python3 scripts/web_parity.py --json

退出码: 0 一致（或缺 node 跳过）；1 有分歧。
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_web  # noqa: E402
import common  # noqa: E402
import hat_scan  # noqa: E402

RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_parity_runner.js")
TIMEOUT = 180

# 语料之外补几条：这些地方最容易两端判得不一样
EXTRA_CASES = [
    ("XTRA-code-fence", "```\n典型的公知体，一条多少钱？散了吧。\n```\n以上是待分析的样例代码。"),
    ("XTRA-inline-code", "他说这行日志 `典型的公知体` 是误报。"),
    ("XTRA-rhetoric", "这不是公知是什么？"),
    ("XTRA-quote-zh", "有人留言：“标准水军，散了吧。”我没这么说过。"),
    ("XTRA-quote-ascii", '文章引用了那句 "又一个民科" 之后才展开反驳。'),
    ("XTRA-no-punct", "标准公知体散了吧不用看了"),
    ("XTRA-multi-sentence", "你不懂就别说了。这种水军一条多少钱？收了钱还装理中客。"),
    ("XTRA-long", "这里是一段很长的正常叙述。" * 120 + "然后突然来一句：典型的水军。"),
    ("XTRA-emoji", "😀 这种公知体，散了吧。"),
    ("XTRA-empty", ""),
    ("XTRA-spaces", "    \n\n   "),
    # doc-mode 的四种槽位。默认模式下四条全部命中；勾上 doc-mode 之后
    # 标题和表格要降，引用块和普通列表项不能降。浏览器端是这套规则的
    # 第二份实现，不给它专门的对拍用例，`webdoc` 那条变异就抓不到。
    ("XTRA-doc-heading", "### HAT-F1-01 公知\n\n这段正文在讲这个词的来历，没在骂人。"),
    ("XTRA-doc-table", "| 家族 | 帽子 |\n|---|---|\n| 立场叛徒 | 公知、殖人、小粉红 |\n"),
    ("XTRA-doc-list", "- CMB-03 的纸环是双标（要列差异）\n- 你这种双标的东西就是欠骂\n"),
    ("XTRA-doc-quote", "> 说这话的，标准公知体，不用看了。\n"),
]


def node_path():
    for name in ("node", "nodejs"):
        found = shutil.which(name)
        if found:
            return found
    return os.environ.get("KOUMAOZI_NODE") or None


def collect_cases():
    """每条用例跑两遍：默认模式与 `--doc-mode`。

    doc-mode 在浏览器端是第二份实现（`scan.js` 的 `markdownSlot` / `docModeRole`），
    只对拍默认模式等于把它放过。纯文本用例两边结果本来就一样，但 md 文件
    （标题、表格）正好能把降级路径也逐条比一遍——多跑一倍用例，成本几毫秒。
    """
    base = []
    for case in common.load_corpus()["cases"]:
        base.append({"id": case["id"], "text": case["text"]})
    example_dir = os.path.join(common.REPO_ROOT, "examples")
    if os.path.isdir(example_dir):
        for name in sorted(os.listdir(example_dir)):
            path = os.path.join(example_dir, name)
            if os.path.isfile(path) and name.endswith(".md"):
                with open(path, "r", encoding="utf-8") as fh:
                    base.append({"id": "examples/" + name, "text": fh.read()})
    base.extend({"id": case_id, "text": text} for case_id, text in EXTRA_CASES)

    cases = []
    for case in base:
        cases.append(dict(case, docMode=False))
        cases.append({"id": case["id"] + "@doc", "text": case["text"], "docMode": True})
    return cases


def python_side(cases):
    compiled = hat_scan.compile_patterns()
    results = []
    for case in cases:
        findings, chars = hat_scan.scan_text("<parity>", case["text"], compiled,
                                             doc_mode=case.get("docMode", False))
        stats = hat_scan.score(findings, chars)
        results.append({
            "id": case["id"],
            "chars": chars,
            "stats": stats,
            "findings": [
                {"kind": item["kind"], "pattern_id": item["pattern_id"],
                 "matched": item["matched"], "severity": item["severity"],
                 "role": item["role"]}
                for item in findings
            ],
        })
    return results


def js_side(cases, node):
    payload = json.dumps([{"id": case["id"], "text": case["text"],
                           "docMode": case.get("docMode", False)} for case in cases],
                         ensure_ascii=False)
    proc = subprocess.run([node, RUNNER], input=payload, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"node 侧跑不起来（退出码 {proc.returncode}）: "
                           f"{(proc.stderr or '').strip()[:400]}")
    return json.loads(proc.stdout)


def signature(findings):
    """把命中折成可比较的签名。比集合不比顺序：两边遍历顺序一致，但顺序不该影响结论。"""
    return sorted((item["kind"], item["pattern_id"], item["matched"],
                   item["severity"], item["role"]) for item in findings)


STAT_KEYS = ("label_score", "hat_hits", "pattern_hits", "combo_hits", "critical_hits")


def compare(py_rows, js_rows):
    js_by_id = {row["id"]: row for row in js_rows}
    problems = []
    for py_row in py_rows:
        js_row = js_by_id.get(py_row["id"])
        if js_row is None:
            problems.append({"id": py_row["id"], "field": "整条", "python": "有结果",
                             "javascript": "缺结果"})
            continue
        if py_row["chars"] != js_row["chars"]:
            problems.append({"id": py_row["id"], "field": "字数",
                             "python": py_row["chars"], "javascript": js_row["chars"]})
        for key in STAT_KEYS:
            if py_row["stats"].get(key) != js_row["stats"].get(key):
                problems.append({"id": py_row["id"], "field": key,
                                 "python": py_row["stats"].get(key),
                                 "javascript": js_row["stats"].get(key)})
        py_sig = signature(py_row["findings"])
        js_sig = signature(js_row["findings"])
        if py_sig != js_sig:
            problems.append({
                "id": py_row["id"], "field": "命中明细",
                "python": [list(item) for item in py_sig],
                "javascript": [list(item) for item in js_sig],
            })
    return problems


def run(verbose=False):
    sync = build_web.check()
    report = {"sync": sync, "cases": 0, "problems": [], "skipped": None}
    if sync["problems"]:
        report["problems"] = [{"id": "rules.js", "field": "规则同步",
                               "python": "已过期", "javascript": sync["problems"][0]}]
        return report

    node = node_path()
    if not node:
        report["skipped"] = "缺 node（网页端跑不了，对拍无从谈起）"
        return report

    cases = collect_cases()
    report["cases"] = len(cases)
    py_rows = python_side(cases)
    try:
        js_rows = js_side(cases, node)
    except (RuntimeError, ValueError) as exc:
        report["problems"] = [{"id": "runner", "field": "执行",
                               "python": "-", "javascript": str(exc)}]
        return report
    report["problems"] = compare(py_rows, js_rows)
    return report


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="网页端与 Python 端对拍")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    report = run(args.verbose)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if not report["problems"] else 1

    if report["skipped"]:
        print(f"网页端对拍  跳过：{report['skipped']}")
        return 0

    print(f"网页端对拍  {report['cases']} 条用例  |  不一致 {len(report['problems'])} 处")
    for problem in report["problems"][:10]:
        print(f"  × {problem['id']}  {problem['field']}")
        print(f"      Python: {problem['python']}")
        print(f"      JS    : {problem['javascript']}")
    if len(report["problems"]) > 10:
        print(f"  … 另有 {len(report['problems']) - 10} 处")
    if report["problems"]:
        print("两端判得不一样，网页的结论就不可信了。先看 docs/scan.js 与 hat_scan.py 的差异")
        return 1
    print("通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
