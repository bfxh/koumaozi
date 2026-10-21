#!/usr/bin/env python3
"""把 data/ 与 common.py 里的常量导出成一份网页端可直接 <script> 引入的规则文件。

为什么要生成而不是手写一份 JS 数据：手写就会分叉。改了帽子词条、加了句式，
网页端还在用三个月前那份，界面上看起来一切正常，只是判得不对——没有任何报错。

唯一真源是 data/*.json 和 common.py 里的常量，docs/rules.js 是派生物：
    python3 scripts/build_web.py            # 重新生成
    python3 scripts/build_web.py --check    # 只检查是否与真源同步（门禁用）

退出码: 0 一致（或已生成）；1 不同步；2 真源读不了。
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

DEFAULT_OUT = os.path.join(common.REPO_ROOT, "docs", "rules.js")

BANNER = """/* 由 scripts/build_web.py 从 data/*.json 与 scripts/common.py 生成，请勿手改。
 *
 * 改了帽子词条、句式、连招或降级词表，都要重新生成：
 *     python3 scripts/build_web.py
 * 忘了重新生成会被门禁拦住（gate.py 的 web 一道），不会静默发旧规则。
 */
"""


def payload():
    """网页端需要的全部规则。字段名尽量与 Python 侧同名，便于对拍时肉眼比对。"""
    hats = common.load_hats()
    patterns = common.load_patterns()
    combos = common.load_combos()
    corpus = common.load_corpus()
    return {
        "version": common.read_version(),
        "families": hats["families"],
        "hats": hats["hats"],
        "patterns": patterns["patterns"],
        "combos": combos["combos"],
        "corpus": [
            {"id": case["id"], "kind": case["kind"], "text": case["text"],
             "expect": case.get("expect", {})}
            for case in corpus["cases"]
        ],
        # 这几个词表在 common.py 里是代码常量，网页端也要一模一样，
        # 否则"强化词"和"降级前缀"两边判得不一样，同一句话两个结论。
        "amplifiers": list(common.AMPLIFIERS),
        "negationPrefixes": list(common.NEGATION_PREFIXES),
        "metaPrefixes": list(common.META_PREFIXES),
        "quotePairs": [list(pair) for pair in common.QUOTE_PAIRS],
        "straightQuotes": list(common.STRAIGHT_QUOTES),
        "rhetoricalSubjects": list(common.RHETORICAL_SUBJECTS),
        "clauseBreaks": list(common.CLAUSE_BREAKS),
        "windows": {"amplifier": 24, "role": 8, "roleRight": 12, "combo": 300},
    }


def render(data=None):
    data = data or payload()
    body = json.dumps(data, ensure_ascii=False, indent=1, sort_keys=False)
    return (
        BANNER
        + "(function (root, factory) {\n"
        + '  if (typeof module === "object" && module.exports) { module.exports = factory(); }\n'
        + "  else { root.KOUMAOZI_RULES = factory(); }\n"
        + '})(typeof globalThis !== "undefined" ? globalThis : this, function () {\n'
        + "  return " + body.replace("\n", "\n  ") + ";\n"
        + "});\n"
    )


def build(out_path=None):
    out_path = out_path or DEFAULT_OUT
    text = render()
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    data = payload()
    return {"path": out_path, "bytes": len(text.encode("utf-8")),
            "hats": len(data["hats"]), "patterns": len(data["patterns"]),
            "combos": len(data["combos"]), "corpus": len(data["corpus"])}


def check(out_path=None):
    """只比对，不写。不同步就报"重新生成"，不替人偷偷改文件。"""
    out_path = out_path or DEFAULT_OUT
    if not os.path.isfile(out_path):
        return {"path": out_path, "problems": [f"{out_path} 不存在，跑 python3 scripts/build_web.py"]}
    with open(out_path, "r", encoding="utf-8") as fh:
        current = fh.read()
    expected = render()
    if current == expected:
        return {"path": out_path, "problems": []}
    return {"path": out_path, "problems": [
        "docs/rules.js 与 data/ 或 common.py 不同步（网页会用旧规则判，且不报错）",
        "重新生成: python3 scripts/build_web.py",
    ]}


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="生成网页端规则文件")
    parser.add_argument("--out", default=None, help=f"输出路径，默认 {DEFAULT_OUT}")
    parser.add_argument("--check", action="store_true", help="只检查是否与真源同步")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.check:
        result = check(args.out)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif result["problems"]:
            for problem in result["problems"]:
                print(f"× {problem}")
        else:
            print(f"规则文件与真源一致  {os.path.relpath(result['path'], common.REPO_ROOT)}")
        return 0 if not result["problems"] else 1

    built = build(args.out)
    if args.json:
        print(json.dumps(built, ensure_ascii=False, indent=2))
    else:
        print(f"生成 {os.path.relpath(built['path'], common.REPO_ROOT)}  "
              f"{built['bytes'] / 1024:.1f} KiB  "
              f"帽子 {built['hats']} / 句式 {built['patterns']} / 连招 {built['combos']} / "
              f"语料 {built['corpus']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
