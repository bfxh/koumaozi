#!/usr/bin/env python3
"""改稿对比：同一段文字改前改后，标签化程度是升了还是降了。

用法:
    python3 scripts/hat_diff.py --before draft-v1.md --after draft-v2.md
    python3 scripts/hat_diff.py --before-text "标准公知体，收钱的吧" --after-text "这个结论我不同意，具体是第二段的样本有问题"
    python3 scripts/hat_diff.py --before a.md --after b.md --json
    python3 scripts/hat_diff.py --before a.md --after b.md --must-drop 10   # 门禁：至少降 10 分

--before / --after 参数：路径存在则读文件，否则当作文本直接扫描。

退出码: 0 通过；1 门禁未过（--must-drop / --max-score）
"""
import argparse
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import hat_scan  # noqa: E402


def id_names():
    table = {}
    for hat in common.flatten_hats():
        table[hat["id"]] = hat["name"]
    for pattern in common.load_patterns()["patterns"]:
        table[pattern["id"]] = pattern["name"]
    for combo in common.load_combos()["combos"]:
        table[combo["id"]] = combo["name"]
    return table


FILE_EXT_RE = re.compile(r"^[^\n]{1,200}\.(?:md|markdown|txt|rst|text)$", re.I)


def looks_like_path(value):
    """判"这看起来是路径"——不然打字打错一个文件名，会被当成正文分析。

    区分依据：带常见文档后缀，或者含路径分隔符。真人写的短句不会长成这样。
    """
    value = value.strip()
    if FILE_EXT_RE.match(value):
        return True
    return os.sep in value or (os.altsep and os.altsep in value)


def load_source(value, label):
    if os.path.isfile(value):
        with open(value, "r", encoding="utf-8") as fh:
            return fh.read(), common.relpath(value)
    if looks_like_path(value):
        # 静默把 "draft-v2.md" 当正文分析，用户会以为对比了两个文件。
        # 这种错误必须炸出来，不能给出一个看着正常的错误结果。
        raise FileNotFoundError(
            f"{label} 看着是文件路径但文件不存在: {value}"
            "（确实要当正文传入请改用 --before-text / --after-text）")
    return value, label


def analyse(value, label, compiled):
    raw, name = load_source(value, label)
    findings, chars = hat_scan.scan_text(name, raw, compiled)
    stats = hat_scan.score(findings, chars)
    return {"source": name, "stats": stats, "findings": findings}


def diff_counts(before, after, names):
    b = Counter(f["pattern_id"] for f in before["findings"])
    a = Counter(f["pattern_id"] for f in after["findings"])

    removed = []
    for key, count in sorted((b - a).items()):
        removed.append({"id": key, "name": names.get(key, key), "count": count})
    added = []
    for key, count in sorted((a - b).items()):
        added.append({"id": key, "name": names.get(key, key), "count": count})
    return removed, added


def first_hits(findings, ids):
    """给每个被消除/新增的 id 找一句原句，方便定位改在哪。"""
    wanted = set(ids)
    out = {}
    for item in findings:
        if item["pattern_id"] in wanted and item["pattern_id"] not in out:
            out[item["pattern_id"]] = {"line": item["line"], "sentence": item["sentence"]}
    return out


def verdict(before_stats, after_stats, removed, added):
    delta = after_stats["label_score"] - before_stats["label_score"]
    if delta <= -5:
        word = "改善"
    elif delta >= 5:
        word = "恶化"
    else:
        word = "基本持平"

    notes = []
    if delta <= -5 and added:
        notes.append(f"总分降了，但新引入了 {len(added)} 类命中——可能是换了一顶帽子")
    if delta >= 5 and removed:
        notes.append(f"总分升了，虽然去掉了 {len(removed)} 类命中——可能是加了更重的招")
    if after_stats["combo_hits"] > before_stats["combo_hits"]:
        notes.append("连招数增加，封死的回路面变多，实际观感会比分数更差")
    return {"word": word, "delta": delta, "notes": notes}


def emit_text(before, after, removed, added, names, result):
    bs, as_ = before["stats"], after["stats"]
    print(f"改稿对比  {before['source']}  →  {after['source']}")
    print("=" * 68)
    print(f"{'项目':<16}{'改前':>10}{'改后':>10}{'变化':>12}")
    rows = [
        ("字数", "chars", ""),
        ("帽子", "hat_hits", ""),
        ("句式", "pattern_hits", ""),
        ("连招", "combo_hits", ""),
        ("Critical", "critical_hits", ""),
        ("标签分", "label_score", ""),
    ]
    for name, key, _ in rows:
        b, a = bs[key], as_[key]
        delta = a - b
        arrow = "+" if delta > 0 else ("" if delta == 0 else "")
        print(f"{name:<16}{b:>10}{a:>10}{arrow + str(delta) if delta else '0':>12}")
    print("-" * 68)
    print(f"判定：{result['word']}（标签分 {result['delta']:+d}）")
    for note in result["notes"]:
        print(f"  注意：{note}")

    if removed:
        print()
        print(f"消除 {len(removed)} 类：")
        for item in removed:
            print(f"  - {item['id']} {item['name']} ×{item['count']}")

    if added:
        print()
        print(f"新增 {len(added)} 类：")
        for item in added:
            print(f"  + {item['id']} {item['name']} ×{item['count']}")

    b_hits = first_hits(before["findings"], [i["id"] for i in removed])
    a_hits = first_hits(after["findings"], [i["id"] for i in added])
    if b_hits or a_hits:
        print()
        print("定位：")
        for tag, hits, side in (("-", b_hits, "改前"), ("+", a_hits, "改后")):
            grouped = {}
            for key, hit in hits.items():
                grouped.setdefault(hit["sentence"], {"line": hit["line"], "ids": []})
                grouped[hit["sentence"]]["ids"].append(key)
            for sentence, info in grouped.items():
                print(f"  [{tag}] {side} L{info['line']}  {sentence}")
                print(f"       {', '.join(sorted(info['ids']))}")


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="改稿前后的标签化程度对比")
    parser.add_argument("--before", help="改前：文件路径或文本")
    parser.add_argument("--before-text", help="改前文本（显式）")
    parser.add_argument("--after", help="改后：文件路径或文本")
    parser.add_argument("--after-text", help="改后文本（显式）")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--must-drop", type=int, default=None,
                        help="门禁：标签分至少要降这么多，否则退出码 1")
    parser.add_argument("--max-score", type=int, default=None,
                        help="门禁：改后的标签分不得超过此值，否则退出码 1")
    args = parser.parse_args(argv)

    before_value = args.before_text if args.before_text is not None else args.before
    after_value = args.after_text if args.after_text is not None else args.after
    if before_value is None or after_value is None:
        parser.error("需要 --before/--before-text 与 --after/--after-text 两侧输入")

    compiled = hat_scan.compile_patterns()
    try:
        before = analyse(before_value, "<before>", compiled)
        after = analyse(after_value, "<after>", compiled)
    except FileNotFoundError as exc:
        # 用 argparse 的报错通道：打出 usage + 干净的错误，不要甩 traceback
        parser.error(str(exc))
        return 2

    names = id_names()
    removed, added = diff_counts(before, after, names)
    result = verdict(before["stats"], after["stats"], removed, added)

    failed = []
    if args.must_drop is not None and -result["delta"] < args.must_drop:
        failed.append(f"标签分只降了 {-result['delta']}，要求至少 {args.must_drop}")
    if args.max_score is not None and after["stats"]["label_score"] > args.max_score:
        failed.append(f"改后标签分 {after['stats']['label_score']} 超过上限 {args.max_score}")

    if args.json:
        payload = {
            "tool": "hat_diff",
            "before": before,
            "after": after,
            "removed": removed,
            "added": added,
            "verdict": result,
            "gates": {"must_drop": args.must_drop, "max_score": args.max_score, "failed": failed},
            "passed": not failed,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if not failed else 1

    emit_text(before, after, removed, added, names, result)
    if failed:
        print()
        for item in failed:
            print(f"门禁未过：{item}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
