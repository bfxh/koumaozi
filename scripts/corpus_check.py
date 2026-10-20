#!/usr/bin/env python3
"""回归语料门禁：正样本该抓的必须抓到，负样本一个都不许抓。

用法:
    python3 scripts/corpus_check.py
    python3 scripts/corpus_check.py --json
    python3 scripts/corpus_check.py --verbose        # 打印每条的命中明细

退出码: 0 全部通过；1 有 case 不符合预期。
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import hat_scan  # noqa: E402

DEFAULT_BAND = [0, 100]


def evaluate(case, findings, chars):
    """只看 role=used 的命中。否认句（我没有收钱）和被引用（他说我是公知）不算攻击。"""
    attack = [f for f in findings if f.get("role", "used") == "used"]
    ids = [f["pattern_id"] for f in attack]
    stats = hat_scan.score(attack, chars)
    expect = case.get("expect", {})
    problems = []

    for need in expect.get("must_include", []):
        if need not in ids:
            problems.append(f"缺 {need}")
    for bad in expect.get("must_exclude", []):
        if bad in ids:
            problems.append(f"不该有 {bad}")

    min_hits = expect.get("min_hits", 0)
    if len(ids) < min_hits:
        problems.append(f"命中 {len(ids)} 处 < 下限 {min_hits}")
    max_hits = expect.get("max_hits")
    if max_hits is not None and len(ids) > max_hits:
        problems.append(f"命中 {len(ids)} 处 > 上限 {max_hits}")

    low, high = expect.get("score_band", DEFAULT_BAND)
    score = stats["label_score"]
    if not low <= score <= high:
        problems.append(f"标签分 {score} 不在 [{low}, {high}]")

    return {
        "id": case["id"],
        "kind": case.get("kind", ""),
        "characters": chars,
        "ids": sorted(set(ids)),
        "label_score": score,
        "problems": problems,
        "passed": not problems,
    }


def run():
    compiled = hat_scan.compile_patterns()
    cases = common.load_corpus()["cases"]
    rows = []
    for case in cases:
        findings, chars = hat_scan.scan_text(case["id"], case["text"], compiled)
        rows.append(evaluate(case, findings, chars))
    return rows


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="回归语料门禁")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="打印每条的命中明细")
    args = parser.parse_args(argv)

    rows = run()
    passed = [r for r in rows if r["passed"]]
    failed = [r for r in rows if not r["passed"]]
    attack = [r for r in rows if r["kind"] == "attack"]
    neutral = [r for r in rows if r["kind"] == "neutral"]

    payload = {
        "tool": "corpus_check",
        "total": len(rows),
        "passed": len(passed),
        "failed": len(failed),
        "attack_pass": f"{sum(1 for r in attack if r['passed'])}/{len(attack)}",
        "neutral_pass": f"{sum(1 for r in neutral if r['passed'])}/{len(neutral)}",
        "cases": rows,
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if not failed else 1

    print(f"语料 {len(rows)} 条  |  正样本 {payload['attack_pass']}  负样本 {payload['neutral_pass']}")
    print("-" * 66)
    for row in rows:
        mark = "PASS" if row["passed"] else "FAIL"
        ids = ",".join(row["ids"]) if row["ids"] else "-"
        print(f"{mark}  {row['id']}  {row['label_score']:>3}分  {ids}")
        if args.verbose or not row["passed"]:
            for problem in row["problems"]:
                print(f"      × {problem}")
    print("-" * 66)
    print("通过" if not failed else f"失败 {len(failed)} 条")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
