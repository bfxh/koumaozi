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
    """只看 role=used 的命中。否认句（我没有收钱）和被引用（他说我是公知）不算攻击。

    kind=context 的样本断言的是"字面有帽子，但语境不算"：
    要求 raw（含降级）达到 min_raw，而 used 必须是 0。
    光有负样本（干净文本）证明不了降级逻辑，因为负样本压根没触发过词形。
    """
    attack = [f for f in findings if f.get("role", "used") == "used"]
    ids = [f["pattern_id"] for f in attack]
    raw = len(findings)
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

    min_raw = expect.get("min_raw", 0)
    if raw < min_raw:
        problems.append(f"原文词形命中 {raw} 处 < 下限 {min_raw}（预期有帽子字样但被判降级）")

    # 比 min_raw 更硬：必须是指定的那一顶被降级，而不是"恰好别的帽子没触发"
    downgraded_seen = {f["pattern_id"]: f.get("role", "used")
                       for f in findings if f.get("role", "used") != "used"}
    for need in expect.get("downgraded", []):
        if need not in downgraded_seen:
            fallback = "（它被判成了 used，降级没生效）" if need in ids else ""
            problems.append(f"{need} 应该被判 denied/quoted 却没进降级集{fallback}")

    low, high = expect.get("score_band", DEFAULT_BAND)
    score = stats["label_score"]
    if not low <= score <= high:
        problems.append(f"标签分 {score} 不在 [{low}, {high}]")

    return {
        "id": case["id"],
        "kind": case.get("kind", ""),
        "characters": chars,
        "raw_hits": raw,
        "ids": sorted(set(ids)),
        "roles": sorted({f.get("role", "used") for f in findings}),
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


def coverage(rows=None):
    """统计语料与连招示例对数据的覆盖。

    两个来源：
    - corpus：真正跑过断言的正样本（strong）
    - example：连招自带的示例，由单元测试保证能被识别（weak，但足以证明"这一式存在可命中的表达"）
    """
    rows = run() if rows is None else rows
    pat_strong, fam_strong, hat_strong, cmb_strong = {}, {}, {}, {}
    fam_of = {hat["id"]: hat["family"] for hat in common.flatten_hats()}
    kind_counts, role_cases = {}, {}

    for row in rows:
        if not row["passed"]:
            continue
        kind_counts[row["kind"]] = kind_counts.get(row["kind"], 0) + 1
        for role in row.get("roles", []):
            role_cases.setdefault(role, set()).add(row["id"])
        for pid in row["ids"]:
            if pid.startswith("PAT"):
                pat_strong.setdefault(pid, set()).add(row["id"])
            elif pid.startswith("HAT"):
                hat_strong.setdefault(pid, set()).add(row["id"])
                family = fam_of.get(pid)
                if family:
                    fam_strong.setdefault(family, set()).add(row["id"])
            elif pid.startswith("CMB"):
                cmb_strong.setdefault(pid, set()).add(row["id"])

    # 野外特征只统计"真跑过且通过"的样本：标了却没验证过的特征不算覆盖。
    passed_ids = {row["id"] for row in rows if row["passed"]}
    trait_counts = {}
    for case in common.load_corpus()["cases"]:
        if case["id"] not in passed_ids:
            continue
        for trait in case.get("traits", []):
            trait_counts[trait] = trait_counts.get(trait, 0) + 1

    pat_weak, cmb_weak = {}, {}
    compiled = hat_scan.compile_patterns()
    for combo in common.load_combos()["combos"]:
        findings, _ = hat_scan.scan_text(combo["id"], combo["example"], compiled)
        for item in findings:
            if item.get("role", "used") != "used":
                continue
            if item["pattern_id"].startswith("PAT"):
                pat_weak.setdefault(item["pattern_id"], set()).add(combo["id"] + "·示例")
            elif item["pattern_id"].startswith("CMB"):
                cmb_weak.setdefault(item["pattern_id"], set()).add(combo["id"] + "·示例")

    return {
        "patterns": {pid: sorted(pat_strong.get(pid, set()) | pat_weak.get(pid, set()))
                     for pid in [p["id"] for p in common.load_patterns()["patterns"]]},
        "pattern_strong": {k: sorted(v) for k, v in pat_strong.items()},
        "families": {k: sorted(v) for k, v in fam_strong.items()},
        "hats": {k: sorted(v) for k, v in hat_strong.items()},
        "combos": {cid: sorted(cmb_strong.get(cid, set()) | cmb_weak.get(cid, set()))
                   for cid in [c["id"] for c in common.load_combos()["combos"]]},
        "hats_uncovered": sorted(h["id"] for h in common.flatten_hats() if h["id"] not in hat_strong),
        "kinds": kind_counts,
        "roles": {k: sorted(v) for k, v in role_cases.items()},
        "traits": trait_counts,
        "traits_required": list(common.REQUIRED_TRAITS),
        "totals": {
            "patterns": len(common.load_patterns()["patterns"]),
            "families": len(common.family_map()),
            "hats": len(common.flatten_hats()),
            "combos": len(common.load_combos()["combos"]),
        },
    }


def coverage_problems(cov, min_family_cases=3, min_family_hats=2,
                      min_context_cases=6, min_role_cases=2):
    """覆盖门禁：漏掉任何一式，说明"这一式到底能不能被识别"没有证据。"""
    problems = []
    for pid, sources in cov["patterns"].items():
        if not sources:
            problems.append(f"句式 {pid} 没有任何语料或示例覆盖")
    for cid, sources in cov["combos"].items():
        if not sources:
            problems.append(f"连招 {cid} 没有任何语料或示例覆盖")

    hat_family = {}
    for hat in common.flatten_hats():
        hat_family.setdefault(hat["family"], set()).add(hat["id"])
    for family, hats in sorted(hat_family.items()):
        cases = cov["families"].get(family, [])
        if len(cases) < min_family_cases:
            problems.append(f"家族 {family} 只有 {len(cases)} 条语料，要求 ≥{min_family_cases}")
        hit_hats = {hid for hid in hats if hid in cov["hats"]}
        if len(hit_hats) < min_family_hats:
            problems.append(f"家族 {family} 只覆盖 {len(hit_hats)} 顶帽子，要求 ≥{min_family_hats}")

    # 降级逻辑（denied / quoted）必须有语料背书。
    # 干净负样本证明不了它——那些样本压根没触发词形，降级代码从头到尾没执行过。
    context_cases = cov.get("kinds", {}).get("context", 0)
    if context_cases < min_context_cases:
        problems.append(f"语境样本只有 {context_cases} 条，要求 ≥{min_context_cases}"
                        "（缺了它，denied/quoted 降级等于没被验证）")
    for role in ("denied", "quoted"):
        hit = cov.get("roles", {}).get(role, [])
        if len(hit) < min_role_cases:
            problems.append(f"role={role} 的语料只有 {len(hit)} 条，要求 ≥{min_role_cases}")
    return problems


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="回归语料门禁")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="打印每条的命中明细")
    parser.add_argument("--no-coverage", action="store_true", help="跳过覆盖门禁（仅调试用）")
    parser.add_argument("--min-family-cases", type=int, default=3)
    parser.add_argument("--min-family-hats", type=int, default=2)
    args = parser.parse_args(argv)

    rows = run()
    passed = [r for r in rows if r["passed"]]
    failed = [r for r in rows if not r["passed"]]
    attack = [r for r in rows if r["kind"] == "attack"]
    neutral = [r for r in rows if r["kind"] == "neutral"]
    context = [r for r in rows if r["kind"] == "context"]

    cov = coverage(rows)
    cov_problems = [] if args.no_coverage else coverage_problems(
        cov, args.min_family_cases, args.min_family_hats)

    payload = {
        "tool": "corpus_check",
        "total": len(rows),
        "passed": len(passed),
        "failed": len(failed),
        "attack_pass": f"{sum(1 for r in attack if r['passed'])}/{len(attack)}",
        "neutral_pass": f"{sum(1 for r in neutral if r['passed'])}/{len(neutral)}",
        "context_pass": f"{sum(1 for r in context if r['passed'])}/{len(context)}",
        "coverage": {
            "patterns_covered": sum(1 for v in cov["patterns"].values() if v),
            "patterns_total": cov["totals"]["patterns"],
            "patterns_strong_covered": len(cov["pattern_strong"]),
            "combos_covered": sum(1 for v in cov["combos"].values() if v),
            "combos_total": cov["totals"]["combos"],
            "hats_covered": len(cov["hats"]),
            "hats_total": cov["totals"]["hats"],
            "hats_uncovered": cov["hats_uncovered"],
            "families": {k: len(v) for k, v in sorted(cov["families"].items())},
            "traits": cov["traits"],
            "traits_required": cov["traits_required"],
            "problems": cov_problems,
        },
        "cases": rows,
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if not failed and not cov_problems else 1

    print(f"语料 {len(rows)} 条  |  正样本 {payload['attack_pass']}  "
          f"负样本 {payload['neutral_pass']}  语境样本 {payload['context_pass']}")
    print("-" * 66)
    for row in rows:
        mark = "PASS" if row["passed"] else "FAIL"
        ids = ",".join(row["ids"]) if row["ids"] else "-"
        raw = f" raw={row['raw_hits']}" if row.get("raw_hits") else ""
        print(f"{mark}  {row['id']}  {row['label_score']:>3}分  {ids}{raw}")
        if args.verbose or not row["passed"]:
            for problem in row["problems"]:
                print(f"      × {problem}")
    print("-" * 66)
    report = payload["coverage"]
    print(f"覆盖  句式 {report['patterns_covered']}/{report['patterns_total']} "
          f"(仅语料 {report['patterns_strong_covered']})   "
          f"连招 {report['combos_covered']}/{report['combos_total']}   "
          f"帽子 {report['hats_covered']}/{report['hats_total']}")
    print("家族语料数: " + "  ".join(f"{k}={v}" for k, v in report["families"].items()))
    traits = report["traits"]
    hit_traits = [t for t in report["traits_required"] if traits.get(t)]
    print(f"野外特征 {len(hit_traits)}/{len(report['traits_required'])}: "
          + "  ".join(f"{t}={traits[t]}" for t in report["traits_required"] if traits.get(t)))
    missing_traits = [t for t in report["traits_required"] if not traits.get(t)]
    if missing_traits:
        print(f"  × 这些野外特征没有已通过的语料: {', '.join(missing_traits)}")
    uncovered = [pid for pid, v in cov["patterns"].items() if v and not cov["pattern_strong"].get(pid)]
    if uncovered:
        print(f"仅靠示例覆盖（无独立语料）: {', '.join(uncovered)}")
    print(f"帽子覆盖 {report['hats_covered']}/{report['hats_total']}："
          "帽子匹配是精确词形，不存在识别不出的风险（别名唯一性由 verify_data 拦截），"
          "所以帽子覆盖是代表性抽样而非能力缺口；门禁只要求每家族 ≥2 顶有语料。")
    if args.verbose and cov["hats_uncovered"]:
        print(f"未覆盖帽子（{len(cov['hats_uncovered'])} 顶）: {', '.join(cov['hats_uncovered'])}")
    for problem in cov_problems:
        print(f"  × {problem}")
    print("-" * 66)
    if failed or cov_problems:
        print(f"失败：{len(failed)} 条语料不符，{len(cov_problems)} 项覆盖不足")
        return 1
    print("通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
