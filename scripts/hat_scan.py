#!/usr/bin/env python3
"""扣帽子扫描器：定位文本中的帽子标签与攻击句式，输出结构化报告。

用法:
    python3 scripts/hat_scan.py --text "这种公知体，收钱办事的吧？"
    python3 scripts/hat_scan.py --file draft.md --json
    python3 scripts/hat_scan.py --target docs/ --min-severity Warning

退出码: 0 正常；1 参数错误；2 无输入。
"""
import argparse
import json
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

TEXT_SUFFIXES = (".md", ".txt", ".markdown", ".rst")
SEVERITY_ORDER = {"Info": 1, "Warning": 2, "Critical": 3}


def compile_patterns():
    compiled = []
    for pattern in common.load_patterns()["patterns"]:
        regexes = [re.compile(expr) for expr in pattern.get("detect_regex", [])]
        compiled.append((pattern, regexes))
    return compiled


def iter_inputs(args):
    if args.text:
        yield "<inline>", args.text
        return
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            yield args.file, fh.read()
        return
    for root, _dirs, files in os.walk(args.target):
        for name in sorted(files):
            if not name.lower().endswith(TEXT_SUFFIXES):
                continue
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8") as fh:
                yield path, fh.read()


def scan_text(path, raw, compiled_patterns, strip_code=True, window=300, doc_mode=False):
    text = common.strip_code(raw) if strip_code else raw
    chars = len(re.sub(r"\s", "", text))
    hats = common.flatten_hats()
    findings = []

    def settle(text_body, start, end):
        """角色判定 + doc-mode 降级。返回 (role, struct_slot, 被降级)。"""
        role = common.context_role(text_body, start, end)
        slot = ""
        demoted = False
        if doc_mode:
            before = role
            role, slot = common.doc_mode_role(role, text_body, start)
            demoted = role != before
        return role, slot, demoted

    for sentence in common.split_sentences(text):
        body = sentence["text"]

        for hat in hats:
            tokens = [hat["name"]] + list(hat.get("aliases", []))
            position = -1
            token = ""
            for candidate in tokens:
                index = body.find(candidate)
                if index >= 0 and (position < 0 or index < position):
                    position = index
                    token = candidate
            if position < 0:
                continue
            absolute = sentence["start"] + position
            amplifiers = common.nearby_amplifier(text, absolute, absolute + len(token))
            role, slot, demoted = settle(text, absolute, absolute + len(token))
            findings.append({
                "kind": "hat",
                "pattern_id": hat["id"],
                "name": hat["name"],
                "matched": token,
                "family": hat["family"],
                "severity": common.severity_for(hat["intensity"], amplifiers, role),
                "location": path,
                "line": text.count("\n", 0, absolute) + 1,
                "offset": absolute,
                "sentence": body,
                "amplifiers": amplifiers,
                "role": role,
                "struct": slot,
                "demoted": demoted,
                "mechanism": hat["mechanism"],
                "remedy": hat["counter"][0],
            })

        for pattern, regexes in compiled_patterns:
            for regex in regexes:
                match = regex.search(body)
                if not match:
                    continue
                absolute = sentence["start"] + match.start()
                amplifiers = common.nearby_amplifier(text, absolute, absolute + len(match.group(0)))
                role, slot, demoted = settle(text, absolute, absolute + len(match.group(0)))
                findings.append({
                    "kind": "pattern",
                    "pattern_id": pattern["id"],
                    "name": pattern["name"],
                    "matched": match.group(0),
                    "family": pattern.get("family_hint", ""),
                    "severity": common.severity_for(2, amplifiers, role),
                    "location": path,
                    "line": text.count("\n", 0, absolute) + 1,
                    "offset": absolute,
                    "sentence": body,
                    "amplifiers": amplifiers,
                    "role": role,
                    "struct": slot,
                    "demoted": demoted,
                    "mechanism": pattern["essence"],
                    "remedy": pattern["counter"][0],
                })
                break

    findings.extend(detect_combos(findings, common.load_combos()["combos"], window=window))
    return findings, chars


def detect_combos(findings, combos, window=300):
    """连招检测：每一环是候选集（PAT 或 HAT 任一命中即可），按顺序落在 window 字内算连招。

    单式好拆，连招难拆——因为拆掉一环，其余环仍在生效。所以连招单独计分，
    且 seal_degree >= 3 的直接按 Critical 处理。

    只收 role == "used" 的命中。连招的定义是"作者把回应路径一环环堵死"，
    这要求每一环都是作者自己打的。早先没这个过滤，讲解文章里挨着引用的
    三段句式能被拼成一个 Critical 连招——被引用的话不构成封堵。
    """
    usable = [f for f in findings
              if f["kind"] in ("pattern", "hat") and f.get("role", "used") == "used"]
    if not usable:
        return []

    by_id = {}
    for item in usable:
        by_id.setdefault(item["pattern_id"], []).append(item)

    combos_hit = []
    for combo in combos:
        sequence = combo.get("sequence", [])
        if not sequence:
            continue
        stages = [stage if isinstance(stage, list) else [stage] for stage in sequence]
        if any(not any(cand in by_id for cand in stage) for stage in stages):
            continue

        first_candidates = [f for cand in stages[0] for f in by_id.get(cand, [])]
        if not first_candidates:
            continue

        # 取能让整串最紧凑的一组出现位置
        best = None
        for anchor in sorted(first_candidates, key=lambda f: f["offset"]):
            chosen = [anchor]
            ok = True
            for stage in stages[1:]:
                pool = [f for cand in stage for f in by_id.get(cand, [])]
                later = [f for f in pool if f["offset"] > chosen[-1]["offset"]]
                if not later:
                    ok = False
                    break
                chosen.append(min(later, key=lambda f: f["offset"]))
            if not ok:
                continue
            span = chosen[-1]["offset"] - chosen[0]["offset"]
            if span <= window and (best is None or span < best[0]):
                best = (span, chosen)
        if best is None:
            continue

        span, chosen = best
        first = chosen[0]
        severity = "Critical" if combo.get("seal_degree", 0) >= 3 else "Warning"
        combos_hit.append({
            "kind": "combo",
            "pattern_id": combo["id"],
            "name": combo["name"],
            "matched": " → ".join(item["pattern_id"] for item in chosen),
            "family": first.get("family", ""),
            "severity": severity,
            "location": first["location"],
            "line": first["line"],
            "offset": first["offset"],
            "sentence": " / ".join(dict.fromkeys(item["sentence"] for item in chosen)),
            "amplifiers": sorted({a for item in chosen for a in item.get("amplifiers", [])}),
            "role": "used",
            "mechanism": f"连招 {combo['id']}：{first.get('mechanism', '')} 后续接 {' / '.join(item['name'] for item in chosen[1:])}，封死 {combo.get('seal_degree', '?')} 向回应路径",
            "remedy": combo.get("break_steps", ["无"])[0],
            "members": [item["pattern_id"] for item in chosen],
            "span": span,
            "break_at": combo.get("break_at", ""),
        })
    return combos_hit


def score(findings, chars, demoted=0, slots=None):
    """密度用对数压缩，短文本分母下限 1000 字。

    38 字里 3 处攻击不能直接等于"满分级重度"——那是篇幅造成的假象。
    实际情况：2 处/38 字 ≈ 57 分，5 处/2000 字 ≈ 31 分，5 处/10000 字 ≈ 31 分。
    展示用的每千字密度按真实字数算，不掺下限。

    **只统计 role == "used"**。这是这个函数唯一容易写错的地方，也真写错过一次：
    早先把 quoted / denied 的命中一起算了密度，于是 SKILL.md 里 56 处命中
    有 51 处是被引用的、3 处是被否认的，2 处才是真在用，分数照样 76 分
    「论证基本让位于身份定性」。一篇《我没有收钱，也不是公知》的澄清文
    和一篇真攻击文拿同样的分，降级 severity 而不降密度等于没降。
    被引用和被否认的命中另计，不参与打分。
    """
    real_kilo = max(chars, 1) / 1000.0
    scoring_kilo = max(chars, 1000) / 1000.0
    used = [f for f in findings if f.get("role", "used") == "used"]
    hat_hits = [f for f in used if f["kind"] == "hat"]
    pattern_hits = [f for f in used if f["kind"] == "pattern"]
    combo_hits = [f for f in used if f["kind"] == "combo"]
    criticals = [f for f in used if f["severity"] == "Critical"]
    # 连招权重高于单式：它封死的回路面更多，同样的字数杀伤力更大
    density = (len(hat_hits) * 10 + len(pattern_hits) * 8 + len(combo_hits) * 14) / scoring_kilo
    raw = 12 * math.log2(1 + density) + len(criticals) * 4
    return {
        "chars": chars,
        "hat_hits": len(hat_hits),
        "pattern_hits": len(pattern_hits),
        "combo_hits": len(combo_hits),
        "critical_hits": len(criticals),
        "quoted_hits": sum(1 for f in findings if f.get("role") == "quoted"),
        "denied_hits": sum(1 for f in findings if f.get("role") == "denied"),
        "hat_per_kilo": round(len(hat_hits) / real_kilo, 2),
        "pattern_per_kilo": round(len(pattern_hits) / real_kilo, 2),
        "label_score": min(100, int(round(raw))),
        "demoted": demoted,
        "demoted_by_slot": slots or {},
        "verdict": _verdict(raw),
    }


def _verdict(raw):
    if raw >= 60:
        return "重度标签化：论证基本让位于身份定性"
    if raw >= 25:
        return "中度标签化：攻击句式已经替代了部分反驳"
    if raw > 0:
        return "轻度标签化：存在可替换为具体主张的标签"
    return "未检出标签化表达"


def _slot_phrase(slots):
    """把 {"heading": 58, "table": 55} 变成 "标题 58 / 表格 55"。"""
    label = {common.SLOT_HEADING: "标题", common.SLOT_TABLE: "表格",
             common.SLOT_LIST: "列表项", common.SLOT_QUOTE: "引用块"}
    parts = [f"{label.get(k, k)} {v}" for k, v in sorted(slots.items(), key=lambda kv: -kv[1]) if v]
    return " / ".join(parts)


def emit_text(results, args):
    total = {"hat_hits": 0, "pattern_hits": 0, "combo_hits": 0, "critical_hits": 0,
             "chars": 0, "quoted_hits": 0, "denied_hits": 0, "demoted": 0}
    for key in ("hat_hits", "pattern_hits", "combo_hits", "critical_hits", "chars",
                "quoted_hits", "denied_hits", "demoted"):
        total[key] = sum(s.get(key, 0) for _, _, s in results)
    for path, findings, stats in results:
        if not findings:
            continue
        print("=" * 72)
        print(f"{common.relpath(path)}  ({stats['chars']} 字)")
        print("-" * 72)
        ordered = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["line"]))
        for item in ordered[: args.top] if args.top else ordered:
            mark = {"Critical": "!!", "Warning": "! ", "Info": "  "}[item["severity"]]
            label = "连招" if item["kind"] == "combo" else "单式"
            role = item.get("role", "used")
            if role == "denied":
                label += "·否认句"
            elif role == "quoted":
                label += "·被引用"
            print(f"{mark} L{item['line']:<4} [{item['severity']:<8}] {item['pattern_id']} {item['name']}  ({label})")
            print(f"     命中: {item['matched']}" + (f"   强化: {','.join(item['amplifiers'])}" if item["amplifiers"] else ""))
            print(f"     原句: {item['sentence']}")
            print(f"     机制: {item['mechanism']}")
            print(f"     反制: {item['remedy']}")
            if item["kind"] == "combo":
                print(f"     先拆: {item['break_at']}   跨度 {item['span']} 字")
            print()
        print(f"    → 帽子 {stats['hat_hits']} / 句式 {stats['pattern_hits']} / 连招 {stats['combo_hits']} / "
              f"每千字 {stats['hat_per_kilo']} / 标签分 {stats['label_score']}  {stats['verdict']}")
        aside = []
        if stats.get("quoted_hits"):
            aside.append(f"被引用 {stats['quoted_hits']}")
        if stats.get("denied_hits"):
            aside.append(f"被否认 {stats['denied_hits']}")
        if stats.get("demoted"):
            aside.append(f"结构行 {stats['demoted']}（{_slot_phrase(stats.get('demoted_by_slot') or {})}）")
        if aside:
            print(f"    · 未计入标签分: {' / '.join(aside)}")
        print()
    if total["chars"]:
        print("=" * 72)
        print(f"合计: {total['chars']} 字, 帽子 {total['hat_hits']} 处, "
              f"句式 {total['pattern_hits']} 处, 连招 {total['combo_hits']} 处, Critical {total['critical_hits']} 处")
        if total["quoted_hits"] or total["denied_hits"] or total["demoted"]:
            print(f"      另有被引用 {total['quoted_hits']} 处 / 被否认 {total['denied_hits']} 处 / "
                  f"结构行降级 {total['demoted']} 处，均不计入标签分")
    if total["hat_hits"] == 0 and total["pattern_hits"] == 0 and args.inputs:
        print("未检出正在使用的帽子标签或攻击句式。")
        if total["quoted_hits"] or total["denied_hits"] or total["demoted"]:
            print("（被引用/被否认/结构行里的提及不算使用——那是文档在讲解标签，不是在扣。）")


ROLE_LABEL = {"used": "使用", "quoted": "被引用", "denied": "被否认"}


def emit_report(results, args):
    """markdown 报告：给人看的，不是给管道看的。

    `--json` 是给程序消费的；但真实用法里拿到报告的人要转给作者/编辑，
    复制 JSON 过去没人看。报告把结论、证据、反制三样放同一张表，
    顺手能贴进 issue。
    """
    total_chars = sum(s["chars"] for _, _, s in results)
    scored = [(p, f, s) for p, f, s in results if f]
    urgent = [(p, f, s) for p, f, s in scored if s["label_score"] >= 40]
    lines = []
    lines.append("# 扣帽子扫描报告")
    lines.append("")
    lines.append(f"- 扫描文件 **{len(results)}** 个，正文 **{total_chars}** 字")
    lines.append(f"- 有命中 **{len(scored)}** 个文件，其中标签分 ≥40 的 **{len(urgent)}** 个")
    lines.append(f"- 最高标签分 **{max([s['label_score'] for _, _, s in results], default=0)}**"
                 f"（满分 100，只算真正在扣的命中）")
    if args.doc_mode:
        demoted = sum(s.get("demoted", 0) for _, _, s in results)
        lines.append(f"- 文档模式：结构行降级 **{demoted}** 处，按\"提到标签\"处理")
    lines.append("")

    if not scored:
        lines.append("未检出帽子标签或攻击句式。")
        print("\n".join(lines))
        return

    lines.append("## 按文件")
    lines.append("")
    lines.append("| 文件 | 字 | 帽子 | 句式 | 连招 | Critical | 标签分 | 判定 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---|")
    for path, findings, stats in sorted(scored, key=lambda x: -x[2]["label_score"]):
        lines.append("| `{}` | {} | {} | {} | {} | {} | **{}** | {} |".format(
            common.relpath(path), stats["chars"], stats["hat_hits"], stats["pattern_hits"],
            stats["combo_hits"], stats["critical_hits"], stats["label_score"], stats["verdict"]))
    lines.append("")

    lines.append("## 证据")
    lines.append("")
    for path, findings, stats in sorted(scored, key=lambda x: -x[2]["label_score"]):
        lines.append(f"### `{common.relpath(path)}`")
        lines.append("")
        lines.append("| 行 | 级别 | ID | 名称 | 角色 | 命中 | 反制 |")
        lines.append("|---:|---|---|---|---|---|---|")
        ordered = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["line"]))
        for item in ordered[: args.top] if args.top else ordered:
            role = ROLE_LABEL.get(item.get("role", "used"), item.get("role", ""))
            cells = [str(item["line"]), item["severity"], item["pattern_id"],
                     item["name"].replace("|", "/"), role,
                     item["matched"].replace("|", "/")[:24],
                     item["remedy"].replace("|", "/")[:60]]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("标签分只统计 role=used 的命中：引号里的话、明确否认的句子、"
                 "标题和表格里的条目都不计入。")
    print("\n".join(lines))


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="扣帽子扫描器")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="直接传入文本")
    source.add_argument("--file", help="单个文本文件")
    source.add_argument("--target", help="目录（递归扫描 md/txt/rst）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--report", action="store_true",
                        help="输出 markdown 报告（给人看，可直接贴进 issue）")
    parser.add_argument("--min-severity", default="Info", choices=["Info", "Warning", "Critical"])
    parser.add_argument("--top", type=int, default=0, help="每个文件最多显示 N 条（0=全部）")
    parser.add_argument("--keep-code", action="store_true", help="不剔除代码块（默认剔除）")
    parser.add_argument("--doc-mode", action="store_true",
                        help="扫描讲解性文档：标题/表格里的标签按\"提到\"算，不降级引用块")
    parser.add_argument("--combo-window", type=int, default=300,
                        help="连招各环之间的最大字符跨度（默认 300）")
    args = parser.parse_args(argv)
    args.inputs = True

    compiled = compile_patterns()
    threshold = SEVERITY_ORDER[args.min_severity]
    results = []
    for path, raw in iter_inputs(args):
        findings, chars = scan_text(path, raw, compiled,
                                    strip_code=not args.keep_code,
                                    window=args.combo_window,
                                    doc_mode=args.doc_mode)
        # 降级统计要在按级别过滤之前数，否则被降下去的那批直接消失，
        # 报告里就成了"什么都没发生"。
        demoted_items = [f for f in findings if f.get("demoted")]
        slots = {}
        for item in demoted_items:
            slots[item["struct"]] = slots.get(item["struct"], 0) + 1
        findings = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= threshold]
        results.append((path, findings, score(findings, chars, len(demoted_items), slots)))

    if args.json:
        payload = {
            "tool": "hat_scan",
            "min_severity": args.min_severity,
            "doc_mode": args.doc_mode,
            "files": [
                {"path": common.relpath(path), "stats": stats, "findings": findings}
                for path, findings, stats in results
            ],
            "summary": {
                "files": len(results),
                "chars": sum(s["chars"] for _, _, s in results),
                "hat_hits": sum(s["hat_hits"] for _, _, s in results),
                "pattern_hits": sum(s["pattern_hits"] for _, _, s in results),
                "combo_hits": sum(s["combo_hits"] for _, _, s in results),
                "critical_hits": sum(s["critical_hits"] for _, _, s in results),
                "demoted": sum(s.get("demoted", 0) for _, _, s in results),
                "max_label_score": max([s["label_score"] for _, _, s in results], default=0),
            },
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if not results:
        print("没有可扫描的输入。", file=sys.stderr)
        return 2
    if args.report:
        emit_report(results, args)
        return 0
    emit_text(results, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
