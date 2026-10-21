#!/usr/bin/env python3
"""数据与仓库一致性门禁。

四类检查：
1. schema —— 结构、枚举、必填字段
2. reference —— 文档里引用的 HAT-xx / PAT-xx 必须真实存在
3. naming —— 文件与 skill 命名规范
4. coverage —— 每个家族都有帽子、每个家族都有可套用的句式

退出码 0 通过；1 有 error。
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import hat_generate  # noqa: E402

SNAKE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
ID_REF_RE = re.compile(r"\b(HAT-F[1-8]-\d{2}|PAT-\d{2}|CMB-\d{2}|CRP-\d{2})\b")
FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)


class Report:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.checked = 0

    def error(self, code, message):
        self.errors.append({"code": code, "message": message})

    def warn(self, code, message):
        self.warnings.append({"code": code, "message": message})

    def ok(self):
        return not self.errors


def check_hats(report):
    data = common.load_hats()
    if data.get("schema_version") != 1:
        report.error("SCHEMA", "hats.json schema_version 必须为 1")
    families = data.get("families", {})
    for name, meta in families.items():
        report.checked += 1
        for field in ("label", "core", "damage", "exit"):
            if not str(meta.get(field, "")).strip():
                report.error("FAMILY", f"家族 {name} 缺少 {field}")

    seen_ids = set()
    seen_names = {}
    family_counts = {}
    for hat in data.get("hats", []):
        report.checked += 1
        hid = hat.get("id", "")
        if not common.HAT_RE.match(hid):
            report.error("HAT-ID", f"id 格式非法: {hid}")
        if hid in seen_ids:
            report.error("HAT-ID", f"id 重复: {hid}")
        seen_ids.add(hid)

        name = hat.get("name", "")
        if not name:
            report.error("HAT-NAME", f"{hid} 缺少 name")
        if name in seen_names:
            report.error("HAT-NAME", f"名称重复: {name} ({hid} 与 {seen_names[name]})")
        seen_names[name] = hid

        family = hat.get("family")
        if family not in families:
            report.error("HAT-FAMILY", f"{hid} 的 family 未注册: {family}")
        family_counts[family] = family_counts.get(family, 0) + 1

        intensity = hat.get("intensity")
        if intensity not in (1, 2, 3):
            report.error("HAT-INTENSITY", f"{hid} intensity 必须是 1/2/3，实际 {intensity}")
        if len(hat.get("counter", [])) < 2:
            report.error("HAT-COUNTER", f"{hid} 反制要点少于 2 条")
        if len(hat.get("signal", [])) < 2:
            report.error("HAT-SIGNAL", f"{hid} 识别特征少于 2 条")
        for field in ("target", "mechanism", "reversal"):
            if len(str(hat.get(field, "")).strip()) < 6:
                report.error("HAT-FIELD", f"{hid} 的 {field} 过短或缺失")

    for family in families:
        if family_counts.get(family, 0) < 4:
            report.error("COVERAGE", f"家族 {family} 帽子数不足 4（实际 {family_counts.get(family, 0)}）")

    # alias 不得与其它帽子的正式名冲突
    for hat in data.get("hats", []):
        for alias in hat.get("aliases", []):
            owner = seen_names.get(alias)
            if owner and owner != hat["id"]:
                report.error("HAT-ALIAS", f"{hat['id']} 的别名 {alias} 与 {owner} 的正式名冲突")
    return family_counts


def check_patterns(report, family_counts):
    data = common.load_patterns()
    if data.get("schema_version") != 1:
        report.error("SCHEMA", "patterns.json schema_version 必须为 1")
    seen = set()
    families = common.family_map()
    allowed_slots = set(hat_generate.SLOT_DEFAULTS) | {"对象", "帽子"}
    hint_counts = {}

    for pattern in data.get("patterns", []):
        report.checked += 1
        pid = pattern.get("id", "")
        if not common.PATTERN_RE.match(pid):
            report.error("PAT-ID", f"id 格式非法: {pid}")
        if pid in seen:
            report.error("PAT-ID", f"id 重复: {pid}")
        seen.add(pid)

        for expr in pattern.get("detect_regex", []):
            try:
                re.compile(expr)
            except re.error as exc:
                report.error("PAT-REGEX", f"{pid} 正则可编译失败: {expr} ({exc})")
        if not pattern.get("detect_regex"):
            report.error("PAT-REGEX", f"{pid} 缺少 detect_regex")

        hint = pattern.get("family_hint")
        if hint not in families:
            report.error("PAT-HINT", f"{pid} family_hint 未注册: {hint}")
        hint_counts[hint] = hint_counts.get(hint, 0) + 1

        if len(pattern.get("counter", [])) < 2:
            report.error("PAT-COUNTER", f"{pid} 反制要点少于 2 条")
        templates = pattern.get("template", [])
        if not templates:
            report.error("PAT-TEMPLATE", f"{pid} 缺少模板")
        for template in templates:
            for slot in hat_generate.SLOT_RE.findall(template):
                if slot not in allowed_slots:
                    report.error("PAT-SLOT", f"{pid} 模板槽位 {{{slot}}} 无默认值")

    for family in families:
        if not hint_counts.get(family):
            report.error("COVERAGE", f"家族 {family} 没有可套用的句式模板")
    return seen


def check_combos(report, hat_ids, pattern_ids):
    data = common.load_combos()
    if data.get("schema_version") != 1:
        report.error("SCHEMA", "combos.json schema_version 必须为 1")
    seen = set()
    for combo in data.get("combos", []):
        report.checked += 1
        cid = combo.get("id", "")
        if not common.COMBO_RE.match(cid):
            report.error("CMB-ID", f"id 格式非法: {cid}")
        if cid in seen:
            report.error("CMB-ID", f"id 重复: {cid}")
        seen.add(cid)

        sequence = combo.get("sequence", [])
        if len(sequence) < 2:
            report.error("CMB-SEQ", f"{cid} 连招至少要有 2 环")
        flat = []
        for index, stage in enumerate(sequence, 1):
            candidates = stage if isinstance(stage, list) else [stage]
            if not candidates:
                report.error("CMB-SEQ", f"{cid} 第 {index} 环候选为空")
            for cand in candidates:
                if cand not in hat_ids and cand not in pattern_ids:
                    report.error("CMB-SEQ", f"{cid} 第 {index} 环引用了不存在的标识 {cand}")
                flat.append(cand)

        if not any(cand in pattern_ids for cand in flat):
            report.error("CMB-SEQ", f"{cid} 全是帽子没有句式，连招必须至少含一个 PAT")
        if combo.get("break_at") not in flat:
            report.error("CMB-BREAK", f"{cid} 的 break_at 不在自身序列里: {combo.get('break_at')}")
        if combo.get("seal_degree") not in (2, 3, 4):
            report.error("CMB-SEAL", f"{cid} seal_degree 必须是 2/3/4")
        if len(combo.get("break_steps", [])) < 2:
            report.error("CMB-BREAK", f"{cid} 破解步骤少于 2 条")
        for field in ("name", "scene", "example", "fail_mode"):
            if not str(combo.get(field, "")).strip():
                report.error("CMB-FIELD", f"{cid} 缺少 {field}")
    return seen


def check_corpus(report, hat_ids, pattern_ids):
    data = common.load_corpus()
    if data.get("schema_version") != 1:
        report.error("SCHEMA", "corpus.json schema_version 必须为 1")
    seen = set()
    counts = {"attack": 0, "neutral": 0, "context": 0}
    trait_counts = {}
    for case in data.get("cases", []):
        report.checked += 1
        cid = case.get("id", "")
        if not common.CORPUS_RE.match(cid):
            report.error("CRP-ID", f"id 格式非法: {cid}")
        if cid in seen:
            report.error("CRP-ID", f"id 重复: {cid}")
        seen.add(cid)

        # 语料的价值在于"长得像真实评论区"。教科书式的完整句子永远测不出漏检和误伤，
        # 所以每条都要标它模拟了什么野外特征，词表外的值一律拒绝。
        traits = case.get("traits", [])
        if not isinstance(traits, list):
            report.error("CRP-TRAIT", f"{cid} traits 必须是列表")
            traits = []
        for trait in traits:
            if trait not in common.CORPUS_TRAITS:
                report.error("CRP-TRAIT", f"{cid} 未知特征 {trait}")
            else:
                trait_counts[trait] = trait_counts.get(trait, 0) + 1

        kind = case.get("kind")
        if kind not in counts:
            report.error("CRP-KIND", f"{cid} kind 必须是 attack / neutral / context")
        else:
            counts[kind] += 1
        if len(str(case.get("text", "")).strip()) < 8:
            report.error("CRP-TEXT", f"{cid} 文本过短")

        expect = case.get("expect") or {}
        must_include = expect.get("must_include", [])
        for need in must_include:
            if need not in hat_ids and need not in pattern_ids:
                report.error("CRP-EXPECT", f"{cid} 期望命中了不存在的标识 {need}")

        if kind == "neutral":
            if must_include:
                report.error("CRP-EXPECT", f"{cid} 负样本不该有 must_include")
            if expect.get("max_hits") != 0:
                report.error("CRP-EXPECT", f"{cid} 负样本必须声明 max_hits=0")
        elif kind == "context":
            # 语境样本断言的是"字面有帽子、但语境不算"：
            # 必须有 downgraded 指名是哪一顶被降级，否则它退化成一条普通负样本。
            if must_include:
                report.error("CRP-EXPECT", f"{cid} 语境样本不该有 must_include")
            if expect.get("max_hits") != 0:
                report.error("CRP-EXPECT", f"{cid} 语境样本必须声明 max_hits=0")
            downgraded = expect.get("downgraded", [])
            if not downgraded:
                report.error("CRP-EXPECT", f"{cid} 语境样本必须声明 downgraded（哪一顶被降级）")
            for need in downgraded:
                if need not in hat_ids and need not in pattern_ids:
                    report.error("CRP-EXPECT", f"{cid} downgraded 引用了不存在的标识 {need}")
            if expect.get("min_raw", 0) < len(downgraded):
                report.error("CRP-EXPECT",
                             f"{cid} min_raw={expect.get('min_raw', 0)} 小于降级项数 {len(downgraded)}")
        elif kind == "attack" and not must_include:
            report.error("CRP-EXPECT", f"{cid} 正样本必须声明 must_include")

        band = expect.get("score_band", [0, 100])
        if len(band) != 2 or band[0] > band[1]:
            report.error("CRP-BAND", f"{cid} score_band 非法: {band}")

    if counts["neutral"] < 4:
        report.error("COVERAGE", f"负样本少于 4 条（实际 {counts['neutral']}）")
    if counts["attack"] < 8:
        report.error("COVERAGE", f"正样本少于 8 条（实际 {counts['attack']}）")
    if counts["context"] < 6:
        report.error("COVERAGE", f"语境样本少于 6 条（实际 {counts['context']}）："
                                 "denied/quoted 降级没有语料背书")

    # 特征覆盖：缺一种野外写法，就有一类真实文本从没被测过。
    # 比如把带谐音的那几条删了，精确词形匹配的边界就重新变成无人看守。
    missing = [trait for trait in common.REQUIRED_TRAITS if not trait_counts.get(trait)]
    if missing:
        report.error("COVERAGE", "语料缺少这些野外特征：" + "、".join(
            f"{trait}（{common.CORPUS_TRAITS[trait]}）" for trait in missing))
    return seen


def check_references(report, hat_ids, pattern_ids, combo_ids=(), corpus_ids=()):
    targets = ["SKILL.md", "README.md"]
    ref_dir = os.path.join(common.REPO_ROOT, "references")
    if os.path.isdir(ref_dir):
        for name in sorted(os.listdir(ref_dir)):
            if name.endswith(".md"):
                targets.append(os.path.join("references", name))
    for rel in targets:
        path = os.path.join(common.REPO_ROOT, rel)
        if not os.path.isfile(path):
            report.warn("REF-MISSING", f"缺少文档 {rel}")
            continue
        with open(path, "r", encoding="utf-8") as fh:
            body = fh.read()
        for ref in sorted(set(ID_REF_RE.findall(body))):
            report.checked += 1
            if ref.startswith("HAT") and ref not in hat_ids:
                report.error("REF-DANGLING", f"{rel} 引用了不存在的帽子 {ref}")
            elif ref.startswith("PAT") and ref not in pattern_ids:
                report.error("REF-DANGLING", f"{rel} 引用了不存在的句式 {ref}")
            elif ref.startswith("CMB") and ref not in combo_ids:
                report.error("REF-DANGLING", f"{rel} 引用了不存在的连招 {ref}")
            elif ref.startswith("CRP") and ref not in corpus_ids:
                report.error("REF-DANGLING", f"{rel} 引用了不存在的语料 {ref}")


def check_naming(report):
    repo_name = os.path.basename(common.REPO_ROOT)
    scripts_dir = os.path.join(common.REPO_ROOT, "scripts")
    for name in sorted(os.listdir(scripts_dir)):
        if not name.endswith(".py"):
            continue
        report.checked += 1
        if not SNAKE_RE.match(name[:-3]):
            report.error("NAMING", f"脚本名不是 snake_case: {name}")

    skill = os.path.join(common.REPO_ROOT, "SKILL.md")
    if not os.path.isfile(skill):
        report.error("NAMING", "SKILL.md 缺失")
        return
    with open(skill, "r", encoding="utf-8") as fh:
        head = fh.read(2000)
    match = FRONTMATTER_RE.match(head)
    if not match:
        report.error("NAMING", "SKILL.md 缺少 frontmatter")
        return
    name_line = re.search(r"^name:\s*[\"']?([^\"'\n]+)", match.group(1), re.M)
    if not name_line:
        report.error("NAMING", "SKILL.md frontmatter 缺少 name")
        return
    declared = name_line.group(1).strip()

    # 目录名只在开发仓里是硬约束：改仓库名而忘了改 name 才是真问题。
    # 装好之后目录名由安装者决定（压成 koumaozi-1.3.0 解压也很正常），
    # 拿它当门禁只会让产物自检永远红——用 .git 是否存在区分这两种场景。
    if not os.path.isdir(os.path.join(common.REPO_ROOT, ".git")):
        return
    report.checked += 1
    if declared != repo_name:
        report.error("NAMING", f"skill name ({declared}) 与仓库目录名 ({repo_name}) 不一致")


VERSION_FILE_RE = re.compile(r"^\d+\.\d+\.\d+$")
CHANGELOG_HEAD_RE = re.compile(r"^##\s+(\d+\.\d+\.\d+)\s*$", re.M)


def check_version(report):
    """版本号三处必须一致：VERSION / SKILL.md frontmatter / CHANGELOG 最新段。

    这三处不一致的后果不是"显示错了"，而是发版发出一个自报版本与实际内容不符的包。
    发布流程按 VERSION 打 tag、按 CHANGELOG 抽说明，任何一处漂了，Release 就在撒谎。
    """
    version_path = os.path.join(common.REPO_ROOT, "VERSION")
    if not os.path.isfile(version_path):
        report.error("VERSION", "缺少 VERSION 文件")
        return None
    with open(version_path, "r", encoding="utf-8") as fh:
        version = fh.read().strip()
    report.checked += 1
    if not VERSION_FILE_RE.match(version):
        report.error("VERSION", f"VERSION 不是 x.y.z 格式: {version!r}")
        return None

    skill = os.path.join(common.REPO_ROOT, "SKILL.md")
    if os.path.isfile(skill):
        with open(skill, "r", encoding="utf-8") as fh:
            head = fh.read(2000)
        match = FRONTMATTER_RE.match(head)
        if match:
            declared = re.search(r"^version:\s*[\"']?([^\"'\n]+)", match.group(1), re.M)
            report.checked += 1
            if not declared:
                report.error("VERSION", "SKILL.md frontmatter 缺少 version")
            elif declared.group(1).strip() != version:
                report.error("VERSION",
                             f"SKILL.md version ({declared.group(1).strip()}) 与 VERSION ({version}) 不一致")

    changelog = os.path.join(common.REPO_ROOT, "CHANGELOG.md")
    if os.path.isfile(changelog):
        with open(changelog, "r", encoding="utf-8") as fh:
            headings = CHANGELOG_HEAD_RE.findall(fh.read())
        report.checked += 1
        if not headings:
            report.error("VERSION", "CHANGELOG.md 里找不到任何 `## x.y.z` 段落")
        elif headings[0] != version:
            report.error("VERSION",
                         f"CHANGELOG 最新版本是 {headings[0]}，VERSION 是 {version}（发版说明会抽错段）")
    return version


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="数据一致性门禁")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = Report()
    family_counts = check_hats(report)
    pattern_ids = check_patterns(report, family_counts)
    hat_ids = {hat["id"] for hat in common.load_hats()["hats"]}
    combo_ids = check_combos(report, hat_ids, pattern_ids)
    corpus_ids = check_corpus(report, hat_ids, pattern_ids)
    check_references(report, hat_ids, pattern_ids, combo_ids, corpus_ids)
    check_naming(report)
    version = check_version(report)

    payload = {
        "tool": "verify_data",
        "checked": report.checked,
        "hats": len(hat_ids),
        "patterns": len(pattern_ids),
        "combos": len(combo_ids),
        "corpus": len(corpus_ids),
        "families": len(family_counts),
        "version": version,
        "errors": report.errors,
        "warnings": report.warnings,
        "passed": report.ok(),
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"检查项 {report.checked}  |  版本 {payload['version']}  "
              f"帽子 {payload['hats']}  句式 {payload['patterns']}  "
              f"连招 {payload['combos']}  语料 {payload['corpus']}  家族 {payload['families']}")
        for item in report.errors:
            print(f"  ERROR [{item['code']}] {item['message']}")
        for item in report.warnings:
            print(f"  WARN  [{item['code']}] {item['message']}")
        print("通过" if report.ok() else f"失败：{len(report.errors)} 个错误")
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
