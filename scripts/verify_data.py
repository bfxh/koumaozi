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
ID_REF_RE = re.compile(r"\b(HAT-F[1-8]-\d{2}|PAT-\d{2})\b")
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


def check_references(report, hat_ids, pattern_ids):
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
            if ref.startswith("PAT") and ref not in pattern_ids:
                report.error("REF-DANGLING", f"{rel} 引用了不存在的句式 {ref}")


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
    report.checked += 1
    if declared != repo_name:
        report.error("NAMING", f"skill name ({declared}) 与仓库目录名 ({repo_name}) 不一致")


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="数据一致性门禁")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = Report()
    family_counts = check_hats(report)
    pattern_ids = check_patterns(report, family_counts)
    hat_ids = {hat["id"] for hat in common.load_hats()["hats"]}
    check_references(report, hat_ids, pattern_ids)
    check_naming(report)

    payload = {
        "tool": "verify_data",
        "checked": report.checked,
        "hats": len(hat_ids),
        "patterns": len(pattern_ids),
        "families": len(family_counts),
        "errors": report.errors,
        "warnings": report.warnings,
        "passed": report.ok(),
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"检查项 {report.checked}  |  帽子 {payload['hats']}  句式 {payload['patterns']}  家族 {payload['families']}")
        for item in report.errors:
            print(f"  ERROR [{item['code']}] {item['message']}")
        for item in report.warnings:
            print(f"  WARN  [{item['code']}] {item['message']}")
        print("通过" if report.ok() else f"失败：{len(report.errors)} 个错误")
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
