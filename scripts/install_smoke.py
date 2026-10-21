#!/usr/bin/env python3
"""装完之后能不能用：对已安装目录做端到端验证。

"包能跑"和"装完能用"是两件事。1.6.0 就是漏了这一步：包里不带 `tests/`，
用户装完一跑 `gate.py` 就红，而发布流水线全绿——因为流水线验的是源目录。

这一段在 ubuntu 和 Windows 上跑同一份代码，不各写一遍 shell：安装脚本本身
是两套（install.sh / install.ps1），验完之后的行为必须只有一套标准。

用法:
    python3 scripts/install_smoke.py --installed ~/.workbuddy/skills/koumaozi
    python3 scripts/install_smoke.py --installed <dir> --json

退出码: 0 通过；1 有问题。
"""
import argparse
import json
import os
import re
import subprocess
import sys


def run(argv, cwd):
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


# 装完之后必须在的东西。少一个，用户第一次用就会缺功能。
# 这份清单要跟 package.py 的打包白名单对得上，否则会出现"验证嫌少、打包嫌多"：
# 一边说缺文件，一边包里其实有，或者反过来。tests/ 里有测试盯着这件事。
REQUIRED_FILES = [
    "SKILL.md", "VERSION", "README.md",
    "data/hats.json", "data/patterns.json", "data/combos.json", "data/corpus.json",
    "scripts/common.py", "scripts/hat_scan.py", "scripts/hat_generate.py",
    "scripts/hat_diff.py", "scripts/gate.py", "scripts/mutation_check.py",
    "scripts/web_lint.py", "scripts/install_smoke.py", "scripts/release_check.py",
    "references/hats-catalog.md", "references/rhetoric-patterns.md",
]

# 这两个目录刻意不打进包里：用户用不上，白占体积。
# 它们不在，意味着 gate 的 unit / mutation 两道必须走 SKIP 而不是红。
FORBIDDEN_DIRS = ("tests", "docs")


def check_layout(root):
    problems = []
    for rel in REQUIRED_FILES:
        if not os.path.isfile(os.path.join(root, rel)):
            problems.append(f"装完缺文件: {rel}")
    for rel in FORBIDDEN_DIRS:
        if os.path.exists(os.path.join(root, rel)):
            problems.append(f"{rel}/ 不该被打进安装包（用户不需要，白占体积）")
    return problems


def check_scan(root):
    """装好的路径直接扫一句，扫不出东西说明 `python <dir>/scripts/x.py` 跑不通。"""
    proc = run([sys.executable, os.path.join(root, "scripts", "hat_scan.py"),
                "--text", "典型的带节奏，一条多少钱？", "--json"], cwd=root)
    if proc.returncode != 0:
        return [f"装完之后 hat_scan 跑不起来（退出码 {proc.returncode}）: "
                f"{(proc.stderr or '').strip().splitlines()[-1:]}"], None
    try:
        summary = json.loads(proc.stdout)["summary"]
    except (ValueError, KeyError) as exc:
        return [f"hat_scan --json 的输出不是预期结构: {exc}"], None
    problems = []
    if summary.get("hat_hits", 0) < 1:
        problems.append(f"装完之后扫不出帽子: {summary}")
    if summary.get("pattern_hits", 0) < 1:
        problems.append(f"装完之后扫不出句式: {summary}")
    return problems, summary


def check_gate(root):
    """在安装目录里跑核心门禁。

    重点是 SKIP 而不是 PASS：安装包不带 tests/ 和 docs/，那几个门禁必须
    就地跳过。跳过的语义如果写错了（比如把"目录不存在"当成失败），用户
    装完第一件事就是看见一片红。
    """
    proc = run([sys.executable, os.path.join(root, "scripts", "gate.py"),
                "--tier", "core"], cwd=root)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-4:]
        return [f"装完之后 core 门禁不过（退出码 {proc.returncode}）: {tail}"], None
    skipped = len(re.findall(r"^SKIP", output, re.M))
    ran = re.search(r"(\d+) 道全通过", output)
    if not ran:
        return [f"gate 输出里找不到通过行: {output.strip().splitlines()[-3:]}"], None
    total = int(ran.group(1))
    if skipped < 2:
        return [f"安装包里应该跳过 unit/mutation 两道门禁（不带 tests/），实际只跳过 "
                f"{skipped} 道——跳过逻辑可能坏了，用户装完会看见红的"], None
    return [], {"total": total, "skipped": skipped,
                "passed": total - skipped}


def main(argv=None):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import common
    common.ensure_utf8_stdout()

    parser = argparse.ArgumentParser(description="安装产物端到端验证")
    parser.add_argument("--installed", required=True, help="安装后的目录")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = os.path.abspath(os.path.expanduser(args.installed))
    report = {"installed": root, "checks": {}, "problems": []}

    if not os.path.isdir(root):
        print(f"安装目录不存在: {root}", file=sys.stderr)
        return 1

    layout_problems = check_layout(root)
    report["checks"]["布局"] = layout_problems or "ok"
    report["problems"].extend(layout_problems)

    scan_problems, summary = check_scan(root)
    report["checks"]["扫描"] = summary or scan_problems
    report["problems"].extend(scan_problems)

    gate_problems, gate_info = check_gate(root)
    report["checks"]["门禁"] = gate_info or gate_problems
    report["problems"].extend(gate_problems)

    version = ""
    version_path = os.path.join(root, "VERSION")
    if os.path.isfile(version_path):
        with open(version_path, "r", encoding="utf-8") as handle:
            version = handle.read().strip()
    report["version"] = version

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif report["problems"]:
        print("安装验证  失败")
        for line in report["problems"]:
            print(f"  × {line}")
    else:
        print(f"安装验证  v{version}  |  布局齐 · 扫描通 · "
              f"门禁 {gate_info['total']} 道跑完（{gate_info['skipped']} 道按预期跳过）")
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
