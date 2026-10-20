#!/usr/bin/env python3
"""CLI 端到端冒烟：四个命令的形状对不对。

单元测试调的是函数，这里调的是命令行——参数解析、JSON 输出、退出码
这些只有真跑命令才验得到。原先散在 ci.yml 的五个 shell step 里，
挪进来是为了本地能一条命令跑完（`gate.py`）。

用法:
    python3 scripts/cli_smoke.py
    python3 scripts/cli_smoke.py --verbose

退出码: 0 全部通过；1 有断言失败。
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPTS)


def run(args):
    return subprocess.run([sys.executable, os.path.join(SCRIPTS, args[0])] + args[1:],
                          cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def check_scan():
    proc = run(["hat_scan.py", "--text", "典型的带节奏，一条多少钱？", "--json"])
    if proc.returncode != 0:
        return [f"退出码 {proc.returncode}: {(proc.stderr or '').strip()[:200]}"]
    summary = json.loads(proc.stdout)["summary"]
    problems = []
    if summary.get("hat_hits", 0) < 1:
        problems.append(f"没扫出帽子: {summary}")
    if summary.get("pattern_hits", 0) < 1:
        problems.append(f"没扫出句式: {summary}")
    if summary.get("max_label_score", 0) <= 0:
        problems.append(f"标签分为 0，评分逻辑断了: {summary}")
    return problems


def check_generate():
    proc = run(["hat_generate.py", "--target", "某方案", "--count", "8", "--json", "--seed", "1"])
    if proc.returncode != 0:
        return [f"退出码 {proc.returncode}: {(proc.stderr or '').strip()[:200]}"]
    data = json.loads(proc.stdout)
    problems = []
    for item in data["results"]:
        # 模板槽位没填上会留下 {对象} 这种花括号
        if re.search(r"\{[^{}]*\}", item["text"]):
            problems.append(f"残留槽位: {item['text']}")
        if len(item.get("counter", "")) < 2:
            problems.append(f"破解点太短: {item}")
    if not data["results"]:
        problems.append("一条都没生成")
    return problems


def check_combo():
    proc = run(["hat_generate.py", "--target", "某博主", "--combo", "CMB-01",
                "--json", "--seed", "3"])
    if proc.returncode != 0:
        return [f"退出码 {proc.returncode}: {(proc.stderr or '').strip()[:200]}"]
    data = json.loads(proc.stdout)
    problems = []
    if data.get("mode") != "combo":
        problems.append(f"mode 不是 combo: {list(data)[:6]}")
    if len(data.get("steps", [])) != 3:
        problems.append(f"CMB-01 应该是三段，实际 {len(data.get('steps', []))}")
    if not data.get("break_steps"):
        problems.append("没有给出拆解步骤")
    # 生成文本的用词未必落在正则覆盖内，这里只要求回扫能扫出东西；
    # "示例自洽"由单元测试 test_combo_examples_are_detected 保证
    scan = run(["hat_scan.py", "--text", data.get("text", ""), "--json"])
    if scan.returncode != 0:
        problems.append(f"回扫失败: {(scan.stderr or '').strip()[:200]}")
    else:
        summary = json.loads(scan.stdout)["summary"]
        if summary["pattern_hits"] + summary["hat_hits"] < 1:
            problems.append(f"生成的连招回扫不出任何东西: {summary}")
    return problems


def check_diff_gate():
    proc = run(["hat_diff.py",
                "--before-text", "标准公知体，收钱的吧。",
                "--after-text", "这一段的样本有问题，结论我不认同。",
                "--must-drop", "10", "--max-score", "30"])
    if proc.returncode != 0:
        return [f"改好之后应当通过门禁，实际退出码 {proc.returncode}: "
                f"{(proc.stderr or proc.stdout or '').strip()[:200]}"]
    return []


def check_diff_blocks_regression():
    proc = run(["hat_diff.py",
                "--before-text", "这个方案还行。",
                "--after-text", "收钱的吧，一看就是那路人，早晚遭报应。",
                "--max-score", "20"])
    if proc.returncode == 0:
        return ["改恶化了却放过了——门禁逻辑反了"]
    return []


CHECKS = [
    ("扫描器", check_scan),
    ("单条生成", check_generate),
    ("连招生成", check_combo),
    ("改稿门禁（正向通过）", check_diff_gate),
    ("改稿门禁（拦住恶化）", check_diff_blocks_regression),
]


def main(argv=None):
    common.ensure_utf8_stdout()
    verbose = "--verbose" in (argv if argv is not None else sys.argv[1:])
    failures = 0
    for name, check in CHECKS:
        try:
            problems = check()
        except Exception as exc:  # noqa: BLE001 - 冒烟脚本要把任何异常都报成失败
            problems = [f"抛异常: {type(exc).__name__}: {exc}"]
        if problems:
            failures += 1
            print(f"FAIL  {name}")
            for problem in problems:
                print(f"      {problem}")
        elif verbose:
            print(f"PASS  {name}")
    if failures:
        print(f"失败：{failures}/{len(CHECKS)} 项")
        return 1
    print(f"CLI 冒烟 {len(CHECKS)}/{len(CHECKS)} 通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
