#!/usr/bin/env python3
"""文档即测试：把 README / SKILL / references 里的命令示例全部真跑一遍。

为什么值得单开一道门禁：文档示例是唯一会被读者**逐字复制**的东西。
脚本改名、参数改了、样例文件挪了位置，源码门禁一条都不会红，但读者
照抄第一行就报 "No such file or directory"。文档腐烂是静默的。

这里做的事：
1. 抽出所有围栏代码块里以 `python3 scripts/` 开头的命令行（含 `\\` 续行）
2. 换成当前解释器真跑，断言退出码 0
3. 带 `--json` 的命令额外断言 stdout 是合法 JSON
4. 引用了不存在文件的命令会被单独点出来（比"命令失败"更能定位）

跳过方式：在命令那一行的**行尾注释**里写 `doc-smoke: skip <理由>`。
写成单独一行不生效——抽取只认以 `python3 scripts/` 开头的行，整行注释
在进入判断前就被跳过了（这个文档字符串原来写的是"上一行"，是错的）。

用法:
    python3 scripts/doc_smoke.py
    python3 scripts/doc_smoke.py --verbose
    python3 scripts/doc_smoke.py --json
    python3 scripts/doc_smoke.py --filter hat_diff

退出码: 0 全部通过；1 有命令跑不通。
"""
import argparse
import glob
import json
import os
import re
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

DOCS = ["README.md", "SKILL.md"]
FENCE_RE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)```", re.S)
CMD_PREFIXES = ("python3 scripts/", "python scripts/")
SKIP_MARK = "doc-smoke: skip"


def skip_reason(command):
    """gate.py 会回头跑 docs 门禁，直接执行文档里的 gate 命令就是无限递归。

    但 --list / --explain 只打印元信息、不跑门禁，没有递归风险，照跑。
    """
    if "scripts/gate.py" not in command:
        return None
    if "--list" in command or "--explain" in command:
        return None
    return "会递归（gate.py 的 docs 门禁会回来跑 doc_smoke）"

# 需要生成产物才存在的路径：跑之前先建好，否则是环境问题不是文档问题
DIST_RE = re.compile(r"\bdist/\S+")

TIMEOUT = 180


def doc_paths(root=None):
    root = root or common.REPO_ROOT
    paths = [os.path.join(root, name) for name in DOCS]
    ref_dir = os.path.join(root, "references")
    if os.path.isdir(ref_dir):
        paths += [os.path.join(ref_dir, name)
                  for name in sorted(os.listdir(ref_dir)) if name.endswith(".md")]
    return [path for path in paths if os.path.isfile(path)]


def extract(path):
    """返回 [{'source': 'README.md:12', 'command': '...'}]。跳过标记写在命令上一行。"""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    # 用 common.relpath 而不是 os.path.relpath：Windows 上跨盘（C: 的文件、
    # D: 的仓库）会抛 ValueError: path is on mount 'C:', start on mount 'D:'。
    # 那是测试夹具的常见形态，不该让整道门禁报错。
    rel = common.relpath(path)
    found = []
    for block in FENCE_RE.finditer(text):
        line_offset = text.count("\n", 0, block.start(1))
        lines = block.group(1).splitlines()
        buffer = ""
        for index, raw in enumerate(lines):
            line = raw.rstrip()
            if buffer:
                buffer += " " + line.strip()
            elif line.strip().startswith(CMD_PREFIXES):
                buffer = line.strip()
            else:
                continue
            if buffer.endswith("\\"):
                buffer = buffer[:-1].rstrip()
                continue
            command = buffer
            buffer = ""
            if SKIP_MARK in command:
                continue
            cleaned = strip_comment(command)
            skip = skip_reason(cleaned)
            found.append({
                "source": f"{rel}:{line_offset + index + 1}",
                "command": cleaned,
                "raw": command,
                "skip": skip,
            })
    return found


def strip_comment(command):
    """去掉行尾 `# 注释`。只在引号外的 ` #` 处切，避免切坏 --text "a # b"。"""
    quote = None
    for index, char in enumerate(command):
        if char in "\"'":
            quote = None if quote == char else (quote or char)
        elif char == "#" and quote is None and index and command[index - 1] == " ":
            return command[:index].rstrip()
    return command.strip()


def to_argv(command, root=None):
    root = root or common.REPO_ROOT
    parts = shlex.split(command)
    if not parts:
        return []
    if parts[0] in ("python3", "python"):
        parts[0] = sys.executable
    # 文档里写 python3 scripts/x.py，脚本存在性单独检查，先确认它没被改名
    if len(parts) > 1 and parts[1].startswith("scripts/"):
        if not os.path.isfile(os.path.join(root, parts[1])):
            raise FileNotFoundError(parts[1])
    expanded = []
    for part in parts:
        if "*" in part and not part.startswith("-"):
            matches = sorted(glob.glob(os.path.join(root, part)))
            if matches:
                expanded.extend(matches)
                continue
        expanded.append(part)
    return expanded


def run_case(case, root=None):
    root = root or common.REPO_ROOT
    result = {"source": case["source"], "command": case["command"]}
    if case.get("skip"):
        result.update({"problems": [], "passed": True, "skipped": case["skip"]})
        return result
    try:
        argv = to_argv(case["command"], root)
    except FileNotFoundError as exc:
        result["problems"] = [f"脚本不存在: {exc}（被改名或删掉了？）"]
        result["passed"] = False
        return result

    if not argv:
        result["problems"] = ["空命令"]
        result["passed"] = False
        return result

    try:
        proc = subprocess.run(argv, cwd=root, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        result["problems"] = [f"超时（>{TIMEOUT}s）"]
        result["passed"] = False
        return result

    problems = []
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        problems.append(f"退出码 {proc.returncode}: " + " | ".join(tail))
    elif "--json" in argv:
        # 文档承诺了 --json，就得真的是 JSON
        try:
            json.loads(proc.stdout)
        except ValueError:
            problems.append("文档写了 --json，但输出不是合法 JSON")

    result["problems"] = problems
    result["passed"] = not problems
    return result


def ensure_dist(cases, root=None):
    """有命令引用 dist/ 时先把包打出来。

    否则在干净 clone 上第一条就失败，而失败原因是"还没打包"，不是文档错了——
    门禁报错要报真原因。
    """
    root = root or common.REPO_ROOT
    if not any("dist/" in case["command"] for case in cases):
        return None
    import package
    return package.build(out_dir=os.path.join(root, "dist"), root=root)


def collect(root=None, filter_text=None):
    root = root or common.REPO_ROOT
    cases = []
    for path in doc_paths(root):
        for case in extract(path):
            if filter_text and filter_text not in case["command"]:
                continue
            cases.append(case)
    return cases


def run(filter_text=None, verbose=False, root=None):
    root = root or common.REPO_ROOT
    cases = collect(root, filter_text)
    ensure_dist(cases, root)
    rows = [run_case(case, root) for case in cases]
    return rows


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="文档命令示例门禁")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="通过的命令也打印")
    parser.add_argument("--filter", default=None, help="只跑命令里含该子串的")
    args = parser.parse_args(argv)

    rows = run(args.filter, args.verbose)
    failed = [r for r in rows if not r["passed"]]

    if args.json:
        print(json.dumps({"tool": "doc_smoke", "total": len(rows),
                          "failed": len(failed), "cases": rows},
                         ensure_ascii=False, indent=2))
        return 0 if not failed else 1

    skipped = [row for row in rows if row.get("skipped")]
    ran = len(rows) - len(skipped)
    line = f"文档命令 {len(rows)} 条  |  跑 {ran}  通过 {ran - len(failed)}"
    if skipped:
        line += f"  跳过 {len(skipped)}（{skipped[0]['skipped']}）"
    print(line)
    print("-" * 66)
    for row in rows:
        if row["passed"] and not args.verbose:
            continue
        mark = "PASS" if row["passed"] else "FAIL"
        print(f"{mark}  {row['source']}")
        print(f"      {row['command']}")
        for problem in row["problems"]:
            print(f"      × {problem}")
    print("-" * 66)
    if failed:
        print(f"失败：{len(failed)} 条命令照抄跑不通")
        return 1
    print("通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
