#!/usr/bin/env python3
"""统一门禁入口：本地和 CI 跑同一套，顺序和集合只在这里定义一次。

散在 workflow 里的门禁有两个老问题：
- 本地要自己记顺序（先打包还是先跑文档？），记错就得到假结果
- CI 和本地各写一份，改了一边忘了另一边，就出现"本地绿、CI 红"

所以顺序、集合、每道门禁挡什么，全部收在这个文件里。ci.yml 只调用它。

用法:
    python3 scripts/gate.py              # 全量（core + full）
    python3 scripts/gate.py --tier core  # 只有核心门禁（CI 的 3.9 / 3.13 用这个）
    python3 scripts/gate.py --list       # 看有哪些门禁
    python3 scripts/gate.py --explain    # 每道门禁挡什么、失败了先看哪
    python3 scripts/gate.py --only data,corpus
    python3 scripts/gate.py --all        # 一道失败也继续跑完（CI 用，一次看全）

退出码: 0 全通过；1 有门禁失败。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPTS)
# 安装包里不带 tests（用户不需要），编译和单测就只处理存在的目录，
# 否则装好的 skill 一跑 gate 就红，而红的理由跟"代码有问题"毫无关系。
_TEST_DIR = os.path.join(ROOT, "tests")
_COMPILE_TARGETS = [SCRIPTS] + ([_TEST_DIR] if os.path.isdir(_TEST_DIR) else [])


def py(script, *args):
    return [sys.executable, os.path.join(SCRIPTS, script)] + list(args)


# tier: core 是每个 Python 版本都跑；full 只在代表版本上跑（慢、和版本无关）
GATES = [
    {
        "key": "compile",
        "name": "语法编译",
        "tier": "core",
        "argv": [sys.executable, "-m", "compileall", "-q"] + _COMPILE_TARGETS,
        "protects": "脚本有语法错误，任何功能都无从谈起",
        "hint": "compileall 只查语法，查不出 NameError——新增正则/变量后要真跑一次脚本",
    },
    {
        "key": "data",
        "name": "数据一致性",
        "tier": "core",
        "argv": py("verify_data.py"),
        "protects": "帽子/句式/连招/语料的 schema、家族覆盖、别名冲突、模板槽位、"
                    "文档引用的编号真实存在、版本号三处一致",
        "hint": "报错行会写明 [CODE] 与具体条目；[VERSION] 多半是改了 VERSION 忘了同步 "
                "SKILL.md 或 CHANGELOG",
    },
    {
        "key": "words",
        "name": "内容量",
        "tier": "core",
        "argv": py("wordcount.py", "--min", "10000"),
        "protects": "文档被大段删改后规模缩水（这个仓库的门槛是一万字）",
        "hint": "看 scripts/wordcount.py 的统计口径：剔除 frontmatter、代码块、链接",
    },
    {
        "key": "corpus",
        "name": "回归语料",
        "tier": "core",
        "argv": py("corpus_check.py"),
        "protects": "该抓的没抓（漏检）、不该抓的抓了（误报）、降级逻辑失效、"
                    "句式/连招/家族覆盖出现空洞",
        "hint": "用 --verbose 看每条的命中明细；改了正则先跑这一道，别等单元测试",
    },
    {
        "key": "unit",
        "name": "单元测试",
        "tier": "core",
        "argv": [sys.executable, "-m", "unittest", "discover", "-s", _TEST_DIR],
        # 安装包里没有 tests/，这道门禁就地跳过——不是失败，是不适用
        "needs": [_TEST_DIR],
        # 这条测试和 docs 门禁重复（都是把 29 条命令跑一遍，占 12s），
        # gate 里由 docs 单独覆盖；直接跑 unittest 时仍然生效
        "env": {"KOUMAOZI_SKIP_DOC_SMOKE": "1"},
        "protects": "扫描器正反例、连招检测、生成器可复现、diff 方向、性能（防正则回溯爆炸）",
        "hint": "失败信息里有断言原文；性能和正则改动最容易连锁失败",
    },
    {
        "key": "docs",
        "name": "文档命令",
        "tier": "full",
        "argv": py("doc_smoke.py"),
        "protects": "文档里的命令示例照抄能不能跑（脚本改名、参数改了、样例文件挪了）",
        "hint": "输出会指到 文件:行号；路径类问题多半是 examples/ 里的样例被动了",
    },
    {
        "key": "cli",
        "name": "CLI 冒烟",
        "tier": "full",
        "argv": py("cli_smoke.py"),
        "protects": "四个命令的端到端形状：扫描有命中、连招三段结构、改稿门禁能拦恶化",
        "hint": "断言在 scripts/cli_smoke.py 里，改 CLI 参数时同步改它",
    },
    {
        "key": "web",
        "name": "网页端对拍",
        "tier": "full",
        "argv": py("web_parity.py"),
        # 安装包不带 docs/（网页是仓库的交付物，不是 skill 的一部分），
        # 那道门禁就地跳过——不是失败，是不适用
        "needs": [os.path.join(ROOT, "docs")],
        # 规则文件是 data/ 的派生物；判定逻辑在 JS 里重写了一遍
        "protects": "网页用的是旧规则，或 JS 与 Python 判得不一样——两者都不报错，"
                    "只是网页给出的结论不可信",
        "hint": "改过 data/ 或 common.py 就先跑 build_web.py 重新生成；"
                "对拍报某个 CRP-xx 的「命中明细」不同，去 diff docs/scan.js 与 hat_scan.py",
    },
    {
        "key": "package",
        "name": "产物",
        "tier": "full",
        "argv": py("package.py", "--verify"),
        "protects": "发出去的包里是不是齐、能不能跑（解压后验证，不验源目录）",
        "hint": "报「清单里有但包里没有」= 打包白名单漏了文件；报「内容被改动」= 清单与内容不同步",
    },
]

KEYS = [gate["key"] for gate in GATES]


def gate_by_key(key):
    for gate in GATES:
        if gate["key"] == key:
            return gate
    return None


def select(tier="all", only=None):
    if only:
        wanted = [item.strip() for item in only.split(",") if item.strip()]
        unknown = [item for item in wanted if item not in KEYS]
        if unknown:
            raise SystemExit(f"没有这些门禁: {', '.join(unknown)}（用 --list 看）")
        return [gate_by_key(key) for key in wanted]
    if tier == "core":
        return [gate for gate in GATES if gate["tier"] == "core"]
    return list(GATES)


def write_markdown(path, version, rows, total):
    """写 markdown 表给 GitHub Step Summary。

    让 gate 自己出摘要，workflow 只负责 cat——在 yml 里嵌 heredoc 拼 JSON
    很容易被缩进和引号搞死，那种错误还只在 CI 上才暴露。
    """
    failed = [row for row in rows if not row["passed"]]
    lines = [f"### 门禁 v{version}", ""]
    lines.append(f"总共 {len(rows)} 道，失败 {len(failed)} 道，耗时 {total}s。"
                 "定义在 `scripts/gate.py`，本地跑 `python3 scripts/gate.py` 是同一套。")
    lines.append("")
    lines.append("| 门禁 | 结果 | 耗时 | 结论 |")
    lines.append("|---|---|---|---|")
    for row in rows:
        mark = "✅" if row["passed"] else "❌"
        if row.get("skipped"):
            mark = "⏭"
        detail = (row.get("skipped") or row["detail"] or "").replace("|", "/")
        lines.append(f"| `{row['key']}` {row['name']} | {mark} | {row['seconds']}s | {detail} |")
    body = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)


def summarize(stdout):
    """从输出里挑一行能代表结论的。优先"检查项/语料/文档命令/通过"。"""
    lines = [line.strip() for line in (stdout or "").splitlines() if line.strip()]
    # 顺序有讲究：单元测试会顺带打印一堆东西（比如 package 的自检行），
    # "Ran 83 tests" 才是它的结论，得优先抓
    for line in lines:
        if line.startswith("Ran "):
            return line.split(" in ")[0]
    for line in lines:
        if line.startswith(("检查项", "语料 ", "文档命令", "CLI 冒烟", "自检 ", "中文合计", "网页端对拍")):
            return line
    for line in reversed(lines):
        if line in ("通过", "OK") or line.startswith("失败"):
            return line
    return lines[-1] if lines else ""


def skip_note(text):
    """unittest 的跳过数不在 "Ran N tests" 那行，在结尾的 "OK (skipped=3)"。

    只看 "Ran 126 tests" 是看不出有多少条**根本没跑**的。跨平台矩阵上这尤其
    要命：Windows 那条要是因为没装 pwsh 全跳过，日志照样一片绿，而矩阵的
    全部意义就是验 Windows 独有的东西。
    """
    found = re.search(r"skipped=(\d+)", text or "")
    return int(found.group(1)) if found else 0


def run_gate(gate, keep_going=True):
    started = time.perf_counter()
    env = dict(os.environ)
    env.update(gate.get("env", {}))
    proc = subprocess.run(gate["argv"], cwd=os.path.dirname(SCRIPTS), env=env,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    elapsed = time.perf_counter() - started
    passed = proc.returncode == 0
    # unittest 把结果写到 stderr，只读 stdout 会抓不到 "Ran N tests"
    detail = summarize(proc.stdout or "")
    if detail.startswith("自检") or not detail:
        alt = summarize(proc.stderr or "")
        if alt and (not detail or alt.startswith("Ran ")):
            detail = alt
    # 跳过数单列出来："Ran 126 tests" 一行看不出有几条根本没跑
    if detail.startswith("Ran "):
        skipped = skip_note(proc.stderr or "") or skip_note(proc.stdout or "")
        if skipped:
            detail = f"{detail}  |  跳过 {skipped}"
    problems = []
    if not passed:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        problems = [line for line in tail if line.strip()][-6:]
    return {
        "key": gate["key"],
        "name": gate["name"],
        "passed": passed,
        "seconds": round(elapsed, 2),
        "detail": detail,
        "problems": problems,
        "returns": proc.returncode,
    }


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="统一门禁入口")
    parser.add_argument("--tier", choices=["core", "full", "all"], default="all",
                        help="core=每个版本都跑；full=再加上文档/CLI/产物")
    parser.add_argument("--only", default=None, help="逗号分隔的门禁 key")
    parser.add_argument("--stop-early", action="store_true",
                        help="第一道失败就退出（本地快速迭代时用；默认跑完，一次看全）")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--markdown", default=None,
                        help="把结果写成 markdown 表（CI 的 Step Summary 用）")
    parser.add_argument("--list", action="store_true", help="列出全部门禁")
    parser.add_argument("--explain", action="store_true", help="说明每道门禁挡什么")
    args = parser.parse_args(argv)

    if args.list:
        for gate in GATES:
            print(f"{gate['key']:<10} {gate['tier']:<5} {gate['name']}")
        return 0

    if args.explain:
        for gate in GATES:
            print(f"[{gate['key']}] {gate['name']}  (tier={gate['tier']})")
            print(f"  挡什么: {gate['protects']}")
            print(f"  失败了: {gate['hint']}")
            print()
        return 0

    gates = select(args.tier, args.only)
    version = "?"
    version_path = os.path.join(os.path.dirname(SCRIPTS), "VERSION")
    if os.path.isfile(version_path):
        with open(version_path, "r", encoding="utf-8") as fh:
            version = fh.read().strip()

    rows = []
    for gate in gates:
        missing = [path for path in gate.get("needs", []) if not os.path.exists(path)]
        if missing:
            rows.append({
                "key": gate["key"], "name": gate["name"], "passed": True,
                "seconds": 0.0, "skipped": "缺 " + ", ".join(
                    os.path.basename(path) for path in missing) + "/（安装包不带）",
                "detail": "", "problems": [], "returns": 0,
            })
            continue
        row = run_gate(gate)
        rows.append(row)
        if not row["passed"]:
            # 失败当场打出来，别让人等最后才知道
            print(f"FAIL  {row['name']}  ({row['seconds']}s)", file=sys.stderr)
            for line in row["problems"]:
                print(f"      {line}", file=sys.stderr)
            if args.stop_early:
                return 1

    failed = [row for row in rows if not row["passed"]]
    total = round(sum(row["seconds"] for row in rows), 2)

    if args.markdown:
        write_markdown(args.markdown, version, rows, total)

    if args.json:
        print(json.dumps({"tool": "gate", "version": version,
                          "total": len(rows), "failed": len(failed),
                          "seconds": total, "gates": rows},
                         ensure_ascii=False, indent=2))
        return 0 if not failed else 1

    print(f"扣帽子工程 门禁  v{version}")
    print("-" * 66)
    for row in rows:
        if row.get("skipped"):
            print(f"SKIP  {row['name']:<8} {'-':>6}   {row['skipped']}")
            continue
        mark = "PASS" if row["passed"] else "FAIL"
        detail = f"  {row['detail']}" if row["detail"] else ""
        print(f"{mark}  {row['name']:<8} {row['seconds']:>6.2f}s{detail}")
    print("-" * 66)
    if failed:
        for row in failed:
            gate = gate_by_key(row["key"])
            print(f"\n{row['name']} 失败：")
            for line in row["problems"]:
                print(f"  {line}")
            print(f"  挡的是: {gate['protects']}")
            print(f"  先看:   {gate['hint']}")
        print(f"\n失败：{len(failed)}/{len(rows)} 道，耗时 {total}s")
        return 1
    print(f"{len(rows)} 道全通过，耗时 {total}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
