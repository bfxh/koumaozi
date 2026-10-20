#!/usr/bin/env python3
"""打包成可安装的 skill 包，并自检它真的能跑。

打包谁都会做，难的是**证明发出去的包能用**。常见的假 CD 是：源码目录跑通门禁，
打出来的 zip 少了一个 data 文件，用户装上去当场报错，而 CI 一路绿。

所以这里的 --verify 做的是：
    解压到干净临时目录 → 按 MANIFEST 校验每个文件的 sha256 →
    在**解压后**的目录里跑 verify_data / corpus_check / 扫描 / 生成 / 改稿对比

验证对象是被交付的那一份，不是源目录。

用法:
    python3 scripts/package.py                  # 打包到 dist/
    python3 scripts/package.py --verify         # 打包 + 自检
    python3 scripts/package.py --verify dist/koumaozi-1.3.0.zip   # 只验已有包
    python3 scripts/package.py --keep           # 自检后保留解压目录，便于排查
    python3 scripts/package.py --check-dir      # 核对已装目录（默认当前目录）

退出码: 0 通过；1 打包或自检失败。
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

INCLUDE_DIRS = ("data", "scripts", "references", "examples")
INCLUDE_FILES = ("SKILL.md", "README.md", "CHANGELOG.md", "LICENSE", "VERSION")
SKIP_NAMES = ("__pycache__", "report.json", "dist")
SKIP_SUFFIXES = (".pyc", ".pyo", ".sha256")
MANIFEST_NAME = "MANIFEST.sha256"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read_version(root=None):
    root = root or common.REPO_ROOT
    path = os.path.join(root, "VERSION")
    with open(path, "r", encoding="utf-8") as fh:
        value = fh.read().strip()
    if not VERSION_RE.match(value):
        raise ValueError(f"VERSION 不是语义化版本号: {value!r}")
    return value


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(root=None):
    """返回 [(相对路径, 绝对路径)]，白名单收集，不靠 git ls-files（打包要能脱离 git 跑）。"""
    root = root or common.REPO_ROOT
    picked = []
    for name in INCLUDE_FILES:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"缺少必需文件: {name}")
        picked.append((name, path))
    for folder in INCLUDE_DIRS:
        base = os.path.join(root, folder)
        if not os.path.isdir(base):
            raise FileNotFoundError(f"缺少必需目录: {folder}")
        for current, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_NAMES)
            for filename in sorted(files):
                if filename in SKIP_NAMES or filename.endswith(SKIP_SUFFIXES):
                    continue
                absolute = os.path.join(current, filename)
                rel = os.path.relpath(absolute, root).replace("\\", "/")
                picked.append((rel, absolute))
    return sorted(picked)


def build_manifest(entries):
    lines = []
    for rel, absolute in entries:
        lines.append(f"{sha256_of(absolute)}  {os.path.getsize(absolute):>8}  {rel}")
    return "\n".join(lines) + "\n"


def build(out_dir=None, root=None):
    root = root or common.REPO_ROOT
    out_dir = out_dir or os.path.join(root, "dist")
    version = read_version(root)
    entries = collect(root)
    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, f"koumaozi-{version}.zip")

    manifest = build_manifest(entries)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(MANIFEST_NAME, manifest)
        for rel, absolute in entries:
            zf.write(absolute, arcname=rel)
    checksum = sha256_of(target)
    checksum_path = target + ".sha256"
    with open(checksum_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{checksum}  {os.path.basename(target)}\n")
    return {
        "version": version,
        "path": target,
        "sha256": checksum,
        "checksum_path": checksum_path,
        "files": len(entries),
        "bytes": os.path.getsize(target),
    }


def parse_manifest(text):
    """返回 {relpath: (sha256, size)}。格式损坏直接抛，不猜。"""
    table = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) != 3:
            raise ValueError(f"MANIFEST 行格式非法: {line!r}")
        digest, size, rel = parts
        if not re.match(r"^[0-9a-f]{64}$", digest):
            raise ValueError(f"MANIFEST sha256 非法: {line!r}")
        table[rel] = (digest, int(size))
    return table


def extract(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        if MANIFEST_NAME not in names:
            raise ValueError(f"包内没有 {MANIFEST_NAME}，无法校验完整性")
        # 防目录穿越：包里的名字必须是相对路径，不许有 .. 或绝对路径
        for name in names:
            normalized = os.path.normpath(name).replace("\\", "/")
            if normalized.startswith("../") or os.path.isabs(normalized) or ":" in normalized:
                raise ValueError(f"包内路径非法: {name!r}")
        zf.extractall(dest)
    with open(os.path.join(dest, MANIFEST_NAME), "r", encoding="utf-8") as fh:
        return parse_manifest(fh.read())


def check_contents(dest, manifest):
    """清单必须双向对得上：声明的一个不少，磁盘上的一个不多。"""
    problems = []
    on_disk = set()
    for current, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for filename in files:
            if filename == MANIFEST_NAME or filename.endswith(SKIP_SUFFIXES):
                continue
            rel = os.path.relpath(os.path.join(current, filename), dest).replace("\\", "/")
            on_disk.add(rel)

    declared = set(manifest)
    for missing in sorted(declared - on_disk):
        problems.append(f"清单里有但包里没有: {missing}")
    for extra in sorted(on_disk - declared):
        problems.append(f"包里有但清单没登记: {extra}")
    for rel in sorted(declared & on_disk):
        digest, size = manifest[rel]
        absolute = os.path.join(dest, rel.replace("/", os.sep))
        if os.path.getsize(absolute) != size:
            problems.append(f"大小不符: {rel}")
        elif sha256_of(absolute) != digest:
            problems.append(f"内容被改动: {rel}")
    return problems


def run_in(dest, args):
    result = subprocess.run([sys.executable] + args, cwd=dest,
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace")
    return result


def smoke(dest):
    """在解压目录里跑命令。任何一步失败都要带出 stderr，否则报错等于没说。"""
    problems = []

    for script in ("verify_data.py", "corpus_check.py"):
        result = run_in(dest, [os.path.join("scripts", script)])
        if result.returncode != 0:
            tail = (result.stdout or "").strip().splitlines()[-4:]
            problems.append(f"{script} 在解压目录里失败: " + " | ".join(tail))

    result = run_in(dest, [os.path.join("scripts", "hat_scan.py"),
                           "--text", "典型的带节奏，一条多少钱？", "--json"])
    if result.returncode != 0:
        problems.append("hat_scan 在解压目录里跑不起来: " + (result.stderr or "").strip()[:200])
    else:
        import json
        try:
            summary = json.loads(result.stdout)["summary"]
        except (KeyError, ValueError) as exc:
            problems.append(f"hat_scan 输出不是预期 JSON: {exc}")
        else:
            if summary.get("hat_hits", 0) + summary.get("pattern_hits", 0) < 1:
                problems.append(f"装完之后扫不出东西，数据文件大概率没打进去: {summary}")

    result = run_in(dest, [os.path.join("scripts", "hat_generate.py"),
                           "--target", "某方案", "--combo", "CMB-01", "--json", "--seed", "3"])
    if result.returncode != 0:
        problems.append("hat_generate 在解压目录里跑不起来: " + (result.stderr or "").strip()[:200])
    else:
        import json
        try:
            data = json.loads(result.stdout)
        except ValueError:
            problems.append("hat_generate 输出不是 JSON")
        else:
            if data.get("mode") != "combo" or not data.get("steps"):
                problems.append(f"连招生成结构不对: {list(data)[:6]}")

    return problems


def check_dir(path=None):
    """核对一个**已安装目录**是否还是当初发出去的那份。

    装完之后目录是会被改的：开发态软链、手改一行试试、被别的工具覆盖、
    半路中断的 cp。这些都不会报错，只会在某天扫不出东西时才暴露。
    清单就在安装目录里（MANIFEST.sha256），核对一遍很便宜，没必要靠猜。

    源码态没有 MANIFEST——那不是失败，是"没什么可核对"。
    """
    path = os.path.abspath(path or common.REPO_ROOT)
    manifest_path = os.path.join(path, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        return {"path": path, "files": 0, "problems": [], "passed": True,
                "skipped": f"没有 {MANIFEST_NAME}（源码态，未打包）"}
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = parse_manifest(fh.read())
    problems = check_contents(path, manifest)
    return {"path": path, "files": len(manifest), "problems": problems,
            "passed": not problems, "skipped": None}


def verify(zip_path, keep=False):
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"找不到包: {zip_path}")
    workdir = tempfile.mkdtemp(prefix="koumaozi-verify-")
    dest = os.path.join(workdir, "unpacked")
    os.makedirs(dest)
    try:
        manifest = extract(zip_path, dest)
        problems = check_contents(dest, manifest)
        if not problems:
            problems.extend(smoke(dest))
        if keep and problems:
            problems.append(f"解压目录保留在: {dest}")
        return {"path": zip_path, "files": len(manifest), "problems": problems,
                "passed": not problems}
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="打包并自检 skill 包")
    parser.add_argument("--out", default=None, help="输出目录，默认 dist/")
    parser.add_argument("--verify", nargs="*", default=None,
                        help="打包后自检；也可给出一个或多个已有 zip 路径")
    parser.add_argument("--keep", action="store_true", help="保留解压目录便于排查")
    parser.add_argument("--check-dir", nargs="?", const=".", default=None,
                        help="核对已安装目录是否与自带 MANIFEST 一致（默认当前目录）")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.check_dir is not None:
        result = check_dir(args.check_dir)
        if args.json:
            import json
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif result.get("skipped"):
            print(f"核对 {result['path']}\n跳过：{result['skipped']}")
        else:
            print(f"核对 {result['path']}  {result['files']} 个文件")
            for problem in result["problems"]:
                print(f"  × {problem}")
            print("通过" if result["passed"] else f"失败：{len(result['problems'])} 项")
        return 0 if result["passed"] else 1

    if args.verify is None:
        built = build(args.out)
        print(f"打包 {os.path.basename(built['path'])}  {built['files']} 个文件  "
              f"{built['bytes'] / 1024:.1f} KiB")
        print(f"sha256 {built['sha256']}")
        return 0

    # --verify 不带值：先打包再验；带值：只验指定的那些 zip。
    # 允许多个是有原因的：dist/ 里通常堆着好几个版本，`dist/koumaozi-*.zip`
    # 展开后是多个参数，只收一个会直接「unrecognized arguments」。
    targets = args.verify
    if targets is None:
        built = build(args.out)
        print(f"打包 {os.path.basename(built['path'])}  {built['files']} 个文件  "
              f"{built['bytes'] / 1024:.1f} KiB")
        print(f"sha256 {built['sha256']}")
        return 0

    if not targets:
        built = build(args.out)
        targets = [built["path"]]
        print(f"打包 {os.path.basename(built['path'])}  {built['files']} 个文件  "
              f"{built['bytes'] / 1024:.1f} KiB")

    results = [verify(path, keep=args.keep) for path in targets]
    if args.json:
        import json
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for result in results:
            print(f"自检 {os.path.basename(result['path'])}  {result['files']} 个文件")
            for problem in result["problems"]:
                print(f"  × {problem}")
            print("通过" if result["passed"] else f"失败：{len(result['problems'])} 项")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
