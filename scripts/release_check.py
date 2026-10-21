#!/usr/bin/env python3
"""发版前的一致性与发版后的回收复检。

原来这两步写在 release.yml 的 bash 片段里，只能跑在 ubuntu 上：
`cat VERSION`、`sha256sum -c` 在 Windows runner 上都不存在。而"这条发布门禁
在 Windows 上跑不了"本身就是个洞——tag 一致性和产物校验是最该两端都验的。

用法:
    python3 scripts/release_check.py --tag v1.10.1
    python3 scripts/release_check.py --tag v1.10.1 \\
        --local dist/koumaozi-1.10.1.zip \\
        --remote downloaded/koumaozi-1.10.1.zip \\
        --sum downloaded/koumaozi-1.10.1.zip.sha256

退出码: 0 通过；1 有问题。
"""
import argparse
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUM_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$")


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_tag(tag):
    """tag 必须与 VERSION 一致。

    `v1.10.1` 和 `v1.10.1.0`、`release-1.10.1` 都不算对上——宁可报错让人
    改一次 tag，也不要让两个地方各说各话，最后装出来的版本号和 Release
    页面写的不是一回事。
    """
    version_path = os.path.join(ROOT, "VERSION")
    if not os.path.isfile(version_path):
        return [f"找不到 VERSION 文件: {version_path}"]
    with open(version_path, "r", encoding="utf-8") as handle:
        version = handle.read().strip()
    if tag != f"v{version}":
        return [f"VERSION 是 {version}，tag 是 {tag}，对不上",
                "发版请先改 VERSION 再打同名 tag"]
    print(f"版本 {version} 与 tag {tag} 一致")
    return []


def check_sum_file(sum_path):
    """`sha256sum -c` 的等价物：文件里写的哈希要等于文件本身算出来的。"""
    if not os.path.isfile(sum_path):
        return [f"找不到校验文件: {sum_path}"], None
    base = os.path.dirname(sum_path)
    problems, checked = [], 0
    with open(sum_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            found = SUM_LINE_RE.match(line)
            if not found:
                problems.append(f"校验文件格式不对: {line!r}")
                continue
            expected, name = found.group(1).lower(), found.group(2)
            target = os.path.join(base, os.path.basename(name))
            if not os.path.isfile(target):
                problems.append(f"校验文件提到的包不存在: {name}")
                continue
            actual = digest(target)
            if actual != expected:
                problems.append(f"{name} 哈希不符: 文件写 {expected}，实际 {actual}")
            else:
                checked += 1
    if not checked and not problems:
        problems.append("校验文件是空的")
    return problems, checked


def compare(local, remote):
    """发布出去的那份和本地验过的那份必须是同一个字节序列。"""
    for path in (local, remote):
        if not os.path.isfile(path):
            return [f"找不到文件: {path}"]
    left, right = digest(local), digest(remote)
    if left != right:
        return [f"发布出去的包与本地验过的包不一致: 本地 {left} / 远端 {right}"]
    print(f"回收复检通过: {os.path.basename(remote)} {right}")
    return []


def main(argv=None):
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import common
    common.ensure_utf8_stdout()

    parser = argparse.ArgumentParser(description="发版一致性与产物复检")
    parser.add_argument("--tag", required=True, help="tag 名，如 v1.10.1")
    parser.add_argument("--local", default=None, help="本地待发布的包")
    parser.add_argument("--remote", default=None, help="发布后回收的包")
    parser.add_argument("--sum", default=None, help="随包发布的 .sha256 文件")
    args = parser.parse_args(argv)

    problems = check_tag(args.tag)

    if args.sum:
        sum_problems, checked = check_sum_file(args.sum)
        problems.extend(sum_problems)
        if checked:
            print(f"校验文件核对通过: {checked} 个包")

    if args.local and args.remote:
        problems.extend(compare(args.local, args.remote))
    elif bool(args.local) != bool(args.remote):
        problems.append("--local 和 --remote 要一起给，只给一个没法比")

    if problems:
        print("发版检查  失败")
        for line in problems:
            print(f"  × {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
