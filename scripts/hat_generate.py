#!/usr/bin/env python3
"""扣帽子生成器：按家族、帽子、句式模板拼装带帽子的短评。

设计约束：
1. 只做模板拼装，不做自由创作——保证产出可审计、可复现（同 seed 同结果）。
2. 每条产出必须同时给出该帽子的破解点，禁止"只会扣不会拆"。
3. 产出永远附带使用场景声明，供教学、讽刺写作、舆情复盘使用。

用法:
    python3 scripts/hat_generate.py --target "某科技博主" --family motive-contamination --count 5
    python3 scripts/hat_generate.py --target "某方案" --hat 巨婴 --pattern PAT-07 --json
    python3 scripts/hat_generate.py --target "某账号" --intensity 3 --seed 42 --no-disclaimer
"""
import argparse
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

SLOT_RE = re.compile(r"\{([^{}\s]+)\}")

SLOT_DEFAULTS = {
    "立场": "对面那套",
    "代价": "结账码准备好了",
    "收益": "带薪发帖",
    "荒谬推论": "谁都别说话了",
    "极端化改写": "干脆把规矩全废了",
    "议题": "这事",
    "我方": "明白人",
    "对方": "对面",
    "选项A": "闭嘴",
    "选项B": "认错",
    "污名群体": "那帮人",
    "群体": "这类人",
    "让步A": "退一步",
    "极端后果B": "收不住场",
    "灾难": "更大的窟窿",
    "领域": "这个领域",
    "权威身份": "权威",
    "机构": "主管部门",
    "表层议题": "技术细节",
    "宏大议题": "大是大非",
    "细节": "细枝末节",
    "大是大非": "大是大非",
    "单一案例": "一张截图",
    "案例": "一个案例",
    "整体结论": "整体不行",
    "断言": "这个结论",
    "另一方": "对面",
    "同一行为": "同样的事",
    "价值": "底线",
    "身份": "成年人",
    "概念": "专业主义",
    "替换概念": "装样子",
    "曲解": "挡箭牌",
    "指控行为": "替人说话",
    "负面行为": "选择性失明",
    "重罪名词": "公开抢劫",
    "小事": "操作失误",
    "重大罪名": "不可原谅的越界",
    "指控": "问题所在",
    "正面词": "专业",
    "反常": "奇怪",
    "反常2": "说不通的地方",
    "高级词": "清醒",
    "奖项": "年度观察奖",
    "比例": "八成",
    "极小比例": "不到百分之三",
    "行为": "这番表态",
    "补课动作": "补两本书",
}

PLATFORM_HINTS = {
    "weibo": "短句、感叹号多、@ 对方、结尾带话题标签",
    "zhihu": "先给结论再补一句场景，用'说白了'收口",
    "tieba": "口语化、反问、带地域或群体简称",
    "comment": "一到两句、直接贴帽子、不留余地",
    "longform": "段落开头定性、中段举例、结尾回到定性",
}

USAGE_NOTE = "使用场景：公共议题复盘 / 修辞教学 / 讽刺写作。禁止用于对真实个人的攻击。"


def pick_hats(args, rng):
    hats = common.flatten_hats()
    if args.hat:
        table = common.hat_lookup()
        hit = table.get(args.hat)
        if hit is None:
            raise SystemExit(f"未知帽子: {args.hat}")
        return [hit]
    pool = hats
    if args.family:
        pool = [h for h in pool if h["family"] == args.family]
        if not pool:
            raise SystemExit(f"未知家族: {args.family}")
    if args.intensity:
        pool = [h for h in pool if h["intensity"] <= args.intensity]
    if not pool:
        raise SystemExit("过滤后没有可用帽子，放宽 --intensity 或 --family")
    rng.shuffle(pool)
    return pool[: max(1, args.count)]


def pick_pattern(hat, patterns, args, rng):
    if args.pattern:
        for pattern in patterns:
            if args.pattern in (pattern["id"], pattern["name"]):
                return pattern
        raise SystemExit(f"未知句式: {args.pattern}")
    same_family = [p for p in patterns if p.get("family_hint") == hat["family"]]
    return rng.choice(same_family or patterns)


def fill(template, slots):
    missing = []

    def replace(match):
        key = match.group(1)
        if key in slots and slots[key]:
            return slots[key]
        missing.append(key)
        return "\x00"

    filled = SLOT_RE.sub(replace, template)
    if "\x00" in filled:
        return None, sorted(set(missing))
    return filled, []


def generate(args):
    rng = random.Random(args.seed)
    patterns = common.load_patterns()["patterns"]
    hats = pick_hats(args, rng)
    slots = dict(SLOT_DEFAULTS)
    slots["对象"] = args.target
    if args.topic:
        slots["议题"] = args.topic
        slots["表层议题"] = args.topic
    for pair in args.slot or []:
        if "=" not in pair:
            raise SystemExit(f"--slot 需要 key=value 形式: {pair}")
        key, value = pair.split("=", 1)
        slots[key] = value

    results = []
    attempts = 0
    while len(results) < args.count and attempts < args.count * 8:
        attempts += 1
        hat = hats[len(results) % len(hats)]
        pattern = pick_pattern(hat, patterns, args, rng)
        template = rng.choice(pattern["template"])
        local_slots = dict(slots)
        local_slots["帽子"] = hat["name"]
        text, missing = fill(template, local_slots)
        if text is None:
            continue
        if any(item["text"] == text for item in results):
            continue
        results.append({
            "text": text,
            "hat": {"id": hat["id"], "name": hat["name"], "family": hat["family"], "intensity": hat["intensity"]},
            "pattern": {"id": pattern["id"], "name": pattern["name"]},
            "counter": hat["counter"],
            "platform_hint": PLATFORM_HINTS.get(args.platform, ""),
        })

    if not results:
        raise SystemExit("模板槽位无法填充，检查 --slot 参数")
    return results


def emit_text(results, args):
    if not args.no_disclaimer:
        print(f"# {USAGE_NOTE}")
        if args.platform:
            print(f"# 平台调性：{PLATFORM_HINTS.get(args.platform, args.platform)}")
        print()
    for index, item in enumerate(results, 1):
        print(f"{index}. {item['text']}")
        print(f"   投放: {item['hat']['name']} ({item['hat']['id']}) + {item['pattern']['name']} ({item['pattern']['id']})")
        print(f"   强度: {item['hat']['intensity']}/3")
        print("   破解: " + "；".join(item["counter"][:2]))
        print()


def main(argv=None):
    common.ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="扣帽子生成器（模板拼装，可复现）")
    parser.add_argument("--target", required=True, help="被扣帽子的对象（立场、行为、群体倾向，不要写真实人名）")
    parser.add_argument("--topic", help="议题，用于填充模板")
    parser.add_argument("--hat", help="指定帽子（id 或名称）")
    parser.add_argument("--family", help="指定帽子家族")
    parser.add_argument("--pattern", help="指定句式（PAT-xx 或名称）")
    parser.add_argument("--intensity", type=int, choices=[1, 2, 3], help="最高攻击强度")
    parser.add_argument("--platform", choices=sorted(PLATFORM_HINTS), help="平台调性提示")
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--seed", type=int, default=0, help="随机种子，同种子同结果")
    parser.add_argument("--slot", action="append", help="覆盖槽位，如 --slot 比例=九成")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-disclaimer", action="store_true", help="不输出使用场景声明")
    args = parser.parse_args(argv)

    results = generate(args)
    if args.json:
        payload = {
            "tool": "hat_generate",
            "target": args.target,
            "platform": args.platform,
            "seed": args.seed,
            "usage_note": USAGE_NOTE,
            "results": results,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    emit_text(results, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
