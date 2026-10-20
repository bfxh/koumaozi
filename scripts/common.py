"""共享工具：数据加载、分句、编码兜底。

Python 3.8+ 标准库，零第三方依赖。
"""
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "data")

HAT_RE = re.compile(r"^HAT-F[1-8]-\d{2}$")
PATTERN_RE = re.compile(r"^PAT-\d{2}$")
COMBO_RE = re.compile(r"^CMB-\d{2}$")
CORPUS_RE = re.compile(r"^CRP-\d{2}$")

# 强化词：出现在帽子/句式命中句附近时，说明不只是"提到"，而是在"使用"
AMPLIFIERS = (
    "跪", "舔", "骨头", "主子", "这帮", "那帮", "果然", "难怪", "不就是",
    "说白了", "无非", "纯属", "典型的", "标准的", "又一个", "不愧是",
    "笑死", "绷不住", "急了", "急了", "散了吧", "不用看", "有本事",
)


def ensure_utf8_stdout():
    """Windows 控制台默认 GBK，中文输出会炸。强制 UTF-8。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def load_json(name):
    path = os.path.join(DATA_DIR, name)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_hats():
    return load_json("hats.json")


def load_patterns():
    return load_json("patterns.json")


def load_combos():
    return load_json("combos.json")


def load_corpus():
    return load_json("corpus.json")


def flatten_hats():
    """返回 [{...hat, '_patterns': [compiled]}...]，帽子自带的正则不在此处。"""
    return load_hats()["hats"]


def family_map():
    return load_hats()["families"]


def hat_lookup():
    """name / alias / id -> hat"""
    table = {}
    for hat in flatten_hats():
        table[hat["id"]] = hat
        table[hat["name"]] = hat
        for alias in hat.get("aliases", []):
            table.setdefault(alias, hat)
    return table


def family_lookup():
    table = {}
    for hat in flatten_hats():
        table[hat["family"]] = hat["family"]
    return table


SENTENCE_SPLIT_RE = re.compile(r"(?<=[。！？；!?;])|\n+")


def split_sentences(text):
    """粗分句。不追求语言学正确，只求定位可读。保留原文偏移。"""
    sentences = []
    cursor = 0
    for chunk in SENTENCE_SPLIT_RE.split(text):
        if not chunk:
            continue
        stripped = chunk.strip()
        if not stripped:
            cursor += len(chunk)
            continue
        start = text.find(stripped, cursor)
        if start < 0:
            start = cursor
        sentences.append({"text": stripped, "start": start, "end": start + len(stripped)})
        cursor = start + len(stripped)
    return sentences


_FENCE_RE = re.compile(r"```.*?```|~~~.*?~~~", re.S)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def strip_code(text):
    """去掉代码块、行内代码、HTML 注释。文档里的示例代码不是观点表达。"""
    text = _FENCE_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = _HTML_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = _INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), text)
    return text


def nearby_amplifier(text, start, end, window=24):
    """命中点前后是否出现强化词。"""
    left = max(0, start - window)
    right = min(len(text), end + window)
    segment = text[left:right]
    hit = [word for word in AMPLIFIERS if word in segment]
    return hit


def severity_for(intensity, amplifiers, role="used"):
    """帽子本身的攻击强度 + 上下文强化，共同决定严重性。

    role 区分"使用帽子"与"提到帽子"：
    - used：真的在扣
    - denied：否定句里（"我没有收钱"），是被否认的帽子
    - quoted：引号内，是被引用的帽子

    denied / quoted 一律降一级——扫描器不实现这条，就会把
    "我没有收钱"判成"收钱"，这是最容易被当成工具不可用的误报。
    """
    score = intensity + (1 if len(amplifiers) >= 2 else 0)
    if score >= 4:
        level = "Critical"
    elif score >= 2:
        level = "Warning"
    else:
        level = "Info"

    if role != "used":
        order = ["Info", "Warning", "Critical"]
        level = order[max(0, order.index(level) - 1)]
    return level


NEGATION_PREFIXES = (
    "不是", "没有", "并非", "而不是", "别说", "不要", "绝不",
    "不存在", "从来不", "算不上", "谈不上",
)

META_PREFIXES = (
    "说我", "说他", "说她", "说你是", "说他是", "被称为", "被说成",
    "骂我", "骂他", "叫我", "叫他", "自称", "被贴上", "扣我",
    # 存疑指控 / 转述他人指控："同事质疑对方收钱"是记录别人的怀疑，不是本人在断言。
    # 代价是"我质疑你收钱"也会降一级——可接受：把怀疑说成怀疑，本来就比直接定性弱。
    "质疑", "怀疑", "指责", "控诉", "追责",
)

QUOTE_PAIRS = (("“", "”"), ("「", "」"), ("『", "』"), ("《", "》"))


REVERSAL_RE = re.compile(r"(?:是什么|是啥|是哪种|吗|嘛|呢|[?？])")


def context_role(text, start, end, window=8):
    """判断命中处是"在用帽子"还是"在提帽子"。

    三类例外必须先排除，否则会把最典型的扣帽子句式误判成否认：
    - "这不是 X 是什么？" —— 反问式定性，是 used
    - "我没有收钱" —— 否认句，是 denied
    - "他说我是公知" —— 元讨论，是 quoted
    """
    left = text[max(0, start - window):start]
    right = text[end:end + 12]

    if left.rstrip().endswith(("不是", "不属于", "不像")) and REVERSAL_RE.search(right):
        return "used"

    for prefix in NEGATION_PREFIXES:
        if prefix in left:
            return "denied"
    for prefix in META_PREFIXES:
        if prefix in left:
            return "quoted"
    for open_q, close_q in QUOTE_PAIRS:
        if text.count(open_q, 0, start) > text.count(close_q, 0, start):
            return "quoted"
    if text.count('"', 0, start) % 2 == 1:
        return "quoted"
    return "used"


def relpath(path):
    try:
        return os.path.relpath(path, REPO_ROOT).replace("\\", "/")
    except ValueError:
        return path
