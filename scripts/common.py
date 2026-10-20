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


def severity_for(intensity, amplifiers):
    """帽子本身的攻击强度 + 上下文强化，共同决定严重性。"""
    score = intensity + (1 if len(amplifiers) >= 2 else 0)
    if score >= 4:
        return "Critical"
    if score >= 2:
        return "Warning"
    return "Info"


def relpath(path):
    try:
        return os.path.relpath(path, REPO_ROOT).replace("\\", "/")
    except ValueError:
        return path
