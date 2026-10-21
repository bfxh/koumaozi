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
CORPUS_RE = re.compile(r"^CRP-\d{2,3}$")

# 语料模拟的"野外特征"。语料的价值不在于条数，而在于它长得像不像真实评论区：
# 教科书式的完整句子永远测不出漏检和误伤。给每条语料标上它模拟了什么特征，
# "像不像"就变成可检查的东西——每个特征都必须至少有一条语料在用。
CORPUS_TRAITS = {
    "colloquial": "口语插入语、省略主语、语气词",
    "no-punct": "句内无标点连写",
    "homophone": "谐音或形近规避（公蜘）",
    "repeat": "叠字或重复施压（双标双标双标）",
    "rhetorical": "反问式定性（这不是…吗）",
    "mixed": "同一句叠加多顶帽子 / 多个句式",
    "long": "长段落里帽子只占一句，其余是事实陈述",
    "single-quote": "单引号标记「提到某个词」",
    "quotative": "转述他人指控（说我 / 被指 / 骂我）",
    "denial": "明确自辩否认（我没收钱）",
    "emoji": "表情符与帽子里外交替出现",
}

# 这几个特征缺一条，"语料像真实评论区"就退化成口号了。
REQUIRED_TRAITS = ("colloquial", "no-punct", "homophone", "repeat", "rhetorical",
                   "mixed", "long", "single-quote", "quotative", "denial", "emoji")

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


_JSON_CACHE = {}


def load_json(name):
    """按 (文件名, mtime) 缓存解析结果。

    90 个测试里有大量重复读 hats.json / patterns.json，每次都重新 parse
    一遍纯属白烧（实测占了单测总耗时的一半）。mtime 进 key 是为了改了
    数据文件能立刻失效，不会读到旧内容。

    ⚠️ 返回的是共享对象，**不要就地修改**。要改先自己 copy 一份。
    """
    path = os.path.join(DATA_DIR, name)
    stamp = os.path.getmtime(path)
    key = (name, stamp)
    if key not in _JSON_CACHE:
        with open(path, "r", encoding="utf-8") as fh:
            _JSON_CACHE[key] = json.load(fh)
        # 只留当前文件的最新版本，避免长期运行时越攒越多
        for stale in [item for item in _JSON_CACHE if item[0] == name and item != key]:
            _JSON_CACHE.pop(stale, None)
    return _JSON_CACHE[key]


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


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read_version(root=None):
    """版本号只认 VERSION 一处。SKILL.md 与 CHANGELOG 的同步由门禁校验。"""
    root = root or REPO_ROOT
    with open(os.path.join(root, "VERSION"), "r", encoding="utf-8") as fh:
        value = fh.read().strip()
    if not VERSION_RE.match(value):
        raise ValueError(f"VERSION 不是语义化版本号: {value!r}")
    return value


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
    # 被动式转述："该账号被指收钱发帖"是复述他人的指控，跟"他就是收钱的"不是一回事。
    "被指", "被质疑",
    # 劝阻句式："别动不动就说别人是带节奏"——这句话在反对贴标签，不是在使用标签。
    "说别人是", "说人家是",
)

QUOTE_PAIRS = (("“", "”"), ("「", "」"), ("『", "』"), ("《", "》"), ("‘", "’"))

# 单字符成对的引号（直引号）：靠奇偶判断"命中处是否在一对引号里面"。
# 中文评论区大量用单引号做"提到某个词"的标记：评论区里有人用'公知'这个词攻击他。
# 只认双引号会把这种元讨论判成正在使用帽子。
STRAIGHT_QUOTES = ('"', "'")


REVERSAL_RE = re.compile(r"(?:是什么|是啥|是哪种|吗|嘛|呢|[?？])")

# 反问式定性的主语。「我不是公知」是第一人称否认；「这不是典型的公知话术吗」
# 是拿指示代词把对方钉在帽子上——两句话都带"不是"，功能正好相反。
RHETORICAL_SUBJECTS = ("这", "那", "您", "你", "他", "她", "它")
CLAUSE_BREAKS = "，。；！？：、\n"


def _cut_at_break(text):
    """截到第一个断句标点之前。反问标记必须和被否定的那个词同处一句。

    「我不是公知，这不是明摆着的吗」——右边 12 字里确实有"吗"，但那是下一个
    分句,"我不是公知"本身是清楚的否认。不截断就会把它翻成"正在使用"。
    """
    cuts = [text.find(broken) for broken in CLAUSE_BREAKS if broken in text]
    return text[:min(cuts)] if cuts else text


def _rhetorical_frame(text, start, end):
    """「这不是…X…吗」：形式带否定词，功能是定性。

    只看紧邻的"不是"不够——「这不是典型的公知话术吗」中间隔了四个字，
    紧邻判定抓不到，整句就按否认算，帽子白扣了。

    但也不能一律放宽：「我不是公知，这不是明摆着的吗」里"不是"的主语是第一
    人称，讲的是否认。所以要求"不是"前面三字内出现过这/那/你/他/她/它，
    且到命中处之间没有断句。
    """
    tail = text[max(0, start - 12):start]
    pos = tail.rfind("不是")
    if pos < 0:
        return False
    if not any(mark in tail[max(0, pos - 3):pos] for mark in RHETORICAL_SUBJECTS):
        return False
    between = tail[pos + 2:]
    if any(broken in between for broken in CLAUSE_BREAKS):
        return False
    return bool(REVERSAL_RE.search(_cut_at_break(text[end:end + 12])))


def context_role(text, start, end, window=8):
    """判断命中处是"在用帽子"还是"在提帽子"。

    三类例外必须先排除，否则会把最典型的扣帽子句式误判成否认：
    - "这不是 X 是什么？" —— 反问式定性，是 used
    - "我没有收钱" —— 否认句，是 denied
    - "他说我是公知" —— 元讨论，是 quoted
    """
    left = text[max(0, start - window):start]
    right = _cut_at_break(text[end:end + 12])

    if left.rstrip().endswith(("不是", "不属于", "不像")) and REVERSAL_RE.search(right):
        return "used"
    if _rhetorical_frame(text, start, end):
        return "used"
    # 紧邻的否定：反问标记没出现时，"这不像 X""这不属于 X" 就是明确的否认。
    # 只在紧邻时生效——"不像话，这就是 X" 里的"不像"隔着一个词，不能算。
    if left.rstrip().endswith(("不属于", "不像")):
        return "denied"

    for prefix in NEGATION_PREFIXES:
        if prefix in left:
            return "denied"
    for prefix in META_PREFIXES:
        if prefix in left:
            return "quoted"
    for open_q, close_q in QUOTE_PAIRS:
        if text.count(open_q, 0, start) > text.count(close_q, 0, start):
            return "quoted"
    for mark in STRAIGHT_QUOTES:
        if text.count(mark, 0, start) % 2 == 1:
            return "quoted"
    return "used"


def relpath(path):
    try:
        return os.path.relpath(path, REPO_ROOT).replace("\\", "/")
    except ValueError:
        return path
