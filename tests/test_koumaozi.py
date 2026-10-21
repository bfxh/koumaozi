"""扣帽子工程的门禁测试。

跑法:
    python -m unittest discover -s tests -v
"""
import io
import json
import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from contextlib import redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

import common  # noqa: E402
import build_web  # noqa: E402
import corpus_check  # noqa: E402
import doc_smoke  # noqa: E402
import gate  # noqa: E402
import hat_diff  # noqa: E402
import hat_generate  # noqa: E402
import hat_scan  # noqa: E402
import package  # noqa: E402
import release_notes  # noqa: E402
import verify_data  # noqa: E402
import web_parity  # noqa: E402
import wordcount  # noqa: E402


class ShellResult:
    """子进程结果的替身：Windows 上命令行的中文是 GBK 出来的，得自己解码。"""

    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def decode_console(raw):
    """按平台猜编码解码子进程输出。

    PowerShell / cmd 在中文 Windows 上吐的是 ANSI 码页（cp936），不是 UTF-8；
    而 CI 的 Linux 上是 UTF-8。装脚本本身**不改**全局控制台编码——那会让
    在 cmd.exe 里直接跑的用户看到乱码，测试迁就它一次就好。
    """
    candidates = ["utf-8"]
    preferred = locale.getpreferredencoding(False)
    if preferred:
        candidates.append(preferred)
    candidates += ["gbk", "cp936"]
    for codec in candidates:
        try:
            return raw.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


class TestData(unittest.TestCase):
    def test_hat_count_floor(self):
        hats = common.flatten_hats()
        self.assertGreaterEqual(len(hats), 50, "帽子词条数低于地板值")

    def test_pattern_count(self):
        patterns = common.load_patterns()["patterns"]
        self.assertEqual(len(patterns), 24, "攻击句式应为 24 式")

    def test_family_coverage(self):
        families = common.family_map()
        counts = {}
        for hat in common.flatten_hats():
            counts[hat["family"]] = counts.get(hat["family"], 0) + 1
        self.assertEqual(len(families), 8)
        for family in families:
            self.assertGreaterEqual(counts.get(family, 0), 4, f"{family} 帽子不足")

    def test_every_hat_has_counter(self):
        for hat in common.flatten_hats():
            self.assertGreaterEqual(len(hat["counter"]), 2, hat["id"])
            self.assertGreaterEqual(len(hat["signal"]), 2, hat["id"])

    def test_every_pattern_example_is_detected_by_its_own_rule(self):
        """文档里写的示例，必须能被这一式自己的规则抓出来。

        原来有 3 条对不上：示例说"按你这逻辑，那…"，正则要求这两个词紧挨着，
        中间不许有逗号；示例说"专家早就定性了"，正则只认"定了"。用户照着示例
        学这一式的写法，换个场景写出来工具却说不算——文档成了误导。
        """
        compiled = hat_scan.compile_patterns()
        bad = []
        for pattern in common.load_patterns()["patterns"]:
            findings, _ = hat_scan.scan_text("<example>", pattern["example"], compiled)
            if pattern["id"] not in {item["pattern_id"] for item in findings}:
                bad.append((pattern["id"], pattern["example"]))
        self.assertEqual(bad, [], f"{len(bad)} 条示例自己的规则抓不到: {bad[:5]}")

    def test_every_hit_carries_a_remedy(self):
        """"只会扣不会拆"是这套工具的反面教材，所以命中必须带反制话术。"""
        compiled = hat_scan.compile_patterns()
        missing = []
        for hat in common.flatten_hats():
            findings, _ = hat_scan.scan_text("<t>", f"典型的{hat['name']}。", compiled)
            hits = [item for item in findings if item["pattern_id"] == hat["id"]]
            if not hits or not str(hits[0].get("remedy") or "").strip():
                missing.append(hat["id"])
        self.assertEqual(missing, [], f"这些帽子命中后没有反制话术: {missing}")

    def test_combo_count(self):
        self.assertEqual(len(common.load_combos()["combos"]), 10)

    def test_combo_examples_are_detected(self):
        """数据自洽：每条连招自己写的 example，必须能被自己的检测器识别出来。

        这条比"生成器产出能被回扫"更可靠——生成器随机挑模板，用词未必落在
        正则覆盖内；而 example 是写死的，它认不出自己就等于数据说谎。
        """
        patterns = hat_scan.compile_patterns()
        for combo in common.load_combos()["combos"]:
            findings, _ = hat_scan.scan_text("<example>", combo["example"], patterns)
            ids = [f["pattern_id"] for f in findings]
            self.assertIn(combo["id"], ids, f"{combo['id']} 的 example 自己认不出来: {ids}")

    def test_combo_break_at_in_sequence(self):
        for combo in common.load_combos()["combos"]:
            flat = []
            for stage in combo["sequence"]:
                flat.extend(stage if isinstance(stage, list) else [stage])
            self.assertIn(combo["break_at"], flat, combo["id"])
            self.assertGreaterEqual(len(combo["break_steps"]), 2, combo["id"])


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.patterns = hat_scan.compile_patterns()

    def scan(self, text, strip_code=True):
        findings, chars = hat_scan.scan_text("<t>", text, self.patterns, strip_code=strip_code)
        return findings, chars

    def test_detects_combo(self):
        text = "说这话的，标准公知体，不用看了。这么卖力地吹，一条多少钱？问了三遍不敢答，心里有数了。"
        findings, _ = self.scan(text)
        ids = {f["pattern_id"] for f in findings}
        self.assertIn("HAT-F1-01", ids)
        self.assertIn("PAT-02", ids)
        self.assertIn("PAT-18", ids)
        self.assertGreaterEqual(len(findings), 3)

    def test_neutral_text_is_clean(self):
        text = ("本次评审共收到十二份方案，按可维护性、部署成本、回滚速度三项指标逐条打分，"
                "最终采纳第三方案，因为它在回滚速度上快四倍，且不引入新的外部依赖。")
        findings, _ = self.scan(text)
        self.assertEqual(findings, [], f"中立文本误报: {findings}")

    def test_code_block_excluded(self):
        text = "```\n# 这种公知体，一条多少钱？\n```\n正文只有一句事实陈述。"
        findings, _ = self.scan(text, strip_code=True)
        self.assertEqual(findings, [])
        raw_findings, _ = self.scan(text, strip_code=False)
        self.assertTrue(raw_findings, "关闭剔除后应能命中代码块内的文本")

    def test_score_monotonic(self):
        short = "这种公知体，一条多少钱？"
        long_many = ("这种公知体，一条多少钱？带节奏的吧。你说我蠢，具体哪步错了？"
                     "问了三遍不敢答，心里有数了。历史会证明。")
        f1, c1 = self.scan(short)
        f2, c2 = self.scan(long_many)
        self.assertGreater(hat_scan.score(f2, c2)["label_score"],
                           hat_scan.score(f1, c1)["label_score"])

    def test_score_bounds(self):
        for text in ("", "短", "公知 公知 公知 公知 公知 公知 公知 公知"):
            findings, chars = self.scan(text)
            stats = hat_scan.score(findings, chars)
            self.assertGreaterEqual(stats["label_score"], 0)
            self.assertLessEqual(stats["label_score"], 100)

    def test_role_denied(self):
        findings, _ = self.scan("我没有收钱。")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["role"], "denied")
        self.assertEqual(findings[0]["severity"], "Info")

    def test_role_quoted(self):
        findings, _ = self.scan("他说我是公知。")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["role"], "quoted")
        self.assertEqual(findings[0]["severity"], "Info")

    def test_rhetorical_question_is_used(self):
        # "这不是 X 是什么？" 是反问式定性，不能判成否认
        findings, _ = self.scan("这不是境外势力是什么？")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["role"], "used")

    def role_of(self, text, pattern_id):
        findings, _ = self.scan(text)
        hit = [f for f in findings if f["pattern_id"] == pattern_id]
        self.assertTrue(hit, f"{pattern_id} 没命中: {text}")
        return hit[0]["role"]

    def test_rhetorical_question_across_words_is_used(self):
        """「这不是典型的公知话术吗」——"不是"和帽子隔了四个字，仍是反问定性。

        只看紧邻的"不是"会把整句当否认，帽子白扣。这条来自真实评论区的写法：
        反问句里很少把否定词紧贴在标签前面。
        """
        self.assertEqual(self.role_of("这不是典型的公知话术吗", "HAT-F1-01"), "used")

    def test_first_person_denial_is_not_flipped_by_later_question(self):
        """反例：「我不是公知，这不是明摆着的吗」

        后面的"吗"属于下一个分句。窗口不截断在断句标点处，就会把一句清楚的
        自辩翻成"正在使用帽子"——比漏检更糟，等于反过来冤枉被骂的人。
        """
        self.assertEqual(self.role_of("我不是公知，这不是明摆着的吗。", "HAT-F1-01"),
                         "denied")

    def test_third_person_rhetorical_is_used(self):
        self.assertEqual(self.role_of("他不是公知吗？天天上节目。", "HAT-F1-01"), "used")

    def test_plain_negation_stays_denied(self):
        self.assertEqual(self.role_of("他不是公知，是普通工程师。", "HAT-F1-01"), "denied")

    def test_not_like_is_denied(self):
        """"这不像 X" 是否认，不是使用。"""
        self.assertEqual(self.role_of("这不像公知说的话。", "HAT-F1-01"), "denied")

    def test_not_like_in_another_clause_does_not_deny(self):
        """「不像话，这就是双标」里的"不像"隔着一个词，不构成对"双标"的否认。

        不区分紧邻，"不像话"会把后面所有的帽子都降级——那是另一种漏检。
        """
        self.assertEqual(self.role_of("不像话，这就是双标。", "HAT-F7-01"), "used")

    def test_single_quote_mention_is_quoted(self):
        """中文评论区常用单引号标记"提到某个词"。

        只认双引号会把"评论区里有人用'公知'攻击他"这种元讨论判成 42 分的攻击。
        """
        self.assertEqual(self.role_of("评论区里有人用'公知'这个词攻击他。",
                                      "HAT-F1-01"), "quoted")

    def test_passive_accusation_is_quoted(self):
        """"被指 X" 是复述他人的指控，跟"他就是 X"不是一回事。"""
        self.assertEqual(self.role_of("该账号被指收钱发帖，警方还在调查。",
                                      "HAT-F3-02"), "quoted")

    def test_urging_others_not_to_label_is_quoted(self):
        """"别…说别人是 X" 在反对贴标签，不是在使用标签。"""
        self.assertEqual(self.role_of("别动不动就说别人是带节奏，先看事实。",
                                      "HAT-F3-01"), "quoted")

    def test_homophone_alias_is_caught(self):
        """谐音规避：评论区写"公蜘"是为了躲关键词，精确词形匹配会整个漏掉。"""
        self.assertEqual(self.role_of("又是公蜘一套。", "HAT-F1-01"), "used")

    def test_combo_detected(self):
        text = "收钱的吧，一看就是那路人，早晚遭报应。"
        findings, _ = self.scan(text)
        combos = [f for f in findings if f["kind"] == "combo"]
        self.assertEqual(len(combos), 1, findings)
        self.assertEqual(combos[0]["pattern_id"], "CMB-01")
        self.assertEqual(combos[0]["severity"], "Critical")
        self.assertEqual(combos[0]["members"][0], "HAT-F3-02")

    def test_combo_not_triggered_by_single_stage(self):
        findings, _ = self.scan("收钱的吧。")
        self.assertFalse([f for f in findings if f["kind"] == "combo"])

    def test_combo_window_respected(self):
        text = "收钱的吧。" + "填充" * 200 + "。一看就是那路人。早晚遭报应。"
        tight, _ = self.scan(text, strip_code=True)
        loose = hat_scan.scan_text("<t>", text, self.patterns, window=5000)[0]
        self.assertFalse([f for f in tight if f["kind"] == "combo"])
        self.assertTrue([f for f in loose if f["kind"] == "combo"])

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "hat_scan.py"),
             "--text", "典型的带节奏，一条多少钱？", "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertGreater(payload["summary"]["pattern_hits"], 0)


class TestGenerator(unittest.TestCase):
    def generate(self, *extra):
        return hat_generate.main([
            "--target", "某方案", "--count", "6", "--json", *extra])

    def capture(self, argv):
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = hat_generate.main(argv)
        return code, buffer.getvalue()

    def test_no_unfilled_slot(self):
        code, out = self.capture(["--target", "某观点", "--count", "10", "--json", "--seed", "3"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        for item in payload["results"]:
            self.assertNotRegex(item["text"], r"\{[^{}]*\}", f"残留槽位: {item['text']}")

    def test_reproducible_with_seed(self):
        _, a = self.capture(["--target", "某账号", "--count", "5", "--json", "--seed", "42"])
        _, b = self.capture(["--target", "某账号", "--count", "5", "--json", "--seed", "42"])
        self.assertEqual(json.loads(a)["results"], json.loads(b)["results"])

    def test_family_filter_respected(self):
        _, out = self.capture(["--target", "某方案", "--family", "moral-verdict",
                               "--count", "5", "--json", "--seed", "9"])
        for item in json.loads(out)["results"]:
            self.assertEqual(item["hat"]["family"], "moral-verdict")

    def test_intensity_cap(self):
        _, out = self.capture(["--target", "某方案", "--intensity", "1",
                               "--count", "5", "--json", "--seed", "5"])
        for item in json.loads(out)["results"]:
            self.assertLessEqual(item["hat"]["intensity"], 1)

    def test_counter_always_paired(self):
        _, out = self.capture(["--target", "某观点", "--count", "8", "--json", "--seed", "11"])
        for item in json.loads(out)["results"]:
            self.assertGreaterEqual(len(item["counter"]), 2, "产出缺少破解要点")

    def test_unknown_hat_fails(self):
        with self.assertRaises(SystemExit):
            hat_generate.main(["--target", "x", "--hat", "不存在的帽子"])

    def test_every_pattern_can_carry_a_hat(self):
        """每个句式至少有一条模板把 {帽子} 写进正文。

        原来是 24 条句式里 23 条的模板压根没有 {帽子} 槽位，于是 `--hat 巨婴`
        生成出来的句子是「某方案也配谈这事？」——句子里根本没有"巨婴"。
        帽子只出现在元数据和破解要点里，正文跟指定帽子无关。
        """
        missing = [p["id"] for p in common.load_patterns()["patterns"]
                   if not hat_generate.hat_templates(p)]
        self.assertEqual(missing, [], f"这些句式的模板写不进帽子: {missing}")

    def test_generated_text_is_recognized_by_own_scanner(self):
        """生成 → 识别 的闭环：产出必须能被自己的扫描器认出指定帽子。

        这是生成器唯一说得清的自我检验。原状态下 165 条产出里 144 条认不出
        （87%）——生成器声称"生成带某顶帽子的短评"，实际只生成了句式。
        两边对"帽子"的理解一旦分叉，用户拿到的就是一堆没有帽子的句子。

        每顶帽子取 3 条而不是 1 条：count=1 时只看第一次随机结果，模板里只要
        有一条能写进帽子就可能蒙混过关（变异验证时确实没红过），那不叫门禁。
        """
        compiled = hat_scan.compile_patterns()
        bad = []
        for hat in common.flatten_hats():
            _, out = self.capture(["--target", "某方案", "--hat", hat["name"],
                                   "--count", "3", "--json", "--seed", "1"])
            for item in json.loads(out)["results"]:
                findings, _ = hat_scan.scan_text("<gen>", item["text"], compiled)
                used = {f["pattern_id"] for f in findings if f.get("role", "used") == "used"}
                if hat["id"] not in used:
                    bad.append((hat["id"], item["text"]))
        self.assertEqual(bad, [], f"{len(bad)} 条产出认不出自己的帽子: {bad[:5]}")

    def test_default_mode_output_is_recognized(self):
        """不带 --hat、随机挑帽子的默认路径也要闭环。"""
        compiled = hat_scan.compile_patterns()
        bad = []
        for seed in range(1, 4):
            _, out = self.capture(["--target", "某方案", "--count", "8",
                                   "--json", "--seed", str(seed)])
            for item in json.loads(out)["results"]:
                findings, _ = hat_scan.scan_text("<gen>", item["text"], compiled)
                used = {f["pattern_id"] for f in findings if f.get("role", "used") == "used"}
                if item["hat"]["id"] not in used:
                    bad.append((item["hat"]["id"], item["text"]))
        self.assertEqual(bad, [], f"默认模式有 {len(bad)} 条认不出: {bad[:5]}")


class TestComboGenerate(unittest.TestCase):
    def capture(self, argv):
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = hat_generate.main(argv)
        return code, buffer.getvalue()

    def test_all_combos_generate(self):
        for combo in common.load_combos()["combos"]:
            code, out = self.capture(["--target", "某博主", "--combo", combo["id"],
                                      "--json", "--seed", "1"])
            self.assertEqual(code, 0, combo["id"])
            payload = json.loads(out)
            self.assertEqual(payload["mode"], "combo")
            self.assertEqual(len(payload["steps"]), len(combo["sequence"]), combo["id"])
            self.assertNotRegex(payload["text"], r"\{[^{}]*\}", combo["id"])

    def test_combo_break_info_present(self):
        _, out = self.capture(["--target", "某人", "--combo", "CMB-10", "--json", "--seed", "2"])
        payload = json.loads(out)
        self.assertEqual(payload["break_at"], "PAT-17")
        self.assertGreaterEqual(len(payload["break_steps"]), 2)
        self.assertTrue(payload["fail_mode"])

    def test_every_combo_step_is_recognized(self):
        """连招每一环的帽子都要能被扫描器认出来，跟单条生成同一个要求。

        连招是"多顶帽子按顺序打"，如果某一环的句子根本不含那顶帽子，
        拆解示范就变成了拆一个不存在的动作。
        """
        compiled = hat_scan.compile_patterns()
        bad = []
        for combo in common.load_combos()["combos"]:
            _, out = self.capture(["--target", "某博主", "--combo", combo["id"],
                                   "--json", "--seed", "1"])
            for step in json.loads(out)["steps"]:
                findings, _ = hat_scan.scan_text("<combo>", step["text"], compiled)
                used = {f["pattern_id"] for f in findings if f.get("role", "used") == "used"}
                if step["hat"]["id"] not in used:
                    bad.append((combo["id"], step["stage"], step["hat"]["id"], step["text"]))
        self.assertEqual(bad, [], f"连招里有 {len(bad)} 环认不出自己的帽子: {bad[:5]}")

    def test_combo_punctuation(self):
        _, out = self.capture(["--target", "某人", "--combo", "CMB-01", "--json", "--seed", "3"])
        text = json.loads(out)["text"]
        self.assertNotIn("？。", text)
        self.assertTrue(text.endswith(("。", "？", "！")))

    def test_combo_reproducible(self):
        _, a = self.capture(["--target", "某人", "--combo", "CMB-03", "--json", "--seed", "9"])
        _, b = self.capture(["--target", "某人", "--combo", "CMB-03", "--json", "--seed", "9"])
        self.assertEqual(json.loads(a)["text"], json.loads(b)["text"])

    def test_unknown_combo_fails(self):
        with self.assertRaises(SystemExit):
            hat_generate.main(["--target", "x", "--combo", "CMB-99"])


class TestDiff(unittest.TestCase):
    def run_diff(self, before, after, *extra):
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = hat_diff.main(["--before-text", before, "--after-text", after, "--json", *extra])
        return code, json.loads(buffer.getvalue())

    def test_improvement_direction(self):
        code, data = self.run_diff(
            "我没有收钱。我做这个号三年了，所有推荐都是自费买的。",
            "证据呢？没有的话，这句就是从你嘴里出来的。")
        self.assertEqual(code, 0)
        self.assertLessEqual(data["verdict"]["delta"], 0)
        self.assertIn("HAT-F3-02", {item["id"] for item in data["removed"]})

    def test_deterioration_detects_combo(self):
        code, data = self.run_diff("这个方案还行。", "收钱的吧，一看就是那路人，早晚遭报应。")
        self.assertGreater(data["verdict"]["delta"], 0)
        self.assertIn("CMB-01", {item["id"] for item in data["added"]})

    def test_gate_must_drop_fails(self):
        code, data = self.run_diff("这个方案还行。", "收钱的吧。", "--must-drop", "50")
        self.assertEqual(code, 1)
        self.assertFalse(data["passed"])

    def test_gate_max_score_fails(self):
        code, _ = self.run_diff("这个方案还行。",
                                "收钱的吧，一看就是那路人，早晚遭报应。",
                                "--max-score", "20")
        self.assertEqual(code, 1)

    def test_gate_pass(self):
        code, data = self.run_diff(
            "标准公知体，收钱的吧。",
            "你这个结论我不同意，具体是第二段的样本有问题。",
            "--must-drop", "10", "--max-score", "30")
        self.assertEqual(code, 0, data["gates"])


class TestCorpus(unittest.TestCase):
    def test_corpus_all_pass(self):
        rows = corpus_check.run()
        failed = [r for r in rows if not r["passed"]]
        self.assertFalse(failed, failed)

    def test_corpus_composition(self):
        cases = common.load_corpus()["cases"]
        kinds = Counter(case["kind"] for case in cases)
        self.assertGreaterEqual(kinds["neutral"], 8)
        self.assertGreaterEqual(kinds["attack"], 30)
        self.assertGreaterEqual(kinds["context"], 6, "语境样本不足，denied/quoted 降级没有背书")

    def test_every_required_trait_has_a_case(self):
        """语料的价值在于"长得像真实评论区"，不是条数。

        教科书式的完整句子永远测不出漏检和误伤。所以每种野外写法（无标点连写、
        谐音规避、叠字施压、单引号转述……）都必须至少有一条语料在模拟它。
        """
        counts = Counter()
        for case in common.load_corpus()["cases"]:
            counts.update(case.get("traits", []))
        missing = [t for t in common.REQUIRED_TRAITS if not counts[t]]
        self.assertEqual(missing, [], f"没有语料模拟这些野外写法: {missing}")

    def test_trait_names_are_from_the_vocabulary(self):
        """特征名不许自由发挥，否则统计出来是一堆同义词各算一种。"""
        for case in common.load_corpus()["cases"]:
            for trait in case.get("traits", []):
                self.assertIn(trait, common.CORPUS_TRAITS, case["id"])

    def test_unknown_trait_is_rejected(self):
        original = common.REQUIRED_TRAITS
        common.CORPUS_TRAITS["bogus-trait"] = "临时造的特征"
        common.REQUIRED_TRAITS = original + ("bogus-trait",)
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = verify_data.main([])
            self.assertEqual(code, 1, "缺特征时数据一致性门禁必须报错")
            self.assertIn("bogus-trait", buffer.getvalue())
        finally:
            common.REQUIRED_TRAITS = original
            del common.CORPUS_TRAITS["bogus-trait"]

    def test_coverage_complete(self):
        cov = corpus_check.coverage()
        problems = corpus_check.coverage_problems(cov)
        self.assertFalse(problems, problems)

    def test_every_pattern_covered(self):
        cov = corpus_check.coverage()
        missing = [pid for pid, sources in cov["patterns"].items() if not sources]
        self.assertEqual(missing, [], f"没有任何语料或示例覆盖的句式: {missing}")

    def test_every_combo_covered(self):
        cov = corpus_check.coverage()
        missing = [cid for cid, sources in cov["combos"].items() if not sources]
        self.assertEqual(missing, [])

    def test_coverage_gate_can_fail(self):
        cov = corpus_check.coverage()
        problems = corpus_check.coverage_problems(cov, min_family_cases=99)
        self.assertTrue(problems, "门槛提到 99 条时门禁必须报错，否则门禁是假的")

    def test_neutral_scores_zero(self):
        for row in corpus_check.run():
            if row["kind"] == "neutral":
                self.assertEqual(row["label_score"], 0, row)
                self.assertEqual(row["ids"], [], row)


class TestContextDowngrade(unittest.TestCase):
    """语境样本：字面有帽子，但语境是引用或否认。

    这类样本是这套工具最容易被骂"不能用"的地方。干净负样本证明不了它——
    那些文本压根没触发词形，降级代码从头到尾没执行过。
    """

    def test_context_cases_have_raw_but_no_used(self):
        for row in corpus_check.run():
            if row["kind"] != "context":
                continue
            self.assertGreater(row["raw_hits"], 0, f"{row['id']} 没有触发任何词形，退化成负样本了")
            self.assertEqual(row["ids"], [], f"{row['id']} 不该有有效命中: {row['ids']}")
            self.assertEqual(row["label_score"], 0, row)

    def test_both_roles_are_exercised(self):
        cov = corpus_check.coverage()
        for role in ("denied", "quoted"):
            self.assertGreaterEqual(len(cov["roles"].get(role, [])), 2,
                                    f"role={role} 没有足够语料，降级分支只走了一半")

    def test_gate_fails_when_context_cases_disappear(self):
        cov = corpus_check.coverage()
        problems = corpus_check.coverage_problems(cov, min_context_cases=99)
        self.assertTrue(problems, "语境样本门槛提到 99 条时必须报错")

    def test_gate_fails_when_a_role_is_uncovered(self):
        cov = corpus_check.coverage()
        for role in ("denied", "quoted"):
            cov["roles"][role] = []
        problems = corpus_check.coverage_problems(cov)
        self.assertTrue(any("denied" in p for p in problems), problems)
        self.assertTrue(any("quoted" in p for p in problems), problems)

    def test_downgraded_expectation_is_enforced(self):
        """把"必须被降级"指到一个根本没出现的标识上，evaluate 必须报错。

        这条防的是语境样本退化成"反正没命中就算过"。
        """
        case = {
            "id": "FAKE-01",
            "kind": "context",
            "text": "我没有收钱。",
            "expect": {"max_hits": 0, "min_raw": 1, "downgraded": ["PAT-99"],
                       "score_band": [0, 0]},
        }
        findings = [{"pattern_id": "HAT-F3-02", "role": "denied", "severity": "Info",
                     "intensity": 3, "amplifiers": [], "family": "motive-contamination"}]
        row = corpus_check.evaluate(case, findings, 6)
        self.assertFalse(row["passed"])
        self.assertTrue(any("PAT-99" in p for p in row["problems"]), row["problems"])

    def test_denial_of_hat_is_not_an_attack(self):
        """"我没有收钱"是最致命的误报来源，单独立一条，防止以后改正则改坏。"""
        compiled = hat_scan.compile_patterns()
        findings, _ = hat_scan.scan_text("<denial>", "我没有收钱，也没替谁说话。", compiled)
        self.assertTrue(findings, "词形应该命中，否则这条测不到降级")
        self.assertFalse([f for f in findings if f.get("role") == "used"], findings)


class TestPerformance(unittest.TestCase):
    """正则数量和长度都上去了，回溯风险必须有个门禁盯着。

    阈值定得宽（2s），只拦数量级退化——比如某条正则写成嵌套量词导致回溯爆炸，
    真出问题时耗时会从毫秒跳到几十秒，撞线的是那个。
    """

    def setUp(self):
        self.patterns = hat_scan.compile_patterns()

    def timed(self, text):
        import time
        start = time.perf_counter()
        findings, chars = hat_scan.scan_text("<bench>", text, self.patterns)
        return time.perf_counter() - start, findings, chars

    def test_normal_long_text(self):
        text = "他说的这个方案在可维护性和部署成本上都有问题，评审组要求补充压测数据。" * 450
        cost, _, chars = self.timed(text)
        self.assertGreater(chars, 10000)
        self.assertLess(cost, 2.0, f"{chars} 字耗时 {cost:.2f}s")

    def test_single_sentence_without_punctuation(self):
        text = "方案可维护性部署成本回滚速度" * 1750
        cost, _, chars = self.timed(text)
        self.assertGreater(chars, 20000)
        self.assertLess(cost, 3.0, f"单句 {chars} 字耗时 {cost:.2f}s")

    def test_dense_attacks(self):
        text = "收钱的吧，一看就是那路人，早晚遭报应。标准公知体，一条多少钱？" * 150
        cost, findings, chars = self.timed(text)
        self.assertGreater(len(findings), 500, "密集攻击文本应产生大量命中")
        self.assertLess(cost, 3.0, f"{chars} 字 {len(findings)} 命中耗时 {cost:.2f}s")


class TestGates(unittest.TestCase):
    def test_verify_data_passes(self):
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = verify_data.main([])
        self.assertEqual(code, 0, buffer.getvalue())

    def test_wordcount_floor(self):
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = wordcount.main(["--min", "10000"])
        self.assertEqual(code, 0, buffer.getvalue())

    def test_frontmatter_name_matches_dir(self):
        with open(os.path.join(REPO_ROOT, "SKILL.md"), encoding="utf-8") as fh:
            head = fh.read(2000)
        match = verify_data.FRONTMATTER_RE.match(head)
        self.assertIsNotNone(match)
        name = re.search(r"^name:\s*[\"']?([^\"'\n]+)", match.group(1), re.M).group(1).strip()
        self.assertEqual(name, os.path.basename(REPO_ROOT))


class TestEncoding(unittest.TestCase):
    def test_all_text_files_are_utf8(self):
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for name in files:
                if not name.endswith((".md", ".json", ".py", ".yml", ".txt")):
                    continue
                path = os.path.join(root, name)
                with open(path, "rb") as fh:
                    raw = fh.read()
                try:
                    raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    self.fail(f"{path} 不是合法 UTF-8: {exc}")

    def test_no_bom(self):
        for name in ("SKILL.md", "README.md"):
            path = os.path.join(REPO_ROOT, name)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as fh:
                self.assertFalse(fh.read(3) == b"\xef\xbb\xbf", f"{name} 含 BOM")


class TestPackage(unittest.TestCase):
    """产物门禁：验证的是被交付的那一份，不是源目录。

    光验源码是假 CD——少打一个 data 文件照样一路绿，用户装上去当场报错。
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.tmp = tempfile.mkdtemp(prefix="koumaozi-test-pkg-")
        cls.built = package.build(out_dir=cls.tmp)
        cls.zip_path = cls.built["path"]

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_bundle_has_manifest_and_checksum(self):
        import zipfile
        with zipfile.ZipFile(self.zip_path) as zf:
            names = zf.namelist()
        self.assertIn(package.MANIFEST_NAME, names)
        self.assertIn("SKILL.md", names)
        self.assertIn("data/hats.json", names)
        self.assertFalse([n for n in names if "__pycache__" in n], names)
        self.assertTrue(os.path.isfile(self.zip_path + ".sha256"))

    def test_manifest_covers_every_file(self):
        import zipfile
        with zipfile.ZipFile(self.zip_path) as zf:
            manifest = package.parse_manifest(zf.read(package.MANIFEST_NAME).decode("utf-8"))
            names = {n for n in zf.namelist() if n != package.MANIFEST_NAME}
        self.assertEqual(set(manifest), names, "清单与实际打包内容不一致")

    def test_verify_passes_on_fresh_build(self):
        result = package.verify(self.zip_path)
        self.assertTrue(result["passed"], result["problems"])

    def test_verify_catches_missing_file(self):
        """漏打一个文件是发布最常见的翻车方式，必须被抓到。"""
        import zipfile
        broken = os.path.join(self.tmp, "missing.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(broken, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "data/corpus.json":
                    continue
                zout.writestr(item, zin.read(item.filename))
        result = package.verify(broken)
        self.assertFalse(result["passed"])
        self.assertTrue(any("corpus.json" in p for p in result["problems"]), result["problems"])

    def test_verify_catches_tampered_content(self):
        import zipfile
        tampered = os.path.join(self.tmp, "tampered.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "data/hats.json":
                    data = data.replace(b'"hats"', b'"hatz"', 1)
                zout.writestr(item, data)
        result = package.verify(tampered)
        self.assertFalse(result["passed"])
        self.assertTrue(any("hats.json" in p for p in result["problems"]), result["problems"])

    def test_verify_accepts_multiple_packages(self):
        """dist/ 里通常堆着好几个版本，`dist/*.zip` 展开后是多个参数。

        只收一个会直接 unrecognized arguments——文档里那条命令就跑了。
        """
        import shutil
        second = os.path.join(self.tmp, "copy.zip")
        shutil.copy(self.zip_path, second)
        self.assertEqual(package.main(["--verify", self.zip_path, second]), 0)

    def test_verify_fails_if_any_package_is_bad(self):
        import shutil
        import zipfile
        broken = os.path.join(self.tmp, "among-bad.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(broken, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "data/combos.json":
                    continue
                zout.writestr(item, zin.read(item.filename))
        self.assertEqual(package.main(["--verify", self.zip_path, broken]), 1)

    def test_rejects_path_traversal(self):
        """包内路径穿越（../../etc/x）必须拒绝，别等解压出来才发现。"""
        import zipfile
        evil = os.path.join(self.tmp, "evil.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../evil.txt", "x")
            zf.writestr(package.MANIFEST_NAME, "")
        with self.assertRaises(ValueError):
            package.verify(evil)


class TestVersion(unittest.TestCase):
    def test_version_is_semver(self):
        version = package.read_version()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_version_matches_skill_and_changelog(self):
        report = verify_data.Report()
        version = verify_data.check_version(report)
        self.assertIsNotNone(version)
        self.assertTrue(report.ok(), report.errors)

    def test_gate_catches_drift_between_sources(self):
        """把三处版本故意写歪一处，门禁必须红——否则它挡不住发错版本。"""
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="koumaozi-test-ver-")
        original = common.REPO_ROOT
        try:
            with open(os.path.join(tmp, "VERSION"), "w", encoding="utf-8") as fh:
                fh.write("9.9.9\n")
            with open(os.path.join(tmp, "SKILL.md"), "w", encoding="utf-8") as fh:
                fh.write('---\nname: "koumaozi"\nversion: "1.0.0"\n---\n')
            with open(os.path.join(tmp, "CHANGELOG.md"), "w", encoding="utf-8") as fh:
                fh.write("## 1.0.0\n\n旧说明\n")
            common.REPO_ROOT = tmp
            report = verify_data.Report()
            verify_data.check_version(report)
            self.assertFalse(report.ok(), "VERSION 9.9.9 与 SKILL.md 1.0.0 不一致时必须报错")
            messages = " ".join(item["message"] for item in report.errors)
            self.assertIn("SKILL.md", messages)
            self.assertIn("CHANGELOG", messages)
        finally:
            common.REPO_ROOT = original
            shutil.rmtree(tmp, ignore_errors=True)


class TestReleaseNotes(unittest.TestCase):
    def test_notes_include_install_block(self):
        version = package.read_version()
        text, ok = release_notes.notes(version)
        self.assertTrue(ok, f"CHANGELOG 里没有 {version} 的段落")
        self.assertIn(f"v{version}", text)
        self.assertIn("koumaozi-{}.zip".format(version), text)
        self.assertIn("sha256sum -c", text)
        self.assertIn("skills/koumaozi", text)

    def test_unknown_version_yields_nothing(self):
        text, ok = release_notes.notes("0.0.1")
        self.assertFalse(ok)
        self.assertEqual(text, "")

    def test_section_stops_at_next_heading(self):
        sample = "# C\n\n## 2.0.0\n\n新东西\n\n### 细节\n\n- x\n\n## 1.0.0\n\n旧东西\n"
        body = release_notes.section(sample, "2.0.0")
        self.assertIn("新东西", body)
        self.assertIn("### 细节", body)
        self.assertNotIn("旧东西", body)


class TestDocSmoke(unittest.TestCase):
    """文档即测试：读者会逐字复制文档里的命令。

    脚本改名、参数改了、样例文件挪了位置，源码门禁一条都不会红，
    但读者照抄第一行就报 No such file or directory。文档腐烂是静默的。
    """

    def test_extracts_commands_from_docs(self):
        cases = doc_smoke.collect()
        self.assertGreaterEqual(len(cases), 20, "抽到的命令太少，抽取逻辑大概断了")
        for case in cases:
            self.assertTrue(case["command"].startswith(("python3 scripts/", "python scripts/")))

    def test_strip_comment_keeps_hash_inside_quotes(self):
        self.assertEqual(doc_smoke.strip_comment('python3 scripts/x.py --text "a # b"  # 注释'),
                         'python3 scripts/x.py --text "a # b"')
        self.assertEqual(doc_smoke.strip_comment("python3 scripts/x.py --count 3"),
                         "python3 scripts/x.py --count 3")

    def test_handles_line_continuation(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="koumaozi-test-doc-")
        try:
            path = os.path.join(tmp, "doc.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("```bash\npython3 scripts/hat_scan.py \\\n  --text \"一句话\"\n```\n")
            original = common.REPO_ROOT
            common.REPO_ROOT = tmp
            try:
                cases = doc_smoke.extract(path)
            finally:
                common.REPO_ROOT = original
            self.assertEqual(len(cases), 1)
            self.assertIn("--text", cases[0]["command"])
            self.assertNotIn("\\", cases[0]["command"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_every_referenced_file_exists(self):
        """文档里点名的样例文件必须真的在——这条最便宜也最有用。"""
        import shlex
        missing = []
        for case in doc_smoke.collect():
            for token in shlex.split(case["command"]):
                if token.startswith("-") or "*" in token or "/" not in token:
                    continue
                if not os.path.exists(os.path.join(REPO_ROOT, token)):
                    missing.append(f"{case['source']}: {token}")
        self.assertEqual(missing, [], f"文档引用了不存在的路径: {missing}")

    def test_missing_script_is_reported_clearly(self):
        case = {"source": "fake:1", "command": "python3 scripts/no_such_tool.py --x"}
        row = doc_smoke.run_case(case)
        self.assertFalse(row["passed"])
        self.assertIn("脚本不存在", row["problems"][0])

    def test_bad_flag_fails(self):
        case = {"source": "fake:2",
                "command": "python3 scripts/hat_scan.py --min-severity Nope --text x"}
        row = doc_smoke.run_case(case)
        self.assertFalse(row["passed"])

    def test_recursive_gate_commands_are_skipped(self):
        """文档里写 `python3 scripts/gate.py` 会 gate → docs → doc_smoke → gate。"""
        self.assertIsNotNone(doc_smoke.skip_reason("python3 scripts/gate.py"))
        self.assertIsNotNone(doc_smoke.skip_reason("python3 scripts/gate.py --tier core"))
        # 只打印元信息的子命令不跑门禁，没有递归风险，必须照跑
        self.assertIsNone(doc_smoke.skip_reason("python3 scripts/gate.py --list"))
        self.assertIsNone(doc_smoke.skip_reason("python3 scripts/gate.py --explain"))
        self.assertIsNone(doc_smoke.skip_reason("python3 scripts/hat_scan.py --text x"))

    def test_no_command_really_recurses(self):
        """跳过的一定都是 gate.py；没跳过而调 gate.py 的，只能是 --list / --explain。"""
        for case in doc_smoke.collect():
            if case.get("skip"):
                self.assertIn("scripts/gate.py", case["command"])
            elif "scripts/gate.py" in case["command"]:
                self.assertTrue("--list" in case["command"] or "--explain" in case["command"],
                                f"这条会递归却要真跑: {case['command']}")

    def test_skip_switch_targets_the_heavy_test(self):
        """跳过开关必须挂在"真跑 33 条文档命令"那条上。

        这条测试是被一次真实的错位逼出来的：加新测试时 skipIf 被挤到了
        隔壁函数上，于是 11 秒照跑、还显示 skipped=1，看起来一切正常。

        只点名那一条测试方法，不能点名整个类——这个类里有本条测试自己，
        整类跑会无限级联出子进程。
        """
        env = dict(os.environ, KOUMAOZI_SKIP_DOC_SMOKE="1")
        target = "tests.test_koumaozi.TestDocSmoke.test_every_doc_command_runs"
        proc = subprocess.run([sys.executable, "-m", "unittest", target],
                              cwd=REPO_ROOT, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertIn("skipped=1", proc.stderr,
                      f"KOUMAOZI_SKIP_DOC_SMOKE=1 时这条应当被跳过: {proc.stderr[-300:]}")

    @unittest.skipIf(os.environ.get("KOUMAOZI_SKIP_DOC_SMOKE"),
                     "由 gate.py 的 docs 门禁单独覆盖，这里跳过省 11s")
    def test_every_doc_command_runs(self):
        """真跑一遍。慢一点（几条子进程），但这是这道门禁的全部意义。"""
        rows = doc_smoke.run()
        failed = [r for r in rows if not r["passed"]]
        self.assertEqual(failed, [], failed)


class TestDiffInput(unittest.TestCase):
    """--before 收到一个不存在的文件名时，绝不能当成正文分析。

    静默把 "draft-v2.md" 当正文，用户会以为对比了两个文件，拿到一个
    看着正常的错误结果——比直接报错危险得多。
    """

    def test_path_like_detection(self):
        self.assertTrue(hat_diff.looks_like_path("draft-v2.md"))
        self.assertTrue(hat_diff.looks_like_path("docs/a.txt"))
        self.assertTrue(hat_diff.looks_like_path(r"notes\draft.md"))
        self.assertFalse(hat_diff.looks_like_path("收钱的吧，一看就是那路人。"))
        self.assertFalse(hat_diff.looks_like_path("样本只覆盖两个城市"))

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            hat_diff.load_source("definitely-missing.md", "<before>")

    def test_plain_text_still_passes_through(self):
        text = "收钱的吧，一看就是那路人。"
        raw, name = hat_diff.load_source(text, "<before>")
        self.assertEqual(raw, text)
        self.assertEqual(name, "<before>")

    def test_cli_reports_missing_file_without_traceback(self):
        result = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "hat_diff.py"),
             "--before", "examples/draft-v1.md", "--after", "nope.md"],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("文件不存在", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class TestGate(unittest.TestCase):
    """统一门禁入口：本地和 CI 必须跑同一套。

    门禁散在 workflow 里最容易出现"本地绿、CI 红"——两边顺序和集合各写一份，
    改了一边忘另一边。所以这里连"CI 是否走 gate.py"都要断言。
    """

    def test_core_is_subset_of_all(self):
        core = {gate["key"] for gate in gate.select("core")}
        everything = {gate["key"] for gate in gate.select("all")}
        self.assertTrue(core <= everything)
        # 全量 = 核心 + 这几个慢的。写死是有意的：新增或删掉一道门禁，
        # 这里必须跟着改一次，避免"顺手删了一道"没人发现。
        self.assertEqual(core | {"docs", "cli", "web", "package"}, everything)

    def test_select_only(self):
        picked = gate.select(only="data,corpus")
        self.assertEqual([item["key"] for item in picked], ["data", "corpus"])

    def test_unknown_key_raises(self):
        with self.assertRaises(SystemExit):
            gate.select(only="data,nope")

    def test_every_gate_script_exists(self):
        for item in gate.GATES:
            argv = item["argv"]
            if "-m" in argv[:3]:
                continue
            script = argv[1] if argv[0] == sys.executable else argv[0]
            if script.endswith(".py"):
                self.assertTrue(os.path.isfile(script), f"{item['key']} 指向不存在的脚本: {script}")

    def test_failure_is_reported(self):
        fake = {"key": "fake", "name": "假门禁", "tier": "core",
                "argv": [sys.executable, "-c",
                         "import sys; sys.stderr.write('boom 出错原因'); sys.exit(3)"],
                "protects": "", "hint": ""}
        row = gate.run_gate(fake)
        self.assertFalse(row["passed"])
        self.assertEqual(row["returns"], 3)
        self.assertTrue(any("boom" in line for line in row["problems"]), row["problems"])

    def test_summarize_prefers_test_count(self):
        text = "自检 koumaozi-1.0.0.zip  10 个文件\nRan 81 tests in 5.2s\nOK"
        self.assertEqual(gate.summarize(text), "Ran 81 tests")

    def test_skip_count_is_surfaced(self):
        """跳过数必须进到门禁那一行。

        "Ran 126 tests" 看不出有几条根本没跑。跨平台矩阵上这是致命的：
        Windows 那条要是因为缺 pwsh 全跳过，日志照样一片绿，而矩阵的全部
        意义就是验 Windows 独有的东西。
        """
        self.assertEqual(gate.skip_note("Ran 126 tests in 8.5s\n\nOK (skipped=4)"), 4)
        self.assertEqual(gate.skip_note("Ran 126 tests in 8.5s\n\nOK"), 0)
        self.assertEqual(gate.skip_note(""), 0)

    def test_skips_appear_in_the_gate_detail(self):
        """端到端：真的走一遍 run_gate，确认那一行写出来了，而不只是算得对。"""
        fake = {"key": "fake", "name": "假单测", "tier": "core",
                "argv": [sys.executable, "-c",
                         "import sys; sys.stderr.write('Ran 3 tests in 0.1s\\n\\n"
                         "OK (skipped=2)\\n')"],
                "protects": "", "hint": ""}
        row = gate.run_gate(fake)
        self.assertIn("Ran 3 tests", row["detail"])
        self.assertIn("跳过 2", row["detail"])

    def test_no_skip_suffix_when_nothing_skipped(self):
        fake = {"key": "fake", "name": "假单测", "tier": "core",
                "argv": [sys.executable, "-c",
                         "import sys; sys.stderr.write('Ran 3 tests in 0.1s\\n\\nOK\\n')"],
                "protects": "", "hint": ""}
        row = gate.run_gate(fake)
        self.assertNotIn("跳过", row["detail"])

    def test_workflows_go_through_single_entry(self):
        """ci.yml 和 release.yml 都必须走 gate.py。

        门禁集合一旦在 yml 里再写一遍，改 gate.py 时就会漏掉某一边，
        然后出现"本地绿、CI 绿、发版红"这种最难查的组合。
        """
        for name in ("ci.yml", "release.yml"):
            path = os.path.join(REPO_ROOT, ".github", "workflows", name)
            self.assertTrue(os.path.isfile(path), f"缺 workflow: {name}")
            with open(path, "r", encoding="utf-8") as fh:
                workflow = fh.read()
            self.assertIn("scripts/gate.py", workflow,
                          f"{name} 没走 gate.py，门禁集合会从两处漂开")
            for script in ("verify_data.py", "corpus_check.py", "doc_smoke.py",
                           "cli_smoke.py", "package.py", "wordcount.py"):
                self.assertNotIn(f"python scripts/{script}", workflow,
                                 f"{name} 里还在直接调 {script}，应当统一走 gate.py")

    def test_web_gate_skips_without_docs(self):
        """安装包不带 docs/，网页端对拍必须标 SKIP 而不是红。

        这是 1.6.0 那个坑的翻版：新加一道门禁，忘了声明"不适用"的条件，
        用户装完一跑 gate 就以为代码坏了。
        """
        gate_def = gate.gate_by_key("web")
        self.assertIsNotNone(gate_def)
        needs = gate_def.get("needs") or []
        self.assertTrue([path for path in needs if path.endswith("docs")],
                        "web 门禁要声明 needs=docs/，否则安装包里会红")

    def test_gate_skips_when_needed_path_missing(self):
        """安装包里没有 tests/，单测门禁要跳过而不是变红。

        1.6.0 就是红在这——"目录不存在"被当成了"测试失败"，
        用户装完一跑 gate 就以为代码坏了。
        """
        import io
        from contextlib import redirect_stdout
        original = gate.GATES
        gate.GATES = [{"key": "fake", "name": "假门禁", "tier": "core",
                       "argv": [sys.executable, "-c", "print('不该执行')"],
                       "needs": [os.path.join(REPO_ROOT, "no-such-dir")],
                       "protects": "", "hint": ""}]
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = gate.main(["--json"])
        finally:
            gate.GATES = original
        payload = json.loads(buffer.getvalue())
        self.assertEqual(code, 0, "缺依赖目录不该算失败")
        self.assertIn("缺 ", payload["gates"][0]["skipped"])

    def test_markdown_table_is_written(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="koumaozi-test-md-")
        try:
            path = os.path.join(tmp, "gate.md")
            rows = [
                {"key": "data", "name": "数据一致性", "passed": True,
                 "seconds": 0.2, "detail": "检查项 314"},
                {"key": "corpus", "name": "回归语料", "passed": False,
                 "seconds": 0.3, "detail": "有 1 条不符"},
            ]
            gate.write_markdown(path, "9.9.9", rows, 0.5)
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("v9.9.9", text)
            self.assertIn("| `data` 数据一致性 | ✅ |", text)
            self.assertIn("| `corpus` 回归语料 | ❌ |", text)
            self.assertIn("失败 1 道", text)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestWeb(unittest.TestCase):
    """网页端：规则是派生物，判定是第二份实现。

    两件事都会静默出错——网页照样打开、照样出结果，只是判得不对。
    所以这里既盯"派生物与真源同步"，也盯"两份实现判得一样"。
    """

    @classmethod
    def setUpClass(cls):
        cls.rules_path = os.path.join(REPO_ROOT, "docs", "rules.js")
        cls.index_path = os.path.join(REPO_ROOT, "docs", "index.html")
        cls.app_path = os.path.join(REPO_ROOT, "docs", "app.js")
        cls.scan_path = os.path.join(REPO_ROOT, "docs", "scan.js")

    def read(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()

    def test_rules_file_is_in_sync_with_data(self):
        import build_web
        result = build_web.check(self.rules_path)
        self.assertEqual(result["problems"], [], "改了 data/ 忘了生成 docs/rules.js")

    def test_rules_version_matches_version_file(self):
        match = re.search(r'"version":\s*"([^"]+)"', self.read(self.rules_path))
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), common.read_version())

    def test_parity_with_python_scanner(self):
        """70+ 条真实语料逐条对拍。缺 node 就跳过——不是失败，是这台机器验不了。"""
        import web_parity
        report = web_parity.run()
        if report["skipped"]:
            self.skipTest(report["skipped"])
        self.assertEqual(report["problems"], [],
                         "网页端与 Python 端判得不一样，网页的结论不可信")
        self.assertGreaterEqual(report["cases"], 60, "对拍用例太少，拦不住分叉")

    def test_compare_would_catch_a_difference(self):
        """对拍本身也要证明不是空转：分数差一分、命中少一条，都必须报出来。"""
        import web_parity
        py_rows = [{"id": "X", "chars": 10,
                    "stats": {"label_score": 51, "hat_hits": 1, "pattern_hits": 1,
                              "combo_hits": 0, "critical_hits": 0},
                    "findings": [{"kind": "hat", "pattern_id": "HAT-F1-01", "matched": "公知",
                                  "severity": "Warning", "role": "used"}]}]
        js_same = [{"id": "X", "chars": 10, "stats": dict(py_rows[0]["stats"]),
                    "findings": [dict(py_rows[0]["findings"][0])]}]
        self.assertEqual(web_parity.compare(py_rows, js_same), [])

        js_score = [{"id": "X", "chars": 10,
                     "stats": dict(py_rows[0]["stats"], label_score=50),
                     "findings": [dict(py_rows[0]["findings"][0])]}]
        self.assertTrue(web_parity.compare(py_rows, js_score))

        js_miss = [{"id": "X", "chars": 10, "stats": dict(py_rows[0]["stats"]),
                    "findings": []}]
        self.assertTrue(web_parity.compare(py_rows, js_miss))

        js_role = [{"id": "X", "chars": 10, "stats": dict(py_rows[0]["stats"]),
                    "findings": [dict(py_rows[0]["findings"][0], role="quoted")]}]
        self.assertTrue(web_parity.compare(py_rows, js_role), "降级判错也算分叉")

    def test_page_loads_only_local_assets(self):
        """静态页不能有外链依赖：断网、内网、离线包里都得能打开。"""
        html = self.read(self.index_path)
        sources = re.findall(r'<script[^>]+src="([^"]+)"', html)
        styles = re.findall(r'<link[^>]+href="([^"]+)"', html)
        css_urls = re.findall(r"url\((['\"]?)(https?://[^)]+)\)", html)
        for asset in sources + styles:
            self.assertFalse(asset.startswith(("http://", "https://")),
                             f"页面依赖了外部资源: {asset}")
        self.assertEqual(css_urls, [], "样式里引了外链（字体/图标），断网就变样")
        self.assertIn("rules.js", sources)
        self.assertIn("scan.js", sources)
        self.assertIn("app.js", sources)

    def test_referenced_files_exist(self):
        html = self.read(self.index_path)
        for name in re.findall(r'<script[^>]+src="([^"]+)"', html):
            path = os.path.join(os.path.dirname(self.index_path), name)
            self.assertTrue(os.path.isfile(path), f"{name} 被引用但不存在")

    def test_every_element_app_js_looks_up_exists(self):
        """app.js 里的 getElementById 拼错一个字母，页面就整块不渲染。"""
        html = self.read(self.index_path)
        ids = set(re.findall(r'\bid="([^"]+)"', html))
        wanted = set(re.findall(r'getElementById\("([^"]+)"\)', self.read(self.app_path)))
        self.assertTrue(wanted)
        missing = sorted(wanted - ids)
        self.assertEqual(missing, [], f"app.js 要找的元素在 index.html 里没有: {missing}")

    def test_js_files_have_no_syntax_error(self):
        node = shutil.which("node") or shutil.which("nodejs")
        if not node:
            self.skipTest("没有 node")
        for name in ("rules.js", "scan.js", "app.js"):
            proc = subprocess.run([node, "--check", os.path.join(REPO_ROOT, "docs", name)],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=120)
            self.assertEqual(proc.returncode, 0, f"{name}: {proc.stderr}")

    def test_scan_js_reads_constants_from_rules(self):
        """降级词表不能抄进 JS：抄一份就等着两边分叉。"""
        source = self.read(self.scan_path)
        self.assertIn("RULES.amplifiers", source)
        self.assertIn("RULES.negationPrefixes", source)
        self.assertIn("RULES.metaPrefixes", source)
        self.assertNotIn("说我", source, "元讨论前缀被抄进了逻辑文件")


class TestCheckDir(unittest.TestCase):
    """--check-dir 核对的是"装完之后那份还在不在"，不是源码目录。

    装好之后被改一行、被半路中断的拷贝覆盖过，都不会有任何报错，
    只会在某天扫不出东西时才暴露——那时代价已经付出了。
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="koumaozi-test-checkdir-")
        cls.built = package.build(out_dir=cls.tmp)
        cls.installed = os.path.join(cls.tmp, "installed")
        with zipfile.ZipFile(cls.built["path"]) as zf:
            zf.extractall(cls.installed)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_fresh_install_passes(self):
        result = package.check_dir(self.installed)
        self.assertTrue(result["passed"], result["problems"])
        self.assertGreater(result["files"], 30)

    def test_detects_tampered_file(self):
        dest = tempfile.mkdtemp(dir=self.tmp)
        with zipfile.ZipFile(self.built["path"]) as zf:
            zf.extractall(dest)
        with open(os.path.join(dest, "data", "hats.json"), "a", encoding="utf-8") as fh:
            fh.write("\n")
        result = package.check_dir(dest)
        self.assertFalse(result["passed"])
        self.assertTrue([p for p in result["problems"] if "hats.json" in p], result["problems"])

    def test_detects_missing_file(self):
        dest = tempfile.mkdtemp(dir=self.tmp)
        with zipfile.ZipFile(self.built["path"]) as zf:
            zf.extractall(dest)
        os.remove(os.path.join(dest, "references", "glossary.md")) \
            if os.path.isfile(os.path.join(dest, "references", "glossary.md")) \
            else os.remove(os.path.join(dest, "SKILL.md"))
        self.assertFalse(package.check_dir(dest)["passed"])

    def test_source_tree_is_skipped_not_failed(self):
        """源码态没有 MANIFEST，那是"没什么可核对"，不是"核对不通过"。"""
        result = package.check_dir(REPO_ROOT)
        self.assertTrue(result["passed"])
        self.assertIsNotNone(result.get("skipped"))

    def test_build_artifacts_are_not_treated_as_tampering(self):
        """装好之后有人在那个目录里跑一次 package.py，会多出 dist/。

        那不是"安装被人动过"。第一次在真装好的包里跑门禁就踩到了这个——
        doc_smoke 会先打包，于是 --check-dir 当场把 dist/ 当成多出来的文件。
        """
        dest = tempfile.mkdtemp(dir=self.tmp)
        with zipfile.ZipFile(self.built["path"]) as zf:
            zf.extractall(dest)
        os.makedirs(os.path.join(dest, "dist"), exist_ok=True)
        with open(os.path.join(dest, "dist", "koumaozi-x.zip"), "wb") as fh:
            fh.write(b"PK\x03\x04")
        result = package.check_dir(dest)
        self.assertTrue(result["passed"], result["problems"])

    def test_cli_exit_code(self):
        proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, "package.py"),
                               "--check-dir", self.installed],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("通过", proc.stdout)


class InstallCheckMixin:
    """--check 的两个平台实现共用同一套断言。

    退出码是这套接口的全部意义：0 不用动 / 1 该动手 / 2 查不到。
    判错的两个方向后果都不小——把"有更新"判成"已是最新"，用户就一直
    停在旧版上；反过来把"已是最新"判成"有更新"，`--check || install`
    会每次都重装一遍。
    """

    shell = None          # 由子类填
    script_name = None
    hint_flag = "-y"      # 结论里给出的"直接可执行"那个开关
    # 指定版本号那个开关的拼写。这条跟"行为"无关，是纯粹的平台差异：
    # PowerShell 用 -Version，bash 用 --version。断言里写死拼写，等于让
    # 共用的用例偷偷依赖 bash。更难的是 `--version` 在 pwsh -Command 模式下
    # 根本不是参数，是 `--` 递减运算符，会直接 ParserError。
    version_flag = "--version"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="koumaozi-test-install-")
        cls.built = package.build(out_dir=cls.tmp)
        cls.version = cls.built["version"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def posix(self, path):
        return path.replace("\\", "/")

    def stub_install(self, version):
        """只写一个 VERSION 的假安装目录：够跑版本比较，又不用每次解压整个包。"""
        dest = tempfile.mkdtemp(dir=self.tmp, prefix="stub-")
        with open(os.path.join(dest, "VERSION"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(version + "\n")
        return dest

    def real_install(self):
        dest = tempfile.mkdtemp(dir=self.tmp, prefix="real-")
        with zipfile.ZipFile(self.built["path"]) as zf:
            zf.extractall(dest)
        return dest

    def run_check(self, target, *extra, **kwargs):
        argv = self.build_argv(target, *extra)
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=180, cwd=REPO_ROOT,
                              env=kwargs.get("env"))

    def skipped(self, reason):
        self.skipTest(reason)

    def test_up_to_date_exits_zero(self):
        proc = self.run_check(self.stub_install(self.version), self.version_flag, self.version)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("已是最新", proc.stdout)

    def test_update_exits_one_with_hint(self):
        proc = self.run_check(self.stub_install(self.version), self.version_flag, "99.0.0")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("有更新", proc.stdout)
        self.assertIn(self.hint_flag, proc.stdout, "报了有更新就得给出能直接执行的命令")

    def test_version_compare_is_numeric_not_lexical(self):
        """1.10.0 比 1.9.0 新，但按字符串比 1.10.0 < 1.9.0。

        这是这类脚本最经典的真 bug，而且不报错——只是永远"已是最新"。
        """
        proc = self.run_check(self.stub_install("1.9.0"), self.version_flag, "1.10.0")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("有更新", proc.stdout)

    def test_local_ahead_is_not_an_error(self):
        proc = self.run_check(self.stub_install("9.9.9"), self.version_flag, "1.0.0")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("本地比线上新", proc.stdout)

    def test_not_installed(self):
        proc = self.run_check(os.path.join(self.tmp, "definitely-not-there"),
                              self.version_flag, "1.0.0")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("未安装", proc.stdout)

    def test_version_with_v_prefix_is_accepted(self):
        proc = self.run_check(self.stub_install(self.version), self.version_flag,
                              "v" + self.version)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class TestInstallCheckBash(InstallCheckMixin, unittest.TestCase):
    """bash 版（Linux / macOS / WSL）。"""

    script_name = "install.sh"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bash = shutil.which("bash")

    def build_argv(self, target, *extra):
        if not self.bash:
            self.skipped("没有 bash（Windows 原生环境），这半边交给 CI 的 ubuntu 矩阵")
        return ([self.bash, self.posix(os.path.join(SCRIPTS, self.script_name)),
                 "--check", "--target", self.posix(target)] + list(extra))

    def test_tampered_install_is_reported(self):
        dest = self.real_install()
        with open(os.path.join(dest, "data", "hats.json"), "a", encoding="utf-8") as fh:
            fh.write("\n")
        proc = self.run_check(dest, self.version_flag, self.version)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("清单不符", proc.stdout)

    def test_check_never_writes_to_the_install(self):
        dest = self.real_install()

        def snapshot():
            table = {}
            for current, dirs, files in os.walk(dest):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for name in files:
                    path = os.path.join(current, name)
                    table[path] = (os.path.getsize(path), os.path.getmtime(path))
            return table

        before = snapshot()
        self.run_check(dest, self.version_flag, "99.0.0")
        self.assertEqual(before, snapshot(), "--check 说好了不动磁盘")

    def test_pinned_version_does_not_call_the_network(self):
        """给了 --version 就不该再去问 API——离线环境、CI 限流都要能跑。"""
        if os.name == "nt":
            self.skipped("Windows 下 PATH 分隔符与 Git Bash 不一致，交给 CI 验")
        stub = tempfile.mkdtemp(dir=self.tmp, prefix="curl-stub-")
        marker = os.path.join(stub, "called")
        script = os.path.join(stub, "curl")
        with open(script, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
        os.chmod(script, 0o755)
        env = dict(os.environ)
        env["PATH"] = stub + os.pathsep + env.get("PATH", "")
        proc = self.run_check(self.stub_install(self.version), self.version_flag,
                              self.version, env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(os.path.exists(marker), "--version 已经给了还要去问 API")


class TestInstallCheckPowerShell(InstallCheckMixin, unittest.TestCase):
    """PowerShell 版（Windows）。

    这里踩过真坑：PowerShell 变量名大小写不敏感，函数里写 `$a = ...` 赋值给的
    是 `[string]$A` 参数，数组被强转成 "1 10 0" 一串，Count 恒为 1，比较结果
    永远"相等"。表现是 --check 一路报"已是最新"，用户永远装不上新版，而且
    不报任何错。所以 Windows 这半边不能只靠人肉 eyeball。
    """

    script_name = "install.ps1"
    hint_flag = "-Yes"
    version_flag = "-Version"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pwsh = shutil.which("pwsh")

    def build_argv(self, target, *extra):
        raise AssertionError("PowerShell 侧不走通用 argv，见 run_check")

    @staticmethod
    def ps_quote(text):
        return "'" + text.replace("'", "''") + "'"

    def run_check(self, target, *extra, **kwargs):
        """用 -Command 而不是 -File：先把控制台编码对齐到 UTF-8 再调用。

        断言的是**逻辑与退出码**，控制台编码是环境属性：英文 Windows 的 OEM 码页
        装不下中文，硬用 -File 会把"有更新"变成一串问号，测试就会为了跟环境较劲
        而红。真正跑 -File 的那条路另有 test_file_form_also_works 盯着。

        注意调用串必须**拼成一条语句**再交给 pwsh。曾经把 "& 'script'"、"-Check"、
        "-Target"、"'...'" 当成四个元素用 "; " 连起来，结果变成 `& 'script'; -Check;
        -Target; '...'`——脚本被裸调（直接开始装），后面三条各成一句全报错。表现是
        "测试说 -Check 没生效"，其实是根本没把参数交给脚本。
        """
        if not self.pwsh:
            self.skipped("没有 pwsh（PowerShell 7）")
        script = os.path.join(SCRIPTS, self.script_name)
        call = ["& " + self.ps_quote(script), "-Check", "-Target", self.ps_quote(target)]
        for item in extra:
            call.append(item if item.startswith("-") else self.ps_quote(item))
        command = "; ".join(["[Console]::OutputEncoding = [Text.Encoding]::UTF8",
                             " ".join(call),
                             "exit $LASTEXITCODE"])
        argv = [self.pwsh, "-NoProfile", "-NonInteractive", "-Command", command]
        proc = subprocess.run(argv, capture_output=True, timeout=180, cwd=REPO_ROOT,
                              env=kwargs.get("env"))
        return ShellResult(proc.returncode, decode_console(proc.stdout),
                           decode_console(proc.stderr))

    def test_file_form_also_works(self):
        """文档里写的是 `install.ps1 -Check`，-File 这条路必须通。

        只断言退出码：输出里有没有中文取决于运行环境的码页，那是环境的事。
        """
        if not self.pwsh:
            self.skipped("没有 pwsh（PowerShell 7）")
        target = self.stub_install(self.version)
        proc = subprocess.run([self.pwsh, "-NoProfile", "-File",
                               os.path.join(SCRIPTS, self.script_name), "-Check",
                               "-Target", target, "-Version", self.version],
                              capture_output=True, timeout=180, cwd=REPO_ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr[:400])

    def test_unknown_flag_does_not_silently_succeed(self):
        """参数打错时 PowerShell 默认会当没事发生，安装脚本不能这样。"""
        if not self.pwsh:
            self.skipped("没有 pwsh（PowerShell 7）")
        proc = subprocess.run([self.pwsh, "-NoProfile", "-Command",
                               "& { $ErrorActionPreference='Stop'; "
                               f"& '{self.posix(os.path.join(SCRIPTS, self.script_name))}' "
                               "-TotallyUnknownFlag }"],
                              capture_output=True, timeout=180)
        self.assertNotEqual(proc.returncode, 0, "未知参数应当报错退出")


class TestMatrixIsNotVacuous(unittest.TestCase):
    """CI 上跑的那条矩阵，必须真的验到了本平台独有的东西。

    这套测试大量按平台分叉：Windows 走 PowerShell，别处走 bash。验不了就
    skip 是对的——本地没装 pwsh 不该红，"不适用"不等于"失败"。但"因为缺工具
    而 skip"和"验过了"在日志里长得一模一样（都是 OK），矩阵就可能悄悄退化成
    一条什么都不验的绿灯。所以反过来在 CI 上要求：本平台的工具必须在位。

    这条守卫本身只在 CI 生效，本地永远 skip。
    """

    def test_platform_shell_is_available_on_ci(self):
        if not os.environ.get("CI"):
            self.skipTest("只在 CI 上要求；本地缺 pwsh 是正常的")
        if os.name == "nt":
            self.assertIsNotNone(
                shutil.which("pwsh"),
                "Windows 矩阵没有 pwsh，install.ps1 这半边等于没验")
        else:
            self.assertIsNotNone(
                shutil.which("bash"),
                "Linux/macOS 矩阵没有 bash，install.sh 这半边等于没验")


if __name__ == "__main__":
    unittest.main(verbosity=2)
