"""扣帽子工程的门禁测试。

跑法:
    python -m unittest discover -s tests -v
"""
import json
import os
import re
import subprocess
import sys
import unittest
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

import common  # noqa: E402
import corpus_check  # noqa: E402
import hat_diff  # noqa: E402
import hat_generate  # noqa: E402
import hat_scan  # noqa: E402
import verify_data  # noqa: E402
import wordcount  # noqa: E402


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
        self.assertGreaterEqual(kinds["attack"], 20)

    def test_neutral_scores_zero(self):
        for row in corpus_check.run():
            if row["kind"] == "neutral":
                self.assertEqual(row["label_score"], 0, row)
                self.assertEqual(row["ids"], [], row)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
