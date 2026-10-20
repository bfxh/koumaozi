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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

import common  # noqa: E402
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
