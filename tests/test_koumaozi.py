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
import doc_smoke  # noqa: E402
import gate  # noqa: E402
import hat_diff  # noqa: E402
import hat_generate  # noqa: E402
import hat_scan  # noqa: E402
import package  # noqa: E402
import release_notes  # noqa: E402
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
        self.assertGreaterEqual(kinds["attack"], 30)
        self.assertGreaterEqual(kinds["context"], 6, "语境样本不足，denied/quoted 降级没有背书")

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
        self.assertEqual(core | {"docs", "cli", "package"}, everything)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
