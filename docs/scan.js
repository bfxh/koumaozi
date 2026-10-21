/* 浏览器端扫描器：判定逻辑与 scripts/hat_scan.py 同一套。
 *
 * 为什么要在 JS 里重写一遍：静态页没有后端，规则必须在浏览器里跑。
 * 重写就有分叉风险，所以——
 *   1) 规则数据全部来自生成的 rules.js（真源是 data/*.json 与 common.py 的常量）
 *   2) 判定逻辑的等价性由 scripts/web_parity.py 拿 55 条回归语料逐条对拍，
 *      分数、命中集合、严重度、角色四项必须与 Python 侧一致，不一致门禁就红
 *
 * 用法：
 *   浏览器：先引 rules.js，再引本文件 → KOUMAOZI_SCAN.scan(text)
 *   node  ：const scan = require("./scan.js"); scan.scan(text)
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./rules.js"));
  } else {
    root.KOUMAOZI_SCAN = factory(root.KOUMAOZI_RULES);
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function (RULES) {
  "use strict";

  if (!RULES) {
    throw new Error("缺少规则：先引入 rules.js（KOUMAOZI_RULES）");
  }

  var AMPLIFIERS = RULES.amplifiers;
  var NEGATION_PREFIXES = RULES.negationPrefixes;
  var META_PREFIXES = RULES.metaPrefixes;
  var QUOTE_PAIRS = RULES.quotePairs;
  var STRAIGHT_QUOTES = RULES.straightQuotes;
  var RHETORICAL_SUBJECTS = RULES.rhetoricalSubjects;
  var CLAUSE_BREAKS = RULES.clauseBreaks;
  var W = RULES.windows;
  var REVERSAL_RE = /(?:是什么|是啥|是哪种|吗|嘛|呢|[?？])/;
  var SENTENCE_CHARS = "。！？；!?;";
  var REGEX_CACHE = {};

  function spaces(count) {
    return new Array(count + 1).join(" ");
  }

  function regexFor(expr) {
    if (!Object.prototype.hasOwnProperty.call(REGEX_CACHE, expr)) {
      REGEX_CACHE[expr] = new RegExp(expr);
    }
    return REGEX_CACHE[expr];
  }

  /* ---- 与 common.py 对应 ---- */

  function stripCode(text) {
    // 与 Python 侧同样的三趟替换，全部替成等长空格：偏移不变，行号不乱
    return text
      .replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, function (m) { return spaces(m.length); })
      .replace(/<!--[\s\S]*?-->/g, function (m) { return spaces(m.length); })
      .replace(/`[^`\n]+`/g, function (m) { return spaces(m.length); });
  }

  function splitSentences(text) {
    // 复刻 re.split(r"(?<=[。！？；!?;])|\n+")：句末标点之后切、连续换行切
    var chunks = [];
    var buf = "";
    for (var i = 0; i < text.length; i++) {
      var ch = text.charAt(i);
      if (ch === "\n") {
        chunks.push(buf);
        buf = "";
        while (i + 1 < text.length && text.charAt(i + 1) === "\n") { i++; }
        continue;
      }
      buf += ch;
      if (SENTENCE_CHARS.indexOf(ch) >= 0) {
        chunks.push(buf);
        buf = "";
      }
    }
    chunks.push(buf);

    var sentences = [];
    var cursor = 0;
    for (var k = 0; k < chunks.length; k++) {
      var chunk = chunks[k];
      if (!chunk) { continue; }
      var stripped = chunk.trim();
      if (!stripped) { cursor += chunk.length; continue; }
      var start = text.indexOf(stripped, cursor);
      if (start < 0) { start = cursor; }
      sentences.push({ text: stripped, start: start, end: start + stripped.length });
      cursor = start + stripped.length;
    }
    return sentences;
  }

  function countOccurrences(text, sub) {
    var total = 0;
    var index = 0;
    while ((index = text.indexOf(sub, index)) >= 0) {
      total += 1;
      index += sub.length;
    }
    return total;
  }

  function nearbyAmplifier(text, start, end) {
    var segment = text.slice(Math.max(0, start - W.amplifier), Math.min(text.length, end + W.amplifier));
    var hit = [];
    for (var i = 0; i < AMPLIFIERS.length; i++) {
      if (segment.indexOf(AMPLIFIERS[i]) >= 0) { hit.push(AMPLIFIERS[i]); }
    }
    return hit;
  }

  function containsAny(text, prefixes) {
    for (var i = 0; i < prefixes.length; i++) {
      if (text.indexOf(prefixes[i]) >= 0) { return true; }
    }
    return false;
  }

  function anyCharIn(text, marks) {
    for (var i = 0; i < marks.length; i++) {
      if (text.indexOf(marks[i]) >= 0) { return true; }
    }
    return false;
  }

  // 截到第一个断句标点之前。反问标记必须和被否定的那个词同处一句：
  // 「我不是公知，这不是明摆着的吗」右边确实有"吗"，但那是下一分句，
  // "我不是公知"本身是清楚的否认。不截断就会把它翻成"正在使用"。
  function cutAtBreak(text) {
    var cut = text.length;
    for (var i = 0; i < CLAUSE_BREAKS.length; i++) {
      var at = text.indexOf(CLAUSE_BREAKS[i]);
      if (at >= 0 && at < cut) { cut = at; }
    }
    return text.slice(0, cut);
  }

  // 「这不是…X…吗」：形式带否定词，功能是定性。只看紧邻的"不是"不够——
  // 「这不是典型的公知话术吗」中间隔了四个字。但也不能一律放宽：
  // 「我不是公知，这不是明摆着的吗」的主语是第一人称，讲的是否认。
  function rhetoricalFrame(text, start, end) {
    var tail = text.slice(Math.max(0, start - 12), start);
    var pos = tail.lastIndexOf("不是");
    if (pos < 0) { return false; }
    var subject = tail.slice(Math.max(0, pos - 3), pos);
    var matched = false;
    for (var i = 0; i < RHETORICAL_SUBJECTS.length; i++) {
      if (subject.indexOf(RHETORICAL_SUBJECTS[i]) >= 0) { matched = true; break; }
    }
    if (!matched) { return false; }
    var between = tail.slice(pos + 2);
    if (anyCharIn(between, CLAUSE_BREAKS)) { return false; }
    return REVERSAL_RE.test(cutAtBreak(text.slice(end, end + W.roleRight)));
  }

  function contextRole(text, start, end) {
    var left = text.slice(Math.max(0, start - W.role), start);
    var right = cutAtBreak(text.slice(end, end + W.roleRight));

    // "这不是 X 是什么？"是反问式定性，不是在否认——必须先排除，否则最典型的
    // 扣帽子句式会被判成否认句，一降级就等于放过。
    if (/(?:不是|不属于|不像)$/.test(left.replace(/\s+$/, "")) && REVERSAL_RE.test(right)) {
      return "used";
    }
    if (rhetoricalFrame(text, start, end)) { return "used"; }
    // 紧邻的否定：反问标记没出现时，"这不像 X""这不属于 X" 就是明确的否认。
    // 只在紧邻时生效——"不像话，这就是 X" 里的"不像"隔着一个词，不能算。
    if (/(?:不属于|不像)$/.test(left.replace(/\s+$/, ""))) { return "denied"; }
    if (containsAny(left, NEGATION_PREFIXES)) { return "denied"; }
    if (containsAny(left, META_PREFIXES)) { return "quoted"; }
    var prefix = text.slice(0, start);
    for (var i = 0; i < QUOTE_PAIRS.length; i++) {
      if (countOccurrences(prefix, QUOTE_PAIRS[i][0]) > countOccurrences(prefix, QUOTE_PAIRS[i][1])) {
        return "quoted";
      }
    }
    for (var k = 0; k < STRAIGHT_QUOTES.length; k++) {
      if (countOccurrences(prefix, STRAIGHT_QUOTES[k]) % 2 === 1) { return "quoted"; }
    }
    return "used";
  }

  function severityFor(intensity, amplifiers, role) {
    var score = intensity + (amplifiers.length >= 2 ? 1 : 0);
    var level = score >= 4 ? "Critical" : (score >= 2 ? "Warning" : "Info");
    if (role !== "used") {
      var order = ["Info", "Warning", "Critical"];
      level = order[Math.max(0, order.indexOf(level) - 1)];
    }
    return level;
  }

  /* ---- 与 hat_scan.py 对应 ---- */

  function lineAt(text, offset) {
    var line = 1;
    for (var i = 0; i < offset && i < text.length; i++) {
      if (text.charAt(i) === "\n") { line += 1; }
    }
    return line;
  }

  function makeFinding(kind, id, name, matched, family, severity, text, absolute, sentence, amplifiers, role, mechanism, remedy) {
    return {
      kind: kind,
      pattern_id: id,
      name: name,
      matched: matched,
      family: family,
      severity: severity,
      line: lineAt(text, absolute),
      offset: absolute,
      length: matched.length,
      sentence: sentence,
      amplifiers: amplifiers,
      role: role,
      struct: "",
      demoted: false,
      mechanism: mechanism,
      remedy: remedy
    };
  }

  var ID_RE = /(?:HAT-F[1-8]-\d{2}|PAT-\d{2}|CMB-\d{2}|CRP-\d{2,3})/;
  var LIST_MARK_RE = /^(?:[-*+]|\d+[.)])\s/;

  function markdownSlot(text, absolute) {
    var lineStart = absolute === 0 ? 0 : text.lastIndexOf("\n", absolute - 1) + 1;
    var lineEnd = text.indexOf("\n", absolute);
    if (lineEnd < 0) { lineEnd = text.length; }
    var line = text.slice(lineStart, lineEnd).replace(/^\s+/, "");
    if (line.charAt(0) === "#") { return "heading"; }
    if (line.charAt(0) === "|") { return "table"; }
    if (line.charAt(0) === ">") { return "quote"; }
    if (LIST_MARK_RE.test(line)) { return "list"; }
    return "";
  }

  function docModeRole(role, text, absolute) {
    // 与 common.doc_mode_role 同构：标题和表格是"给标签起名/归类"的格子，
    // 列表项要带 HAT-/PAT-/CMB-/CRP- 编号才算条目，引用块一律不动。
    var slot = markdownSlot(text, absolute);
    if (role !== "used" || !slot) { return { role: role, slot: slot }; }
    if (slot === "heading" || slot === "table") { return { role: "quoted", slot: slot }; }
    if (slot === "list") {
      var lineStart = absolute === 0 ? 0 : text.lastIndexOf("\n", absolute - 1) + 1;
      var lineEnd = text.indexOf("\n", absolute);
      var line = text.slice(lineStart, lineEnd < 0 ? text.length : lineEnd);
      if (ID_RE.test(line)) { return { role: "quoted", slot: slot }; }
    }
    return { role: role, slot: slot };
  }

  function detectCombos(findings, combos, window) {
    // 只收 role === "used"。连招要求每一环都是作者自己打的；讲解文章里
    // 挨着引用的三段句式能拼成一个 Critical 连招，那是被引用的话，不构成封堵。
    var usable = [];
    for (var i = 0; i < findings.length; i++) {
      var item = findings[i];
      if ((item.kind === "pattern" || item.kind === "hat") &&
          (item.role || "used") === "used") {
        usable.push(item);
      }
    }
    if (!usable.length) { return []; }

    var byId = {};
    for (var j = 0; j < usable.length; j++) {
      var key = usable[j].pattern_id;
      if (!byId[key]) { byId[key] = []; }
      byId[key].push(usable[j]);
    }

    var hits = [];
    for (var c = 0; c < combos.length; c++) {
      var combo = combos[c];
      var sequence = combo.sequence || [];
      if (!sequence.length) { continue; }
      var stages = sequence.map(function (stage) {
        return Array.isArray(stage) ? stage : [stage];
      });

      var complete = true;
      for (var s = 0; s < stages.length; s++) {
        var any = false;
        for (var a = 0; a < stages[s].length; a++) {
          if (byId[stages[s][a]]) { any = true; break; }
        }
        if (!any) { complete = false; break; }
      }
      if (!complete) { continue; }

      var firstPool = [];
      for (var f0 = 0; f0 < stages[0].length; f0++) {
        firstPool = firstPool.concat(byId[stages[0][f0]] || []);
      }
      if (!firstPool.length) { continue; }

      // 取能让整串最紧凑的一组出现位置
      firstPool.sort(function (x, y) { return x.offset - y.offset; });
      var best = null;
      for (var fi = 0; fi < firstPool.length; fi++) {
        var chosen = [firstPool[fi]];
        var ok = true;
        for (var st = 1; st < stages.length; st++) {
          var pool = [];
          for (var pc = 0; pc < stages[st].length; pc++) {
            pool = pool.concat(byId[stages[st][pc]] || []);
          }
          var later = null;
          for (var pi = 0; pi < pool.length; pi++) {
            if (pool[pi].offset > chosen[chosen.length - 1].offset) {
              if (later === null || pool[pi].offset < later.offset) { later = pool[pi]; }
            }
          }
          if (!later) { ok = false; break; }
          chosen.push(later);
        }
        if (!ok) { continue; }
        var span = chosen[chosen.length - 1].offset - chosen[0].offset;
        if (span <= window && (best === null || span < best.span)) {
          best = { span: span, chosen: chosen };
        }
      }
      if (!best) { continue; }

      var first = best.chosen[0];
      var sentences = [];
      for (var sc = 0; sc < best.chosen.length; sc++) {
        if (sentences.indexOf(best.chosen[sc].sentence) < 0) { sentences.push(best.chosen[sc].sentence); }
      }
      var amplifiers = [];
      for (var ac = 0; ac < best.chosen.length; ac++) {
        var list = best.chosen[ac].amplifiers || [];
        for (var ai = 0; ai < list.length; ai++) {
          if (amplifiers.indexOf(list[ai]) < 0) { amplifiers.push(list[ai]); }
        }
      }
      amplifiers.sort();
      var tail = best.chosen.slice(1).map(function (item) { return item.name; }).join(" / ");
      var seal = combo.seal_degree === undefined ? "?" : combo.seal_degree;
      var breakSteps = combo.break_steps || ["无"];

      hits.push({
        kind: "combo",
        pattern_id: combo.id,
        name: combo.name,
        matched: best.chosen.map(function (item) { return item.pattern_id; }).join(" → "),
        family: first.family || "",
        severity: (combo.seal_degree || 0) >= 3 ? "Critical" : "Warning",
        line: first.line,
        offset: first.offset,
        length: best.span,
        sentence: sentences.join(" / "),
        amplifiers: amplifiers,
        role: "used",
        mechanism: "连招 " + combo.id + "：" + (first.mechanism || "") +
          (tail ? " 后续接 " + tail : "") + "，封死 " + seal + " 向回应路径",
        remedy: breakSteps[0],
        members: best.chosen.map(function (item) { return item.pattern_id; }),
        span: best.span,
        break_at: combo.break_at || ""
      });
    }
    return hits;
  }

  function scan(text, options) {
    options = options || {};
    var stripCodeBlocks = options.stripCode !== false;
    var docMode = options.docMode === true;
    var window = options.window || W.combo;
    var body = stripCodeBlocks ? stripCode(text) : text;
    var chars = Array.from(body.replace(/\s/g, "")).length;
    var findings = [];
    var sentences = splitSentences(body);

    function settle(role, absolute) {
      if (!docMode) { return { role: role, slot: "", demoted: false }; }
      var settled = docModeRole(role, body, absolute);
      return {
        role: settled.role,
        slot: settled.slot,
        demoted: settled.role !== role
      };
    }

    for (var s = 0; s < sentences.length; s++) {
      var sentence = sentences[s];
      var line = sentence.text;

      for (var h = 0; h < RULES.hats.length; h++) {
        var hat = RULES.hats[h];
        var tokens = [hat.name].concat(hat.aliases || []);
        var position = -1;
        var token = "";
        for (var t = 0; t < tokens.length; t++) {
          var index = line.indexOf(tokens[t]);
          if (index >= 0 && (position < 0 || index < position)) {
            position = index;
            token = tokens[t];
          }
        }
        if (position < 0) { continue; }
        var absolute = sentence.start + position;
        var amplifiers = nearbyAmplifier(body, absolute, absolute + token.length);
        var settled = settle(contextRole(body, absolute, absolute + token.length), absolute);
        var finding = makeFinding("hat", hat.id, hat.name, token, hat.family,
          severityFor(hat.intensity, amplifiers, settled.role), body, absolute, line,
          amplifiers, settled.role, hat.mechanism, (hat.counter || [""])[0]);
        finding.struct = settled.slot;
        finding.demoted = settled.demoted;
        findings.push(finding);
      }

      for (var p = 0; p < RULES.patterns.length; p++) {
        var pattern = RULES.patterns[p];
        var regexes = pattern.detect_regex || [];
        for (var r = 0; r < regexes.length; r++) {
          var match = regexFor(regexes[r]).exec(line);
          if (!match) { continue; }
          var offset = sentence.start + match.index;
          var amps = nearbyAmplifier(body, offset, offset + match[0].length);
          var patternSettled = settle(contextRole(body, offset, offset + match[0].length), offset);
          var item = makeFinding("pattern", pattern.id, pattern.name, match[0],
            pattern.family_hint || "", severityFor(2, amps, patternSettled.role), body, offset,
            line, amps, patternSettled.role, pattern.essence, (pattern.counter || [""])[0]);
          item.struct = patternSettled.slot;
          item.demoted = patternSettled.demoted;
          findings.push(item);
          break;
        }
      }
    }

    findings = findings.concat(detectCombos(findings, RULES.combos, window));
    return { chars: chars, findings: findings, stats: score(findings, chars), text: body };
  }

  function pyRound(value) {
    // Python 的 round 是"四舍六入五取偶"，Math.round 是五入。差 1 分也会让对拍红，
    // 所以照抄 Python 的规则。
    var floor = Math.floor(value);
    var diff = value - floor;
    if (diff > 0.5) { return floor + 1; }
    if (diff < 0.5) { return floor; }
    return floor % 2 === 0 ? floor : floor + 1;
  }

  function score(findings, chars) {
    // 只统计 role === "used"。被引用的、被否认的命中不参与打分——
    // 否则一篇《我没有收钱，也不是公知》的澄清文和真攻击文拿同样的分。
    // 这部分命中另计到 quoted_hits / denied_hits，报告里照常展示。
    var realKilo = Math.max(chars, 1) / 1000;
    var scoringKilo = Math.max(chars, 1000) / 1000;
    var hats = 0, patterns = 0, combos = 0, criticals = 0, quoted = 0, denied = 0;
    for (var i = 0; i < findings.length; i++) {
      var item = findings[i];
      var used = (item.role || "used") === "used";
      if (item.role === "quoted") { quoted += 1; }
      if (item.role === "denied") { denied += 1; }
      if (!used) { continue; }
      if (item.kind === "hat") { hats += 1; }
      if (item.kind === "pattern") { patterns += 1; }
      if (item.kind === "combo") { combos += 1; }
      if (item.severity === "Critical") { criticals += 1; }
    }
    var density = (hats * 10 + patterns * 8 + combos * 14) / scoringKilo;
    var raw = 12 * Math.log2(1 + density) + criticals * 4;
    return {
      chars: chars,
      hat_hits: hats,
      pattern_hits: patterns,
      combo_hits: combos,
      critical_hits: criticals,
      quoted_hits: quoted,
      denied_hits: denied,
      hat_per_kilo: Math.round((hats / realKilo) * 100) / 100,
      pattern_per_kilo: Math.round((patterns / realKilo) * 100) / 100,
      label_score: Math.min(100, pyRound(raw)),
      raw: raw,
      verdict: verdictFor(raw)
    };
  }

  function verdictFor(raw) {
    if (raw >= 60) { return "重度标签化：论证基本让位于身份定性"; }
    if (raw >= 25) { return "中度标签化：攻击句式已经替代了部分反驳"; }
    if (raw > 0) { return "轻度标签化：存在可替换为具体主张的标签"; }
    return "未检出标签化表达";
  }

  return {
    scan: scan,
    score: score,
    stripCode: stripCode,
    splitSentences: splitSentences,
    contextRole: contextRole,
    markdownSlot: markdownSlot,
    docModeRole: docModeRole,
    severityFor: severityFor,
    detectCombos: detectCombos,
    rules: function () { return RULES; }
  };
});
