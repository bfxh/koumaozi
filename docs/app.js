/* 页面逻辑：调用 scan.js，把结果画出来。
 *
 * 这里不做任何判定——判定全在 scan.js 里，scan.js 由 web_parity 对着
 * hat_scan.py 逐条校验。页面最怕的是一边显示一边自己加规则，那对拍就白做了。
 */
(function () {
  "use strict";

  var RULES = window.KOUMAOZI_RULES;
  var SCAN = window.KOUMAOZI_SCAN;
  var els = {
    meta: document.getElementById("meta"),
    samples: document.getElementById("samples"),
    text: document.getElementById("text"),
    counter: document.getElementById("counter"),
    clear: document.getElementById("clear"),
    score: document.getElementById("score"),
    bar: document.getElementById("bar"),
    verdict: document.getElementById("verdict"),
    counts: document.getElementById("counts"),
    markup: document.getElementById("markup"),
    findings: document.getElementById("findings")
  };

  var ROLE_LABEL = { used: "正在使用", denied: "被否认", quoted: "被引用" };
  var SEVERITY_CLASS = { Critical: "critical", Warning: "warning", Info: "info" };

  function escapeHtml(text) {
    return text.replace(/[&<>"]/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch];
    });
  }

  function clearChildren(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  /* ---- 示例：从语料里挑，不写死文本 ---- */

  function pickSamples() {
    var byKind = {};
    RULES.corpus.forEach(function (item) { byKind[item.kind] = byKind[item.kind] || item; });
    var picked = [];
    if (byKind.attack) { picked.push({ label: "典型扣帽子", case: byKind.attack }); }
    if (byKind.context) { picked.push({ label: "引用 / 否认（该降级）", case: byKind.context }); }
    if (byKind.neutral) { picked.push({ label: "中性文本（零命中）", case: byKind.neutral }); }

    // 连招最能说明问题：找一条真的能出连招的语料，找不到就不放这个按钮
    for (var i = 0; i < RULES.corpus.length; i++) {
      var result = SCAN.scan(RULES.corpus[i].text);
      if (result.stats.combo_hits > 0) {
        picked.push({ label: "连招（" + RULES.corpus[i].id + "）", case: RULES.corpus[i] });
        break;
      }
    }
    return picked;
  }

  function renderSamples() {
    var samples = pickSamples();
    samples.forEach(function (item) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "chip";
      button.textContent = item.label;
      button.addEventListener("click", function () {
        els.text.value = item.case.text;
        run();
        els.text.focus();
      });
      els.samples.appendChild(button);
    });
  }

  /* ---- 渲染 ---- */

  function renderCounts(stats) {
    clearChildren(els.counts);
    var pairs = [
      ["帽子", stats.hat_hits],
      ["句式", stats.pattern_hits],
      ["连招", stats.combo_hits],
      ["Critical", stats.critical_hits],
      ["每千字帽子", stats.hat_per_kilo],
      ["字数", stats.chars]
    ];
    pairs.forEach(function (pair) {
      var li = document.createElement("li");
      li.textContent = pair[0] + " " + pair[1];
      els.counts.appendChild(li);
    });
  }

  function ranges(findings) {
    // 只标帽子与句式：连招是它们的组合，单独标会和成员重复
    var spans = findings
      .filter(function (item) { return item.kind !== "combo"; })
      .map(function (item) {
        return { start: item.offset, end: item.offset + item.length, soft: item.role !== "used" };
      })
      .sort(function (a, b) { return a.start - b.start || b.end - a.end; });

    var merged = [];
    spans.forEach(function (span) {
      var last = merged[merged.length - 1];
      if (last && span.start < last.end) {
        last.end = Math.max(last.end, span.end);
        last.soft = last.soft && span.soft;
        return;
      }
      merged.push({ start: span.start, end: span.end, soft: span.soft });
    });
    return merged;
  }

  function renderMarkup(text, findings) {
    if (!text.trim()) {
      els.markup.className = "empty";
      els.markup.textContent = "贴一段文本，这里会把命中的地方标出来。";
      return;
    }
    var spans = ranges(findings);
    if (!spans.length) {
      els.markup.className = "";
      els.markup.textContent = text;
      return;
    }
    var html = "";
    var cursor = 0;
    spans.forEach(function (span) {
      var start = Math.min(Math.max(span.start, 0), text.length);
      var end = Math.min(Math.max(span.end, start), text.length);
      html += escapeHtml(text.slice(cursor, start));
      html += '<mark' + (span.soft ? ' class="soft"' : "") + ">" +
        escapeHtml(text.slice(start, end)) + "</mark>";
      cursor = end;
    });
    html += escapeHtml(text.slice(cursor));
    els.markup.className = "";
    els.markup.innerHTML = html;
  }

  function renderFindings(findings) {
    clearChildren(els.findings);
    if (!findings.length) {
      var empty = document.createElement("li");
      empty.className = "empty";
      empty.style.border = "none";
      empty.style.background = "none";
      empty.style.padding = "0";
      empty.textContent = "暂无命中。";
      els.findings.appendChild(empty);
      return;
    }

    var order = { Critical: 0, Warning: 1, Info: 2 };
    var sorted = findings.slice().sort(function (a, b) {
      return (order[a.severity] - order[b.severity]) || (a.offset - b.offset);
    });

    sorted.forEach(function (item) {
      var li = document.createElement("li");

      var head = document.createElement("div");
      head.className = "fhead";

      var sev = document.createElement("span");
      sev.className = "tag " + (SEVERITY_CLASS[item.severity] || "info");
      sev.textContent = item.severity;
      head.appendChild(sev);

      var kind = document.createElement("span");
      kind.className = "tag role";
      kind.textContent = item.kind === "combo" ? "连招" : (item.kind === "hat" ? "帽子" : "句式");
      head.appendChild(kind);

      var id = document.createElement("span");
      id.className = "fid";
      id.textContent = item.pattern_id;
      head.appendChild(id);

      var name = document.createElement("span");
      name.className = "fname";
      name.textContent = item.name;
      head.appendChild(name);

      if (item.role !== "used") {
        var role = document.createElement("span");
        role.className = "tag role";
        role.textContent = ROLE_LABEL[item.role] || item.role;
        head.appendChild(role);
      }
      li.appendChild(head);

      var matched = document.createElement("div");
      matched.className = "fdetail";
      matched.innerHTML = "命中 <b>" + escapeHtml(item.matched) + "</b>" +
        (item.kind === "combo" ? "　跨度 " + item.span + " 字" : "");
      li.appendChild(matched);

      var mech = document.createElement("div");
      mech.className = "fdetail";
      mech.textContent = item.mechanism;
      li.appendChild(mech);

      var fix = document.createElement("div");
      fix.className = "ffix";
      fix.textContent = item.kind === "combo" && item.break_at
        ? item.break_at + "（" + item.remedy + "）"
        : item.remedy;
      li.appendChild(fix);

      els.findings.appendChild(li);
    });
  }

  function setScore(stats, hasText) {
    els.score.textContent = hasText ? String(stats.label_score) : "—";
    els.bar.style.width = (hasText ? stats.label_score : 0) + "%";
    els.verdict.textContent = hasText
      ? stats.verdict
      : "还没有输入。";
    renderCounts(hasText ? stats : {
      hat_hits: 0, pattern_hits: 0, combo_hits: 0, critical_hits: 0,
      hat_per_kilo: 0, chars: 0
    });
  }

  /* ---- 主流程 ---- */

  var timer = null;

  function run() {
    var text = els.text.value;
    els.counter.textContent = Array.from(text.replace(/\s/g, "")).length + " 字";
    var hasText = text.trim().length > 0;

    if (!hasText) {
      setScore(null, false);
      renderMarkup("", []);
      renderFindings([]);
      return;
    }

    var result = SCAN.scan(text);
    setScore(result.stats, true);
    renderMarkup(text, result.findings);
    renderFindings(result.findings);
  }

  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(run, 120);
  }

  /* ---- 启动 ---- */

  els.meta.textContent = "规则 v" + RULES.version + " · 帽子 " + RULES.hats.length +
    " · 句式 " + RULES.patterns.length + " · 连招 " + RULES.combos.length +
    " · 判定与命令行版逐条对拍";

  renderSamples();
  els.text.addEventListener("input", schedule);
  els.clear.addEventListener("click", function () {
    els.text.value = "";
    run();
    els.text.focus();
  });

  // 支持 ?text=xxx 直接带文本进来，方便分享某一段
  var shared = new URLSearchParams(window.location.search).get("text");
  if (shared) {
    els.text.value = shared;
  } else {
    var first = RULES.corpus.filter(function (item) { return item.kind === "attack"; })[0];
    if (first) { els.text.value = first.text; }
  }
  run();
})();
