/* 对拍用的 node 侧入口：从 stdin 读 [{id, text}]，输出 [{id, result}]。
 *
 * 单独一个 runner 是为了让 scripts/web_parity.py 只做比较，不做进程编排——
 * 比较逻辑里混进 spawn 就没法单独测了。
 */
"use strict";

const path = require("path");
const scan = require(path.join(__dirname, "..", "docs", "scan.js"));

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { raw += chunk; });
process.stdin.on("end", () => {
  let cases;
  try {
    cases = JSON.parse(raw);
  } catch (err) {
    process.stderr.write("stdin 不是合法 JSON: " + err.message + "\n");
    process.exit(2);
  }
  const out = cases.map((item) => {
    const result = scan.scan(item.text);
    return {
      id: item.id,
      chars: result.chars,
      stats: result.stats,
      findings: result.findings.map((f) => ({
        kind: f.kind,
        pattern_id: f.pattern_id,
        matched: f.matched,
        severity: f.severity,
        role: f.role,
        offset: f.offset
      }))
    };
  });
  process.stdout.write(JSON.stringify(out));
});
