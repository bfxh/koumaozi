# CHANGELOG

格式按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号按语义化版本。

`## <版本号>` 这一行的格式被 `scripts/release_notes.py` 依赖——改格式会让发布流程抽不到说明，CI 会拦住。

## 1.5.0

### 新增

- **文档即测试**：`scripts/doc_smoke.py`，把 README / SKILL / references 里 29 条命令示例逐条真跑，断言退出码 0、`--json` 输出真是 JSON、引用的样例文件真的存在。文档示例是唯一会被读者逐字复制的东西，它腐烂起来是静默的——脚本改名、参数一改，源码门禁一条都不会红。
- **`examples/`**：文档命令引用的样例文件，照抄就能跑。也一起打进发布包，装了包再看 SKILL.md，例子依然可跑。

### 修复

- `hat_diff.py` 把不存在的路径当正文分析。`--after draft-v2.md` 文件不存在时，它不报错，而是去分析字符串 `"draft-v2.md"`，读者会以为对比了两个文件、拿到一个看着正常的错误结果。现在带文档后缀或路径分隔符却不存在，直接报错并提示改用 `--before-text` / `--after-text`。

### 变更

- 安装文档不再硬编码版本号：bash 从 `releases/latest` 的 302 里取 tag，`package.py --verify` 用 glob 匹配 `dist/*.zip`，发版不用再回来改文档。
- `package.py` 的打包白名单加入 `examples/`。
- CI 加第八道：文档命令门禁（每次 push 都跑，不只发版时）。

## 1.4.0

首个对外发布。之前 1.0~1.3 是开发期内部版本，没有打 tag，所以这次发布包含它们的全部内容。

### 新增

- **可安装产物**：`scripts/package.py` 打 `koumaozi-<version>.zip` + `.sha256`，包内附 `MANIFEST.sha256`。
- **产物自检**：`package.py --verify` 解压到干净临时目录，按清单校验每个文件的 sha256，再在**解压后**的目录里跑数据门禁、语料门禁、扫描、生成、改稿对比。验证对象是被交付的那一份，不是源目录。
- **发布流水线**：`.github/workflows/release.yml`，推 `v*` tag 触发；校验 tag 与 `VERSION` 一致 → 复跑全量门禁 → 打包自检 → 建 Release 并附 zip / sha256。
- **一键安装**：`scripts/install.sh`（Linux/macOS/WSL）、`scripts/install.ps1`（Windows）。支持从 Release 下载、从本地 zip 安装、从本地目录软链三种方式。
- `VERSION` 文件作为版本单一真源；`verify_data.py` 校验 `SKILL.md` 的 `version` 与之同步。

### 变更

- 命名门禁的"目录名必须等于 skill name"只在存在 `.git` 时生效。装好之后目录名由安装者决定（解压成 `koumaozi-1.4.0` 很正常），拿它当门禁会让产物自检永远红。
- CI action 升到 `checkout@v7` / `setup-python@v7`（原版本还在 Node 20 运行时上）；`runs-on` 锁 `ubuntu-24.04`；加 `concurrency` 取消过期矩阵；门禁结论写入 Step Summary。

## 1.3.0

### 新增

- **语境样本**（`kind: "context"`）8 条：字面有帽子词，但语境是引用或否认，断言零有效命中。断言靠三个字段咬死：`min_raw`（词形必须真触发过）、`downgraded`（必须是指定的那一顶被降级）、`max_hits: 0`（结论）。

### 修复

- `有同事质疑对方收钱` 被判成本人在扣帽子。`META_PREFIXES` 补 `质疑` / `怀疑` / `指责` / `控诉` / `追责`，转述他人指控一律降级。代价是 `我质疑你收钱` 也降一级——把怀疑说成怀疑本来就比直接定性弱。

### 已知限制

- `把对手说成水军`（描述手法）与 `别把红利说成本事`（攻击）词面结构相同，扫描器判不出，需人工读。已写进 `SKILL.md`。

## 1.2.0

### 新增

- **覆盖门禁**：句式 / 连招 / 家族 / 帽子四层覆盖统计。要求 24 式全部有独立语料、10 条连招全部覆盖、每家族 ≥2 条语料且 ≥2 顶帽子。
- **性能门禁**：18k 字长文、28k 单句、4650 字高命中密度三种输入必须线性时间跑完，防正则回溯爆炸。
- CI 增加 3.13 专属 `-W error::DeprecationWarning` 步骤。

### 变更

- 回归语料 32 → 47 条。加覆盖门禁后立刻露出 8 项缺口（PAT-04/06/16/19 零覆盖，moral-verdict 与 temporal-politics 各只有 1 条），补了 15 条。
- 帽子覆盖 21/55 是刻意的：帽子匹配是精确词形，别名唯一性由 `verify_data` 拦，所以是代表性抽样而非能力缺口。

## 1.1.0

### 新增

- **连招** `data/combos.json` 10 条。序列是候选集（PAT 或 HAT 任一命中即算该环成立），取最紧凑的一组出现位置，跨度 ≤ 300 字。
- `scripts/hat_diff.py`：改稿前后对比，`--must-drop` / `--max-score` 可直接当门禁。
- **回归语料** 32 条（24 正 + 8 负）。
- **命中角色判定**：`used` / `denied` / `quoted`，后两者降一级。三个例外：`"这不是 X 是什么？"` 是反问式定性必须判 `used`；`"我没有收钱"` → `denied`；`"他说我是公知"` → `quoted`。

## 1.0.0

### 新增

- 55 顶帽子 / 8 个家族 / 24 式攻击句式。
- `hat_scan.py`（命中定位 + 强化词 + 对数压缩评分）、`hat_generate.py`（模板拼装，同 `--seed` 可复现，强制成对输出破解点）、`verify_data.py`、`wordcount.py`。
- 识别与生成双模工作流、反制三阶、五份 references。
- 六道 CI 门禁，Python 3.9 / 3.12 / 3.13 三版本矩阵。
