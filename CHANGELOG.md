# CHANGELOG

格式按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号按语义化版本。

`## <版本号>` 这一行的格式被 `scripts/release_notes.py` 依赖——改格式会让发布流程抽不到说明，CI 会拦住。

## 1.7.0

### 新增

- **`install.sh --check` / `install.ps1 -Check`**：只读不写，一次报三件事——本地装的是哪一版、线上现在哪一版、本地文件与包内 `MANIFEST.sha256` 是否还一致。
  - 退出码 `0` 不用动 · `1` 该动手（有更新 / 未安装 / 本地文件被改）· `2` 查不到版本。所以 `install.sh --check || install.sh -y` 就是"有新版才装"，不需要人看输出。
  - 给了 `--version` 就不问 API，离线环境与 CI 限流都能跑。
  - 版本比较按数字段比：`1.10.0` 比 `1.9.0` 新，字符串比会判反，而这类脚本判反了不报错，只是永远"已是最新"。
- **`package.py --check-dir`**：核对一个**已安装目录**。装完之后被改一行、被半路中断的拷贝覆盖过，都不会有任何报错，只会在某天扫不出东西时才暴露。清单就在安装目录里，核一遍很便宜。源码态没有 `MANIFEST` 就说"跳过"，那不是失败。

### 修复

- **PowerShell 侧版本比较恒判相等**：PowerShell 变量名大小写不敏感，函数里 `$a = ... -split` 赋给的其实是 `[string]$A` 参数，数组被强转成 `"1 10 0"`，`Count` 恒为 1，循环只跑一轮。表现是 `--check` 一路报"已是最新"，用户永远装不上新版，而且**不报任何错**。
- **Windows 上 `install.ps1` 输出串码**：python 侧固定吐 UTF-8（`common.ensure_utf8_stdout`），本进程在中文 Windows 上默认 GBK，两者混在同一条管道里，两边都变乱码。改为调用子进程期间临时对齐 `[Console]::OutputEncoding`，收完字符串再恢复——不动全局控制台编码，免得把 `cmd.exe` 里的中文也带成乱码。
- PowerShell 5.1 上显式补 TLS 1.2，别让老 .NET 的默认协议把 GitHub API 挡在握手阶段。

### 测试

- 新增 22 项：`--check` 两平台各跑一遍（含 `1.10.0` vs `1.9.0` 这种字符串比会判反的用例、`v` 前缀、本地比线上新、未安装）、`--check-dir` 的通过/篡改/缺文件/源码态跳过、`--check` 说好了不动磁盘、给了 `--version` 不许联网、参数打错必须报错退出。
- `--check` 的两套断言写成同一个 mixin——两个平台的语义必须一致，各抄一遍迟早分叉。

## 1.6.1

### 修复

- 装好的 skill 里跑 `python3 scripts/gate.py --tier core` 会红在「单元测试」上——包里不带 `tests/`，而门禁把"目录不存在"当成了"测试失败"。现在门禁声明 `needs`，缺了就标 `SKIP 缺 tests/（安装包不带）`，退出码仍为 0。
- 语法编译同样只编译存在的目录，避免打出 `Can't list .../tests` 这种噪音。

> 这条是在 v1.6.0 发布后，从 Release 装一遍再跑 gate 才发现的——打包自检验的是"能不能跑扫描器"，没验"装完之后门禁自己还绿不绿"。

## 1.6.0

### 新增

- **统一门禁入口** `scripts/gate.py`：八道门禁的顺序、集合、每道挡什么，全部写在代码里。本地 `python3 scripts/gate.py` 与 CI 跑的是同一套。
  - `--list` / `--explain`：有哪些门禁、每道挡什么、失败了先看哪
  - `--tier core|full` / `--only data,corpus`：按需跑
  - `--markdown PATH`：产出 Step Summary 用的表格
  - `--stop-early`：本地快速迭代时第一道失败就退出（默认跑完，一次看全）
- **`scripts/cli_smoke.py`**：把 `ci.yml` 里五个 shell 冒烟 step 收编成脚本，本地可一条命令跑。
- 门禁失败时直接给出三件事：输出了什么、**这道门禁挡的是什么**、先看哪里。

### 变更

- `ci.yml` / `release.yml` 只决定"哪个 Python 版本跑哪一层"，不再逐个列举脚本名。新增测试 `test_workflows_go_through_single_entry` 盯着这件事——谁在 yml 里再抄一遍脚本名，CI 就红。
- CI 摘要改由 `gate.py --markdown` 产出，workflow 只 `cat`。在 yml 里嵌 heredoc 拼 JSON 很容易被缩进和引号搞死，而且只在 CI 上才暴露。
- 单元测试里"跑全部文档命令"那条在 gate 下跳过（与 `docs` 门禁重复，省 12s）；直接跑 `unittest` 时仍然生效。

### 修复

- `doc_smoke.py` 遇到文档里的 `scripts/gate.py` 示例会**无限递归**（gate → docs → doc_smoke → gate）。这类命令现在只登记不执行，输出里明确写"跳过 N 条（会递归）"；`--list` / `--explain` 不跑门禁，照跑。
- `common.load_json` 加缓存（key 含文件 mtime）。90 多个测试反复 parse 同一批 JSON 纯属白烧。**代价是暴露了一个潜伏的别名 bug**：`hat_generate` 里 `pool = hats` 没有复制，`rng.shuffle(pool)` 就地打乱了共享列表——以前每次重新 parse 掩盖了它，加缓存后同 seed 会产出不同结果。改成 `list(hats)`。
- 测试里用子进程点名整个测试类，而那个类里正好有这条测试自己 → 无限级联出子进程。改成只点名那一条测试方法，并加超时。
- `skipIf` 装饰器被插在错误函数上（新增测试时挤位），导致"跳过 11 秒"实际没跳过。补了一条测试专门盯这个错位。

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
