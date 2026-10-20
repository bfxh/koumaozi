# 扣帽子工程 (Koumaozi)

识别、拆解、反制、生成——中文语境下的标签化攻击，一套可执行的工具。

不是教你怎么骂人。是教你看懂**别人怎么用六个字让你三十分钟的论证作废**，以及那个把戏为什么有效、破在哪。

## 它解决什么问题

你在网上说了一句有内容的话，收到回复：

> "收钱的吧，一看就是那路人，早晚遭报应。"

三段，二十四个字，每一段都封死了一条回应路径：

- 说"我没收钱" → 接下了不该你证明的事
- 说"我不是那路人" → 承认了群体连坐成立
- 说"什么报应" → 给了一个"你看他急了"的新素材

**这就是帽子。** 它不反驳你，它取消你。本仓库把这类操作拆成 55 顶帽子、24 式句式、8 个家族，每一顶都给出识别特征、破解入口、以及"什么时候这顶帽子会失效"。

## 安装

两种方式，都不需要 clone 仓库。

**用 Release 包**（推荐）：

```bash
# Linux / macOS / WSL —— 版本号从 latest 的 302 里取，不用手改
TAG=$(curl -sI https://github.com/bfxh/koumaozi/releases/latest \
  | grep -i '^location' | sed 's#.*/tag/##' | tr -d '\r')
ZIP="koumaozi-${TAG#v}.zip"
curl -fL -O "https://github.com/bfxh/koumaozi/releases/download/$TAG/$ZIP"
curl -fL -O "https://github.com/bfxh/koumaozi/releases/download/$TAG/$ZIP.sha256"
sha256sum -c "$ZIP.sha256"          # macOS: shasum -a 256 -c "$ZIP.sha256"
mkdir -p ~/.workbuddy/skills/koumaozi
unzip -o "$ZIP" -d ~/.workbuddy/skills/koumaozi
```

Windows 下同理，用 `Invoke-WebRequest` 取 `Headers.Location` 里的 tag 再拼文件名，或者直接跑下面的 `install.ps1`（它替你处理这些）。

**用安装脚本**（会先验 sha256，再在临时目录自检，通过了才动目标目录）：

```bash
bash scripts/install.sh                    # 装最新版
bash scripts/install.sh --version <tag>    # 指定版本，如 v1.5.0
bash scripts/install.sh --from-dir .       # 开发态：软链，改代码立即生效
```

```powershell
.\scripts\install.ps1
.\scripts\install.ps1 -Version <tag>
.\scripts\install.ps1 -FromDir .           # 开发态：Junction 指向源码
```

目标目录已存在时一律先改名成 `koumaozi.bak-<时间戳>`，不直接删——装脚本把人原来的安装干掉，比装不上更糟。

**查一下该不该动手**（只读不写）：

```bash
bash scripts/install.sh --check            # 本地版本 / 线上版本 / 本地文件对不对得上
```

```powershell
.\scripts\install.ps1 -Check
```

三件事一次报完：本地装的是哪一版、线上现在哪一版、本地文件与包内 `MANIFEST.sha256` 是否还一致（装完被改过、被半路中断的拷贝覆盖过，都不会报错，只会在某天扫不出东西时才暴露）。

退出码 `0` 不用动 · `1` 该动手（有更新 / 未安装 / 本地文件被改）· `2` 查不到版本。所以可以直接接起来用：

```bash
bash scripts/install.sh --check || bash scripts/install.sh -y    # 有新版才装
```

版本比较按数字段比，不是字符串比——`1.10.0` 比 `1.9.0` 新，字符串比会判反，而这类脚本判反了不报错，只是永远"已是最新"。

## 快速开始

```bash
# 扫一段文本，看它在扣什么帽子
python3 scripts/hat_scan.py --text "这种公知体还用看？一条多少钱？"

# 扫整个目录，只报 Warning 以上
python3 scripts/hat_scan.py --target examples/notes/ --min-severity Warning

# 整串连招（10 条固定连招，四向封死直接判 Critical）
python3 scripts/hat_generate.py --target "某博主" --combo CMB-01 --seed 3

# 改稿前后对比：分数升降、消除了什么、新增了什么
python3 scripts/hat_diff.py --before examples/draft-v1.md --after examples/draft-v2.md

# 回归语料门禁：正样本该抓必抓，负样本一个不许抓
python3 scripts/corpus_check.py

# 生成帽子文案（模板拼装，同 seed 同结果）
python3 scripts/hat_generate.py --target "某科技博主" --family motive-contamination --count 5 --seed 7

# 数据一致性门禁
python3 scripts/verify_data.py

# 内容量统计
python3 scripts/wordcount.py
```

Python 3.8+，**标准库零依赖**。Windows 控制台自动切 UTF-8。

## 结构

```
koumaozi/
├── SKILL.md                          技能主干：四要素模型、双模工作流、反制三阶
├── VERSION                           版本单一真源（SKILL.md / CHANGELOG 由门禁校验同步）
├── CHANGELOG.md                      版本史（Release 说明从这里抽）
├── data/
│   ├── hats.json                     55 顶帽子（机器可读单一真源）
│   ├── patterns.json                 24 式攻击句式 + 生成模板
│   ├── combos.json                   10 条固定连招（候选集序列）
│   └── corpus.json                   55 条回归语料（39 正 + 8 负 + 8 语境）
├── references/
│   ├── hats-catalog.md               帽子全解：55 顶 × 触发/投放/识别/破法/失效
│   ├── rhetoric-patterns.md          24 式拆解：机理、变体、为什么有效、怎么拆
│   ├── combos.md                     10 条连招：三种结构、逐条拆解、破法通则
│   ├── counterplay.md                反制手册：三阶响应、场景剧本、六种失败模式
│   ├── generation-playbook.md        生成手册：参数决策、强度控制、去 AI 味
│   └── casebook.md                   六个案例复盘：原文 → 扫描 → 拆解 → 处置
├── examples/                         文档命令引用的样例文件（照抄命令就能跑）
│   ├── draft.md  draft-v1.md  draft-v2.md
│   ├── a.md  b.md  reply.md
│   └── notes/comment-01.md  notes/comment-02.md
├── scripts/
│   ├── common.py                     数据加载、分句、角色判定、编码兜底
│   ├── hat_scan.py                   扫描器（帽子 / 句式 / 连招 / 否认降级）
│   ├── hat_generate.py               生成器（单条 + 连招，可复现）
│   ├── hat_diff.py                   改稿对比（可当门禁）
│   ├── corpus_check.py               回归语料门禁
│   ├── gate.py                       统一门禁入口（本地与 CI 共用同一套）
│   ├── doc_smoke.py                  文档即测试：把文档里的命令全跑一遍
│   ├── cli_smoke.py                  CLI 端到端冒烟（从 ci.yml 挪进来的）
│   ├── verify_data.py                一致性门禁（含版本同步）
│   ├── wordcount.py                  内容量门禁
│   ├── package.py                    打包 + 产物自检（解压后验证，不验源目录）
│   ├── release_notes.py              从 CHANGELOG 抽发版说明
│   ├── install.sh                    安装（Linux/macOS/WSL）
│   └── install.ps1                   安装（Windows，Junction 支持开发态）
├── .github/workflows/
│   ├── ci.yml                        门禁 × py3.9/3.12/3.13
│   └── release.yml                   打 tag 发版：门禁 → 打包自检 → 装一遍 → 发布 → 回收复检
└── tests/test_koumaozi.py            门禁测试
```

## 核心模型

一顶帽子要生效，四件事缺一不可：

| 要素 | 说明 | 破法所在 |
|---|---|---|
| 触发条件 | 必须挂在一个可见的动作上 | **拆挂钩** |
| 投放动作 | 陈述 / 疑问 / 玩梗，越轻越难反制 | 识别句式 |
| 读者反应 | 帽子瞄准的是第三方，不是被扣的人 | 对围观者说话 |
| 退出路径 | 好帽子四向封死 | 判断是否值得回应 |

四要素里，**触发条件是唯一的战场**。帽子掉了挂钩就是一句空话；挂钩在，说什么都是自证。

## 八族与二十四式

八族：立场叛徒、智力贬损、动机污染、身份污名、群体威胁、专业越界、道德审判、时间政治。

二十四式里，只有 `PAT-02`（动机归因）、`PAT-17`（语用预设）、`PAT-18`（沉默即认罪）是真正四向封死的。遇到这三式，不要讲理——对围观者拆结构，或者走。

单式好拆，连招难拆：**拆掉一环，其余环仍在生效**。所以十条连招单独计分，`seal_degree >= 3` 直接判 Critical。连招破了三环全拆的念头，只拆最脆的一环——要求对方提供具体信息的那一环。

## 评分怎么读

`label_score` 0-100，对数压缩后的标签化程度。短文本按至少 1000 字估算密度，避免"38 字里两处攻击＝满分"的假象。

| 分档 | 含义 |
|---|---|
| 0 | 未见标签化 |
| 1-24 | 轻度：论证仍在 |
| 25-59 | 中度：攻击句式已替代部分反驳 |
| 60-100 | 重度：论证基本让位于定性 |

分数用来**定位**，不用来定性。一段讽刺文打 70 分可能是好文章，一篇论文打 5 分也可能有一句要命的动机归因。

## 配合 anti-ai-flavor

生成端产出必须先过 [anti-ai-flavor](https://github.com/bfxh) 的文本维度：

```
hat_generate.py → 手改（砍一半 / 换口语 / 加毛刺）→ anti-ai-flavor → 再手改 → 交付
```

AI 写的帽子 100% 有 AI 味，因为它倾向于把攻击写得"完整"——而完整的攻击是不成立的。详见 `references/generation-playbook.md` 的"去 AI 味"一节。

实测记录：本仓库 7 份文档过 `detect_text_ai.py`，`TEXT-006`（信息空洞）与 `TEXT-007`（重复赘述）的命中全部来自表格分隔线、目录树、清单项和重复出现的 CLI 命令——这是脚本对 markdown 结构的系统性误报。它抓得准的是 `TEXT-001`（套话开头）和 `TEXT-005`（AI 常用短语）。**工具告警要人工过滤，不然改的是噪音。**

## 四条红线

1. **不对真实个人**。目标是立场、行为、群体倾向，不是姓名。
2. **不做群体仇恨**。不把民族、地域、宗教、性别、残障、疾病当作帽子本身。
3. **不涉未成年人**。
4. **不伪造证据**。`PAT-23` 伪统计是识别对象，不是生成作业。

生成器内置上述约束的说明，违反时拒绝执行。

## 质量门禁

八道门禁定义在 `scripts/gate.py` **一处**，本地和 CI 跑同一套：

```bash
python3 scripts/gate.py              # 全量，一次跑完再看结论
python3 scripts/gate.py --tier core  # 只跑核心（换 Python 版本时够用，约 6s）
python3 scripts/gate.py --list       # 有哪些门禁
python3 scripts/gate.py --explain    # 每道挡什么、失败了先看哪
python3 scripts/gate.py --only data,corpus
```

| key | 门禁 | 挡什么 |
|---|---|---|
| `compile` | 语法编译 | 脚本有语法错误 |
| `data` | 数据一致性 | schema、家族覆盖、别名冲突、模板槽位、文档引用的编号真实存在、版本号三处一致 |
| `words` | 内容量 | 文档被大段删改后规模缩水（门槛一万字） |
| `corpus` | 回归语料 | 漏检、误报、降级失效、句式/连招/家族覆盖出现空洞 |
| `unit` | 单元测试 | 扫描器正反例、连招检测、生成器可复现、diff 方向、性能（防正则回溯爆炸）、`install --check` 两平台的版本比较与完整性核对 |
| `docs` | 文档命令 | 文档里的命令示例照抄能不能跑 |
| `cli` | CLI 冒烟 | 四个命令的端到端形状：扫描有命中、连招三段结构、改稿门禁能拦恶化 |
| `package` | 产物 | 发出去的包齐不齐、能不能跑（解压后验证） |

**为什么收进一个入口**：门禁散在 workflow 里有两个老问题——本地要自己记顺序，记错就得到假结果；CI 和本地各写一份，改了一边忘另一边，就出现"本地绿、CI 红"。现在 `ci.yml` / `release.yml` 只负责"在哪个 Python 版本上跑哪一层"，具体集合不再重复列举。有一条测试专门盯着这件事（`test_workflows_go_through_single_entry`），谁在 yml 里再抄一遍脚本名，CI 就红。

门禁失败时会直接告诉你三件事：输出了什么、**这道门禁挡的是什么**、先看哪里：

```
FAIL  回归语料  0.24s
      语料 55 条  |  正样本 38/39  负样本 8/8  语境样本 8/8
      × CRP-12 命中 0 处 < 下限 1
  挡的是: 该抓的没抓（漏检）、不该抓的抓了（误报）、降级逻辑失效
  先看:   用 --verbose 看每条的命中明细；改了正则先跑这一道
```

门禁的意义不在通过，在于挡住"看着像有内容"的改动：加一顶帽子必须补反制要点，改模板必须保证槽位有默认值，写文档引用编号必须真实存在，动正则必须过回归语料。

### 文档即测试

文档示例是唯一会被读者**逐字复制**的东西。脚本改名、参数改了、样例文件挪了位置，源码门禁一条都不会红，但读者照抄第一行就是 `No such file or directory`。**文档腐烂是静默的**，所以它得有自己的门禁。

`doc_smoke.py` 抽出所有围栏代码块里以 `python3 scripts/` 开头的命令（支持 `\` 续行、行尾注释、glob），换成当前解释器真跑，并额外断言 `--json` 的输出真是 JSON。

它上线第一次就抓到一个真问题：`hat_diff.py --after draft-v2.md`（文件不存在）**没有报错**——`load_source` 把不存在的路径当成正文分析了。读者会以为对比了两个文件，拿到一个看着正常、实际在对比字符串 `"draft-v2.md"` 的结果。修法是加一条启发式：带 `.md/.txt/.rst` 后缀或含路径分隔符却不存在，直接报错并提示改用 `--before-text`。

`examples/` 目录就是为了让这 29 条命令照抄能跑而存在的，它也一起打进发布包——**装了包再看 SKILL.md，例子还是能跑**。

**回归语料是这套门禁里最有用的一个**：39 条正样本保证"该抓的抓到"，8 条负样本保证"不该抓的别抓"。第一次跑就有 4 条正样本漏检（"这不是境外势力是什么""收了多少公关费""什么时候才肯停止""先去读两本书"），全部补了正则才通过——这就是语料的价值，它逼工具兑现承诺。

语料还兼一层职责：**数据覆盖**。每个句式、每条连招、每个家族都必须至少被一条语料或连招示例覆盖，且每家族至少命中 2 顶不同帽子。加一道覆盖门禁之后，立刻露出 8 项缺口（PAT-04/06/16/19 完全无覆盖、moral-verdict 与 temporal-politics 各只有 1 条）——又补了 9 条语料，把 24 式从「仅示例覆盖」推到「全部有独立语料」。**没有被语料碰过的句式，等于没有被验证过。**

### 第三类样本：语境

正负样本之外还有 8 条 `kind: "context"`。它们字面上有帽子（"我没有收钱""他说我是公知""论文里把这类攻击称作扣帽子"），断言的是**零有效命中**：

```json
{ "kind": "context", "text": "我没有收钱，也没有替谁站台，这套说法省省。",
  "expect": { "max_hits": 0, "min_raw": 1, "downgraded": ["HAT-F3-02"], "score_band": [0, 0] } }
```

三个字段缺一不可：`min_raw` 保证词形真的触发过（否则它退化成一条普通负样本），`downgraded` 指名必须是**那一顶**被降级（而不是恰好别的帽子没命中），`max_hits: 0` 才是结论。

**干净负样本证明不了降级逻辑**——那些文本压根没触发词形，`context_role` 从头到尾没执行过。写这批样本时立刻撞出两个真实误报：「把对手**说成**水军」「同事**质疑**对方收钱」被算成本人在扣帽子。前者结构上无法与正样本「别把红利说成本事」区分（都是"把 X 说成 Y"），属于词面检测的边界，记在 SKILL.md 里不修；后者是转述他人指控，补进 `META_PREFIXES` 才算解决。

代价是「我质疑你收钱」也会降一级。接受这个代价：把怀疑说成怀疑，本来就比直接定性弱。

## 发版

推 `v*` tag 触发 `.github/workflows/release.yml`，顺序是：

1. **tag 与 `VERSION` 必须一致**——版本号在 `VERSION` 一处定义，`SKILL.md` 的 frontmatter 与 `CHANGELOG.md` 最新段由 `verify_data.py` 校验同步，任何一处漂了就发不出去。
2. **全量门禁重跑一遍**。打 tag 不等于推 main，那个 commit 很可能从没被 `ci.yml` 验过。
3. **打包 + 产物自检**：`package.py --verify` 解压到干净临时目录，按包内 `MANIFEST.sha256` 校验每个文件，再在**解压后**的目录里跑数据门禁、语料门禁、扫描、生成、改稿对比。
4. **安装脚本端到端**：真跑一次 `install.sh` 装到临时 HOME，再用装好的路径扫一次。
5. **建 Release**，附 `koumaozi-<version>.zip` 与 `.sha256`，说明从 `CHANGELOG.md` 抽（`release_notes.py`），抽不到就不发。
6. **发布后回收复检**：把刚上传的资产下载回来，和本地验过的那份比 sha256。

第 3、6 步是这套 CD 的全部意义。**只验源码目录是假 CD**——少打一个 `data/` 文件照样一路绿，用户装上去当场报错。所以验证对象永远是"解压出来的那一份"和"从 Release 下载回来的那一份"，不是工作区。

本地复现：

```bash
python3 scripts/package.py --verify         # 打包并自检
python3 scripts/package.py --verify dist/koumaozi-*.zip     # 只验已有包
python3 scripts/package.py --check-dir      # 核对当前目录（源码态会说跳过）
python3 scripts/release_notes.py            # 看这一版会发什么说明
```

## License

MIT
