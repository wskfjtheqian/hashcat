Add BTC recover  AI development task documents for hashcat project

# 助记词排列破解器 — AI 开发任务书（v3.0）

> **任务目标**：已知 1~N 个精确钱包地址，助记词部分已知（支持模糊匹配、多语言），但顺序未知。利用 CPU 做排序组合 + GPU 做密钥派生加速，找到能生成所有目标地址的正确助记词排列。
>
> **定位**：作为 hashcat 的扩展项目，复用 hashcat 的后端抽象、设备管理、事件系统等基础设施。
>
> **v3.0 新增**：多语言助记词 (10种语言) | 多地址匹配 (OR 逻辑, 任一命中) | 助记词模糊匹配强化

---

## 1. 问题分析

### 1.1 场景描述

用户拥有一个 BIP39 助记词钱包，但：

- **助记词顺序丢失**：知道单词但不知道排列顺序
- **部分单词记忆模糊**：只记得单词的部分内容（如前缀 `app*`、后缀 `*ple`、包含 `*ppl*`）
- **某些位置可能有多个候选**：如第三个位置可能是 `cat` 或 `cut` 或 `cot`
- **助记词长度确定**：12 词或 15 词（BIP39 标准）
- **可能不是英文助记词**：中文、日文、韩文、西班牙文等 BIP39 多语言助记词
- **用户可能拥有多个地址**：同一个助记词对应的 ETH 地址 + BTC 地址 + TRON 地址都已知

**目标**：在 GPU 加速下，找出唯一正确的助记词排列，使得派生地址与**其中任意一个**目标地址匹配即可。

### 1.2 核心思路：索引化 + CPU 排列 + GPU 计算

```
┌──────────────────────────────────────────────────────────────┐
│  输入：模糊词 / 候选词列表 + 语言选择                            │
│    ↓                                                         │
│  CPU: 模糊匹配 BIP39 词表(指定语言, 2048词) → 每个位置候选索引集合 │
│    ↓                                                         │
│  CPU: 索引排列组合 + BIP39 校验和过滤 → 有效候选索引序列(分批)    │
│    ↓                                                         │
│  一维数组传输： 扁平化的索引序列 → GPU                           │
│    ↓                                                         │
│  GPU: 索引→种子→密钥派生→公钥→多地址生成→多地址同时匹配           │
│    ↓                                                         │
│  结果回传                                                      │
└──────────────────────────────────────────────────────────────┘
```

### 1.3 搜索空间分析

**传统全排列（无模糊匹配）**：

| 词数 | 排列数 | 可行性 |
|------|--------|--------|
| 12 | 12! = 4.79×10⁸ | ✅ GPU 可行 |
| 15 | 15! = 1.31×10¹² | ⚠️ 困难 |

**模糊匹配场景（每个位置有 cᵢ 个候选）**：

搜索空间 = (每个位置的候选数之积) × (排列数)

**多地址 OR 逻辑**：只需匹配 N 个地址中的任意 1 个即算成功。GPU 端也是早停——第一个匹配就立即返回，无需检查后续地址。多地址增加了命中概率，但不增加单候选计算量（早停后跳过其余地址）。

**关键优化**：BIP39 校验和在 CPU 端快速过滤 93.75%（12词）无效排列，大幅减少传给 GPU 的数据量。

---

## 2. 技术背景

### 2.1 BIP39 词表结构（多语言）

BIP39 支持 **10 种语言**，每种语言有独立的 2048 词词表。每个单词仍对应 0–2047 的 11-bit 索引，但索引含义因语言而异：

| 语言 | BIP39 代码 | 词表示例 | 编码 | 分隔符 |
|------|-----------|---------|------|--------|
| English | `en` | abandon, zoo | ASCII | 空格 |
| 中文简体 | `zhs` | 的, 一, 爱 | UTF-8 | 无（直接连接） |
| 中文繁体 | `zht` | 的, 一, 愛 | UTF-8 | 无 |
| 日本語 | `jp` | あいこくしん, けさ | UTF-8 | 全角空格 `\u3000` |
| 한국어 | `kr` | 가드, 힘 | UTF-8 | 空格 |
| Español | `es` | ábaco, zurdo | UTF-8 | 空格 |
| Français | `fr` | abaisser, zodiaque | ASCII | 空格 |
| Italiano | `it` | abaco, zuppa | ASCII | 空格 |
| Čeština | `cz` | abdikace, život | UTF-8 | 空格 |
| Português | `pt` | abacate, zumbi | ASCII | 空格 |

索引化优势（跨语言一致）：
- 一个助记词只需 **2 字节（u16）** 存储，不随语言改变
- 12 词 = 24 字节；15 词 = 30 字节
- GPU 常量内存中的词查找表按语言切换（单次运行只用一种语言）

> ⚠️ **重要**：中文/日文助记词的单词拼接方式与英文不同。GPU 内核需根据语言代码选择分隔符（`" "`、`""`、`\u3000`）。

### 2.2 BIP39 种子派生（GPU 端计算）

```
助记词索引序列 [i₀, i₁, ..., i₁₁]
    │
    ▼ 查语言词表 LUT[lang][index] → 单词
    │ 按语言规则拼接（空格 / 无分隔 / 全角空格）
    ▼
助记词字符串
    │
    ▼
PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048 iterations)
    │
    ▼
种子 (64 bytes)
```

### 2.3 密钥派生与多地址生成（GPU 端）

多个目标地址为**同一种链类型**（如全部 ETH、或全部 BTC）。目标地址与 BIP44 address_index **无固定对应关系**——每个 index 派生的地址都可能命中任意一个目标地址：

```
种子 → BIP32 → BIP44(m/44'/c'/0'/0/i) → 子私钥 → secp256k1公钥
                                                    │
  对每个 i ∈ [index_start .. index_end]:              │
    链特定哈希 → addr_i                              │
    对每个 target ∈ 目标地址集合:                      │
      if addr_i == target:  ✅ 匹配！                 │
                                                    │
                   OR 逻辑：
      任一 (i, target) 配对成功 → 写入结果（早停）
```

> 默认 `index_start=0, index_end=0`，只检查常用 index=0。用户可指定 `--index-range 0-5`。
> 目标地址是地址集合，不关联 index。GPU 端对每个 index 派生地址后遍历所有 target。

各链 BIP44 路径：

| 链 | coin_type | 派生路径模板 | 地址格式 |
|----|-----------|-------------|---------|
| BTC | 0' | `m/44'/0'/0'/0/{i}` | Base58Check / Bech32 |
| ETH | 60' | `m/44'/60'/0'/0/{i}` | 0x + Keccak256(pubkey)[-20:] |
| TRON | 195' | `m/44'/195'/0'/0/{i}` | Base58Check (T 开头) |
| BSC | 60' | `m/44'/60'/0'/0/{i}` | 同 ETH |
| DOGE | 3' | `m/44'/3'/0'/0/{i}` | Base58Check |

### 2.4 地址逆向解码（CPU 端预处理）★

GPU 不浪费时间做 Base58/Bech32/hex 编解码。CPU 端将所有目标地址预解码为原始字节：

```
ETH: 0xAb5801a7D398...  → hex解码 → 20 字节 → GPU 常量内存
BTC: 1A1zP1eP5QGe...    → Base58Check解码 → 20 字节 → GPU 常量内存
TRON: TUEZSdKsoDH...    → Base58Check解码 → 20 字节 → GPU 常量内存
```

**每种链的 CPU 预处理**：

| 链 | CPU 预处理 | 结果 | GPU 端比较 |
|----|-----------|------|-----------|
| ETH | hex→20B | 20 字节 | memcmp 20B |
| BTC P2PKH | Base58Check→20B | 20 字节 (pubkey hash) | memcmp 20B |
| BTC P2WPKH | Bech32→20B | 20 字节 | memcmp 20B |
| TRON | Base58Check→20B | 20 字节 | memcmp 20B |

**多地址结构**：所有解码后的目标地址放入 GPU 常量内存，内核依次匹配，任一匹配立即返回（OR 早停）。

---

## 3. 助记词模糊匹配系统

### 3.1 匹配语法

用户在配置文件中为每个位置指定模式：

```
位置1: app*        → 匹配以 "app" 开头的所有 BIP39 单词（当前语言）
位置2: *ple        → 匹配以 "ple" 结尾的所有 BIP39 单词
位置3: *ppl*       → 匹配包含 "ppl" 的所有 BIP39 单词
位置4: apple       → 精确匹配 "apple"（唯一候选）
位置5: apple,apply → 手动列举多个候选
位置6: *           → 匹配全部 2048 个单词（完全不确定）
位置7: 的*          → 中文模糊：匹配以"的"开头的词（如 的⼀爱）
```

规则：
- `*` 在开头 → 后缀匹配
- `*` 在结尾 → 前缀匹配
- `*` 在两端 → 包含匹配
- 无 `*` → 精确匹配
- 纯 `*` → 全部 2048 个候选
- 逗号分隔 → 手动候选列表
- 大小写不敏感（ASCII 语言）；中文/日文/韩文按 Unicode 字符匹配

### 3.2 匹配结果数据结构

```C
// BIP39 支持的语言枚举
typedef enum {
    LANG_EN,        // English
    LANG_ZH_S,      // 中文简体
    LANG_ZH_T,      // 中文繁体
    LANG_JP,        // 日本語
    LANG_KR,        // 한국어
    LANG_ES,        // Español
    LANG_FR,        // Français
    LANG_IT,        // Italiano
    LANG_CZ,        // Čeština
    LANG_PT,        // Português
} bip39_language_t;

// 每个位置的模糊匹配结果
typedef struct position_candidates_t {
    u16 *indices;         // 候选 BIP39 索引数组（u16 = 0..2047）
    u32 count;            // 候选数量
    bool is_exact;        // 是否精确匹配（count==1 且无通配符）
} position_candidates_t;

// 全部位置的候选
typedef struct mnemonic_candidates_t {
    u32 word_count;                        // 12 或 15
    bip39_language_t language;             // 助记词语言
    position_candidates_t positions[15];   // 每个位置的候选
    u64 total_combinations;                // ∏ count[i]，用于预估
} mnemonic_candidates_t;
```

### 3.3 BIP39 词表前缀树（Trie）加速匹配

为高效支持 `*` 模糊匹配，在 CPU 端按需构建**当前语言**的 BIP39 词表前缀树：

```
Root
├── a → b → a → n → d → o → n → {index=0}   (English: abandon)
├── b → ...
├── z → ... → z → o → o → {index=2047}
│
├── 的 → ⼀ → 爱 → ...   (中文简体：BIP39 中文词表 Trie)
└── あ → い → こ → ...  (日文)
```

- 前缀匹配 `app*`：沿 Trie 走到 `app` 节点，收集所有子孙叶子
- 后缀匹配 `*ple`：遍历所有叶子，反向比较
- 包含匹配 `*ppl*`：遍历所有单词，检查子串
- 每种语言独立构建 Trie，按用户指定语言加载

由于词表仅 2048 个单词，构建 Trie 在毫秒级完成。

---

## 4. 架构设计：CPU + GPU 流水线

### 4.1 总体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    hashcat 扩展入口                           │
│              hashcat -m 99999 --mnemonic-crack ...           │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Phase 1: CPU — 语言选择 + 模糊匹配 + 地址预处理                │
│                                                              │
│  --language en|zhs|jp|...  →  加载对应 BIP39 词表 + Trie      │
│  输入文件(.mnem)   →   解析每个位置的模糊模式                   │
│       ↓                                                     │
│  语言 Trie 匹配 → 每个位置 → candidate indices[]              │
│       ↓                                                     │
│  地址文件(.addr) → 每行一个同链地址（不关联 index）→ Base58/hex解码  │
│                → target_addresses[] (1~N 个, 纯地址集合)         │
│  --index-range 0-4 → index_start=0, index_end=4                 │
│       ↓                                                     │
│  统计 total_combinations，评估可行性                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Phase 2: CPU — 分批排列 & 校验和过滤                          │
│                                                              │
│  排列引擎（迭代式）:                                           │
│    for each permutation of positions:                        │
│      for each combination of candidates:                    │
│        生成索引序列 [i₀, i₁, ..., i₁₁]                        │
│        SHA256(entropy) → 校验和验证                           │
│        if 通过: 写入 batch_buffer[]                           │
│                                                              │
│  批大小控制： 每批 50,000 ~ 500,000 条（可配置，控制内存）       │
│  双缓冲： 一个 buffer 填满后提交 GPU，同时填充另一个             │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │   一维数组 (u16[])                │
          │   [i₀,i₁,...,i₁₁, i₀,i₁,...]   │
          │   每 12/15 个 u16 = 一条候选      │
          │   扁平化，无结构体开销             │
          └────────────────┬────────────────┘
                           │  PCIe 传输
┌──────────────────────────▼──────────────────────────────────┐
│  Phase 3: GPU — PBKDF2 + 密钥派生 + 同链多index地址生成 + OR匹配    │
│                                                              │
│  常量内存:                                                     │
│    - 语言词查找表 LUT (2048 × ~8字符)                          │
│    - 目标地址数组 target[0..N-1] (每个 20B, 同一链类型)         │
│    - 各地址的 BIP44 address_index                              │
│    - 链类型 coin_type (全局统一)                                │
│                                                              │
│  GPU 线程 (每条候选):                                          │
│    索引→单词→PBKDF2→种子→BIP32→BIP44→secp256k1→               │
│    for i in index_start..index_end:                          │
│      CKDpriv(index=i) → 同链哈希 → addr_i                    │
│      for j in 0..N-1:                                       │
│        if memcmp(addr_i, target[j]): 原子写结果; 早停返回       │
│    (全部不匹配 → 继续下一个候选)                                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Phase 4: CPU — 结果处理                                      │
│  从 GPU 读取匹配结果 → 还原助记词 → 显示/保存所有匹配地址        │
│  如果未找到 → 生成下一批                                       │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 作为 hashcat 项目的集成方式

```
hashcat/
├── src/modules/
│   └── module_99999.c          # 助记词破解模块 (special hash-mode)
├── src/
│   ├── mnemonic_permute.c      # 排列引擎（CPU 端核心）
│   ├── mnemonic_fuzzy.c        # 模糊匹配 & 多语言 Trie
│   ├── mnemonic_address.c      # 地址逆向解码
│   └── mnemonic_kernel.c       # GPU 内核管理
├── include/
│   ├── mnemonic_permute.h
│   ├── mnemonic_fuzzy.h
│   └── mnemonic_address.h
├── OpenCL/
│   └── m09999_a0-optimized.cl  # GPU 内核
├── data/
│   ├── bip39_en.txt            # BIP39 英文词表
│   ├── bip39_zhs.txt           # BIP39 中文简体词表
│   ├── bip39_jp.txt            # BIP39 日文词表
│   └── ...                     # 其他 7 种语言词表
├── ai/
│   ├── PROJECT_OVERVIEW.md
│   └── MNEMONIC_PERMUTATION_CRACKER.md
└── docs/
    └── hashcat-mnemonic-crack.md
```

### 4.3 排列引擎设计（CPU 迭代器模式）

```C
typedef struct perm_iterator_t {
    // 输入
    position_candidates_t positions[15];
    u32 word_count;                      // 12 或 15

    // 迭代状态
    u64 current_perm_index;
    u64 current_comb_index;
    u64 total_perms;                     // word_count!
    u64 total_combs;                     // ∏ positions[i].count

    // 输出缓冲
    u16 *output_buf;                     // 一维数组
    u32 batch_size;
    u32 batch_count;
} perm_iterator_t;

int  perm_iterator_init   (perm_iterator_t *it, mnemonic_candidates_t *mc, u32 batch_size);
int  perm_iterator_next   (perm_iterator_t *it);   // 填充下一批，返回条数
void perm_iterator_destroy(perm_iterator_t *it);
```

**分批策略**（控制内存）：
- 默认 `batch_size = 100,000`：每批约 100K 条候选
- 12 词：每批 = 100,000 × 12 × 2B = **2.4 MB**
- 15 词：每批 = 100,000 × 15 × 2B = **3.0 MB**
- 双缓冲：2 × 3 MB = 6 MB（CPU 端占用极小）

**排列生成算法**：Heap 算法（迭代版，O(1) 空间）

### 4.4 一维数组传输格式

```
GPU 接收的一维数组布局 (u16[]):

[ idx₀₀, ..., idx₀₁₁,  |  idx₁₀, ..., idx₁₁₁,  |  ... ]
  ←— 候选0 (12个u16) —→   ←— 候选1 (12个u16) —→

步长 = word_count (12 或 15)
总大小 = batch_count × word_count × sizeof(u16)
```

---

## 5. GPU 内核设计

### 5.1 内核流水线（多地址版）

```
GPU Kernel (单线程处理单候选):

输入: 索引序列 (12 个 u16, 来自全局内存一维数组)

1. 索引 → 单词 (查常量内存 LUT[lang][index])
   → 按语言规则拼接 → 助记词字符串 (栈上)
        │
2. PBKDF2-HMAC-SHA512 (2048轮) → seed[64]
        │
3. BIP32 主密钥: HMAC-SHA512("Bitcoin seed", seed)
   → master_k[32], master_cc[32]
        │
4. BIP44 hardened CKD: m/44'/coin_type'/0'/0/0
        │
5. secp256k1: pubkey = privkey × G
        │
6. 多地址匹配 (同链, 目标地址无 index 对应):
   pubkey → 链特定哈希模板
   ┌────────────────────────────────────────┐
   │ for i in index_start .. index_end:      │
   │   CKDpriv(index=i) → 链哈希 → addr_i   │
   │   for j in 0..N-1:                     │
   │     if memcmp(addr_i, target[j]):      │
   │       atomic_write(result); return      │← 匹配！
   ├────────────────────────────────────────┤
   │ (全部 (i,j) 不匹配 → 自然结束)           │
   └────────────────────────────────────────┘
```

### 5.2 不需要做的（已在 CPU 端完成）

| 操作 | 在哪做 | 原因 |
|------|--------|------|
| Base58/Bech32 编码 | ❌ 不做 | CPU 端已逆向解码地址 |
| Hex 编码 (ETH) | ❌ 不做 | CPU 端已 hex→bytes |
| 校验和验证 | ❌ GPU 不做 | CPU 端已过滤 |
| 排列生成 | ❌ GPU 不做 | CPU 端迭代器完成 |
| 地址模糊匹配 | ❌ 不做 | 地址统一为精确匹配 |

GPU 只做：**PBKDF2 + 椭圆曲线 + 单一链哈希 + index 范围循环 × target 集合 memcmp + OR 早停**。

### 5.3 优化策略

1. **常量内存使用**（多语言适配）：
   - 当前语言词查找表（2048 × ~8 字符 ≈ 16KB，64KB 限制内 OK）
   - 目标地址数组（最多 N×20B，建议 N≤32）
   - BIP44 路径预计算值
   - secp256k1 基点 G 预计算表（窗口法）

2. **早停优化**（多地址 OR 逻辑）：
   - 一旦任一地址匹配即返回成功
   - 建议把最可能匹配的链放在前面（如用户最确定的那条链）
   - 最坏情况：全部不匹配时需检查所有地址

3. **指令级优化**：
   - secp256k1 endomorphism（lambda 分裂）：加速点乘 ~50%
   - 窗口法（w=5）：预计算 16 个点

4. **多 GPU**：每个 GPU 处理不同排列区间

---

## 6. 用户输入格式

### 6.1 助记词配置文件（`.mnem` 格式）

```
# wallet.mnem — 12词中文助记词，顺序未知

的                 # 位置0: 精确
一*                # 位置1: 以"一"开头
*爱                # 位置2: 以"爱"结尾
*国*               # 位置3: 包含"国"
人,民,大           # 位置4: 三选一
?                  # 位置5: 完全不确定 (2048候选)
学                 # 位置6: 精确
*                  # 位置7: 完全不确定 (同 ?)
中,华              # 位置8: 二选一
工*                # 位置9: 以"工"开头
*作                # 位置10: 以"作"结尾
家                 # 位置11: 精确
```

### 6.2 地址文件（`.addr` 格式，每行一个同链地址，不关联 index）

```
# eth_addrs.addr — 同一 ETH 钱包的多个地址（无 index 对应关系）

0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
0x71C7656EC7ab88b098defB751B7401B5f6d8976F
0xFE9Bf08c4bB625904Ed2Ef217bbd9e497A472D7A
```

```
# btc_addrs.addr — 同一 BTC 钱包的多个地址

1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX
```

> 所有地址必须是同一链类型。地址与 BIP44 index 无对应关系——每个 index 派生地址都会与所有目标地址比较。
> 链类型通过 CLI `--chain` 指定或在地址文件中自动检测。

### 6.3 CLI 接口

```
hashcat -m 99999 [选项] --mnemonic-file <file> --address-file <file>

专用选项：
  --mnemonic-file FILE    助记词配置文件（.mnem 格式）
  --address-file FILE     目标地址文件（每行一个同链地址）
  --chain CHAIN           链类型：eth, btc, tron, bsc, doge
  --index-range RANGE     派生 index 范围（默认 0-0，即只 index=0。如 0-5）
  --mnemonic-count N      助记词数量：12 或 15
  --language LANG         助记词语言：en, zhs, zht, jp, kr, es, fr, it, cz, pt
  --passphrase STR        BIP39 密码短语（默认 ""）
  --batch-size N          每批候选数（默认 100000）

通用 hashcat 选项：
  -d, --backend-devices   设备列表
  -D, --opencl-device-types
  -O, --optimized-kernel-enable
  -w, --workload-profile
  --restore               恢复会话
  --status                显示状态
  -o, --outfile           结果输出

示例：
  # ETH，index 范围 0-4，3 个目标地址（无 index 对应关系）
  hashcat -m 99999 --mnemonic-file wallet.mnem \
          --address-file eth_addrs.addr --chain eth \
          --index-range 0-4 --language en -d 0,1 -O

  # BTC，默认 index=0，单地址
  hashcat -m 99999 --mnemonic-file wallet.mnem \
          --address-file btc_addrs.addr --chain btc --language zhs -d 0
```

### 6.4 输出格式

```
================================================
✅ 助记词已恢复！(ETH) 匹配到 1 个地址 (index=2)

助记词 (en):
  apple banana cat dog sun truck abandon eagle fox grape juice zone

排列编号: 42,581,007

派生 index 范围: 0-4
目标地址 (3 个):
  [0] 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
  [1] 0x71C7656EC7ab88b098defB751B7401B5f6d8976F  ✅ 匹配！(index=2)
  [2] 0xFE9Bf08c4bB625904Ed2Ef217bbd9e497A472D7A

BIP39 种子 (hex): 5eb00bbddcf069084889a8ab91555681...
⚠️  请将助记词离线安全保存！
================================================
```

---

## 7. 地址预处理模块

### 7.1 地址格式 & 多地址结构（同链）

```C
typedef enum {
    ADDR_ETH,            // 0x + 40 hex → 20 bytes
    ADDR_BTC_P2PKH,      // 1... Base58Check → 20 bytes
    ADDR_BTC_P2SH_P2WPKH,// 3... Base58Check → 20 bytes
    ADDR_BTC_P2WPKH,     // bc1q... Bech32 → 20 bytes
    ADDR_TRON,           // T... Base58Check → 20 bytes
    ADDR_DOGE,           // D... Base58Check → 20 bytes
} address_type_t;

// 单个解码后的目标地址（纯地址，无 index 关联）
typedef struct {
    u8 raw[20];              // 原始字节
} target_address_t;

// 多地址列表（同一链）+ index 范围
typedef struct {
    address_type_t chain;    // 链类型（所有地址统一）
    u32 coin_type;           // BIP44 coin_type
    target_address_t *addrs;
    u32 count;
    u32 index_start;         // 派生 index 起始（默认 0）
    u32 index_end;           // 派生 index 结束（默认 0）
} target_address_list_t;
```

### 7.2 逆向解码函数

```C
// 单地址解码（不再需要 index 参数）
int address_decode_eth   (const char *addr_str, target_address_t *out);
int address_decode_btc   (const char *addr_str, target_address_t *out);
int address_decode_tron  (const char *addr_str, target_address_t *out);

// 自动检测类型
int address_decode_auto  (const char *addr_str, target_address_t *out);

// 解析地址文件，返回同链地址列表 + index 范围
int address_file_parse   (const char *filepath, u32 index_start, u32 index_end, target_address_list_t *out);
```

---

## 8. 数据结构总览

```C
// ========== BIP39 词表 & 多语言 ==========
typedef enum {
    LANG_EN, LANG_ZH_S, LANG_ZH_T, LANG_JP, LANG_KR,
    LANG_ES, LANG_FR, LANG_IT, LANG_CZ, LANG_PT,
} bip39_language_t;

typedef struct {
    u16 index;               // BIP39 索引 (0-2047)
    char word[16];           // 单词 (UTF-8)
    u8  word_len;            // 实际字节长度
    bool is_ascii;           // 是否纯 ASCII（决定分隔符）
} bip39_word_t;

typedef struct {
    bip39_language_t lang;
    bip39_word_t words[2048];
    trie_node_t *trie_root;  // 该语言的 Trie 根节点
    const char *separator;   // 拼接分隔符 (" ", "", "\u3000")
} bip39_wordlist_t;

// ========== 模糊匹配 ==========
typedef struct {
    u16 *indices;
    u32 count;
} pos_candidates_t;

typedef struct {
    u32 word_count;          // 12 或 15
    bip39_language_t language;
    pos_candidates_t pos[15];
    u64 total_combinations;
} mnemonic_candidates_t;

// ========== 多地址（同链，无 index 对应） ==========
typedef struct {
    u8  raw[20];              // 原始字节（解码后的地址）
} target_address_t;

typedef struct {
    u32 chain_type;           // 链类型：ADDR_ETH / ADDR_BTC_P2PKH / ...
    u32 coin_type;            // BIP44 coin_type (60=ETH, 0=BTC, ...)
    target_address_t *addrs;  // 地址数组（纯地址集合，不关联 index）
    u32 count;                // 地址数量 (1~N)
    u32 index_start;          // 派生 index 起始（默认 0）
    u32 index_end;            // 派生 index 结束（默认 0）
} target_address_list_t;

// ========== 排列引擎 ==========
typedef struct {
    mnemonic_candidates_t *candidates;
    u64 perm_idx, comb_idx;
    u64 total_perms, total_combs, total_work;
    u16 *current_order;
    u32 *heap_c;
    u16 *comb_buf;
    u16 *output_buf;
    u32 batch_size, batch_count;
} perm_iterator_t;

// ========== GPU 通信 ==========
typedef struct {
    u16 *h_indices, *d_indices;
    u32 batch_count, word_count, stride;
    u8  *d_targets;          // 所有目标地址（扁平: addr0[20B] + addr1[20B] + ...）
    u32  target_count;       // 目标地址数量 N
    u32  coin_type;          // 链的 BIP44 coin_type（全局统一）
    u32  index_start;        // 派生 index 起始
    u32  index_end;          // 派生 index 结束
} gpu_batch_t;
```

---

## 9. 实施路线图

### Phase 1：CPU 基础设施（1 周）
- [ ] 10 种语言 BIP39 词表加载 + 各自 Trie 构建
- [ ] 多语言模糊匹配引擎（前缀/后缀/包含/精确/手动列表）
- [ ] 地址逆向解码（ETH hex, BTC Base58Check, BTC Bech32, TRON Base58Check）
- [ ] 地址文件解析（纯地址集合）+ index 范围参数
- [ ] 排列迭代器（Heap 算法 + 候选组合 + 分批输出）
- [ ] BIP39 校验和验证（跨语言）
- [ ] 单元测试（多语言 BIP39 官方测试向量）

### Phase 2：CPU 端到端（1 周）
- [ ] PBKDF2-HMAC-SHA512（CPU 参考实现）
- [ ] BIP32/BIP44 密钥派生（CPU 参考实现，使用 libsecp256k1）
- [ ] 多链地址生成（CPU 参考实现）
- [ ] 同链 index 范围 × target 集合验证逻辑
- [ ] CPU 端完整流程集成测试

### Phase 3：GPU 内核（2-3 周）
- [ ] GPU HMAC-SHA512 + PBKDF2 (2048轮)
- [ ] GPU BIP32 主密钥 + BIP44 hardened CKD
- [ ] GPU secp256k1 点乘法（窗口法 + endomorphism）
- [ ] GPU Keccak256 + SHA256 + RIPEMD160
- [ ] GPU 多地址双层循环匹配（index 范围 × target 集合 + OR 早停）
- [ ] 多语言词表常量内存切换
- [ ] 与 CPU 参考实现交叉验证

### Phase 4：集成到 hashcat（1 周）
- [ ] 注册 `-m 99999` 模块
- [ ] 复用 hashcat backend 抽象
- [ ] CLI 参数集成（--language, --address-file）
- [ ] 状态/进度报告集成
- [ ] 多语言词表打包到 hashcat 数据目录

### Phase 5：优化与测试（1 周）
- [ ] Nsight/rocprof 性能分析
- [ ] 多 GPU 负载均衡
- [ ] OpenCL 移植（AMD GPU）
- [ ] 12 词中/英/日文实际场景测试
- [ ] 多地址 (1~5 个) 性能影响分析

---

## 10. 关键设计决策对照

| 方面 | v2.0 | v3.0 |
|------|------|------|
| 排列生成 | CPU Heap 算法 | ← 不变 |
| 助记词表示 | 索引 (u16) | ← 不变 + 语言标签 |
| 助记词语言 | 仅英文 | **10 种语言** |
| 模糊匹配 | 前缀/后缀/包含/手动 | ← 不变 + 多语言 |
| GPU 传输 | 一维 u16 数组 | ← 不变 |
| 地址比较 | CPU逆向解码, GPU memcmp | ← 不变 |
| 地址数量 | 仅 1 个 | **1~N 个（同链, 无 index 对应, OR）** |
| GPU 地址匹配 | 单次 memcmp | **index 范围循环 × target 集合循环 + OR 早停** |
| 词表 | 英文 2048 词 | **按语言加载对应词表** |
| 项目形式 | hashcat 扩展 | ← 不变 |

---

## 11. 依赖

| 库 | 用途 | 备注 |
|----|------|------|
| hashcat 基础设施 | 后端管理、事件、日志、CLI | 复用 |
| libsecp256k1 | CPU 端椭圆曲线参考验证 | MIT |
| OpenCL / CUDA SDK | GPU | 通过 hashcat backend |
| BIP39 多语言词表 | 10 种语言词表数据 | 来自 trezor/python-mnemonic |

> **不额外引入外部依赖**：GPU 端全部手写，CPU 端仅用 libsecp256k1 测试验证。

---

## 12. 安全性

1. **完全离线**：无网络通信
2. **内存安全**：找到结果后立即 `memset(0)` 清理 GPU/CPU 敏感缓冲区
3. **不在日志中记录完整助记词/私钥**
4. **开源 & 审计**：代码随 hashcat 开源

---

> **文档版本**: v3.0
> **创建日期**: 2025-07-15
> **更新日期**: 2025-07-15
> **状态**: 待实施

# hashcat 项目分析文档（面向 AI 辅助开发）

> **项目简介**：hashcat 是世界上最快、最先进的密码恢复工具，支持 300+ 种哈希算法，可在 CPU、GPU 及其他硬件加速器上运行。使用 C 语言编写（gnu99 标准），采用 MIT 许可证。

---

## 1. 项目整体架构

```
hashcat/
├── src/              # 核心 C 源码（约 130 个文件）
├── include/          # 头文件（约 78 个文件）
├── modules/          # 哈希模块（.so 共享库，约 350+ 个）
├── OpenCL/           # GPU 内核（.cl 文件，约 1500+ 个）
├── Rust/             # 下一代插件系统（Rust FFI）
│   ├── hashcat-sys/  # 底层 FFI 绑定
│   ├── bridges/      # 桥接插件（连接外部计算后端）
│   └── feeds/        # 馈送插件（连接外部候选生成器）
├── Python/           # Python 工具和原型
├── tools/            # 40+ 个实用脚本（哈希提取/转换/测试）
├── deps/             # 第三方依赖
├── docs/             # 文档（含插件开发指南）
├── rules/            # 规则文件
├── masks/            # 掩码攻击定义
├── charsets/         # 字符集文件
├── layouts/          # 键盘布局映射
├── tunings/          # 调优数据库
├── bridges/          # 桥接配置
├── feeds/            # 馈送配置
├── kernels/          # （空目录，曾用于存放编译后内核）
├── docker/           # Docker 构建配置
├── extra/            # 额外资源文件
└── AI/               # AI 辅助开发文档（本目录）
```

---

## 2. 核心入口与主循环

### 2.1 `src/main.c` — 程序入口

```C
int main (int argc, char **argv)  // 第 1338 行
```

执行流程：
1. `setup_console()` — 控制台设置
2. `hashcat_init(hashcat_ctx, event)` — 创建核心上下文
3. `user_options_init()` — 初始化用户选项
4. `user_options_getopt()` — 解析命令行参数
5. `user_options_postprocess()` — 参数后处理
6. `hashcat_session_init()` — 会话初始化（加载模块、检测设备等）
7. `hashcat_session_execute()` — 执行破解
8. 清理和退出

### 2.2 `src/hashcat.c` — 会话管理

核心函数调用链：

```
hashcat_session_init()
  → module_load()          # 加载指定哈希模块
  → backend_init()         # 初始化后端（CUDA/HIP/Metal/OpenCL）
  → backend_opencl_init()  # 发现计算设备
  → bridges_init()         # 初始化桥接
  → ...

hashcat_session_execute()
  → autodetect_hashmodes() # 自动检测哈希模式
  → selftest()             # 自检
  → autotune()             # 自动调优
  → outer_loop()           # 主破解循环
    → inner1_loop()
      → inner2_loop()
        → run_kernel()     # 在 GPU/CPU 上执行内核
```

### 2.3 事件驱动架构

所有日志、UI 更新、生命周期通知通过 `event()` 函数分发（`src/main.c:1265`）。事件类型定义在 `include/types.h` 的 `event_identifier_t` 枚举中（第 100-175 行），如：
- `EVENT_CRACKER_STARTING` / `EVENT_CRACKER_FINISHED` — 破解开始/结束
- `EVENT_CRACKER_HASH_CRACKED` — 哈希被破解
- `EVENT_MONITOR_STATUS_REFRESH` — 状态刷新
- `EVENT_SELFTEST_STARTING` / `EVENT_SELFTEST_FINISHED` — 自检
- 等等

---

## 3. 核心数据结构

### 3.1 全局上下文 `hashcat_ctx_t`（`include/types.h:3236-3272`）

这是贯穿整个程序的核心结构体，包含所有子系统的上下文指针：

| 字段 | 子系统 | 职责 |
|------|--------|------|
| `brain_ctx` | 分布式 | 分布式破解协调 |
| `bitmap_ctx` | 位图 | 布隆过滤器，快速哈希淘汰 |
| `bridge_ctx` | 桥接 | 桥接插件上下文 |
| `combinator_ctx` | 组合攻击 | 组合攻击状态 |
| `cpt_ctx` | 破解时间 | 破解时间统计 |
| `debugfile_ctx` | 调试 | 调试文件输出 |
| `dictstat_ctx` | 字典统计 | 字典缓存 |
| `event_ctx` | 事件 | 事件缓冲 |
| `folder_config` | 路径 | 安装/配置/缓存/会话目录 |
| `generic_ctx` | 通用插件 | 通用攻击模式插件 |
| `hashconfig` | 哈希配置 | 当前哈希模式配置 |
| `hashes` | 哈希列表 | 待破解的哈希 |
| `hwmon_ctx` | 硬件监控 | 温度/风扇/功耗监控 |
| `induct_ctx` | 归纳 | 字典归纳（循环） |
| `logfile_ctx` | 日志 | 日志文件 |
| `loopback_ctx` | 回环 | 回环字典 |
| `mask_ctx` | 掩码 | 掩码/BF 攻击状态 |
| `module_ctx` | 模块 | 动态加载的哈希模块 |
| `backend_ctx` | 后端 | 设备管理 |
| `outcheck_ctx` | 输出检查 | 输出目录检查 |
| `outfile_ctx` | 输出文件 | 破解结果输出 |
| `pidfile_ctx` | PID | PID 文件 |
| `potfile_ctx` | Potfile | 已破解哈希记录 |
| `restore_ctx` | 恢复 | 会话恢复 |
| `status_ctx` | 状态 | 运行时状态 |
| `straight_ctx` | 直连攻击 | 字典攻击状态 |
| `tuning_db` | 调优 | 设备调优数据库 |
| `user_options` | 用户选项 | 命令行参数 |
| `user_options_extra` | 额外选项 | 派生的用户选项 |
| `wl_data` | 字典数据 | 字典文件读写状态 |

### 3.2 设备参数 `hc_device_param_t`（`include/types.h:1264-1985`）

这是最复杂的结构体之一（~720 行），统一抽象了 CUDA、HIP、Metal、OpenCL 四种后端：

- **通用字段**：`device_id`、`device_name`、`device_processors`、`kernel_accel/loops/threads` 等
- **CUDA 特定**：`is_cuda`、`cuda_device`、`cuda_context`、`cuda_function*`、`cuda_d_*`（设备内存指针）
- **HIP 特定**：`is_hip`、`hip_device`、`hip_context`、`hip_function*`、`hip_d_*`
- **Metal 特定**：`is_metal`、`is_apple_silicon`、`metal_device`、`metal_function*`、`metal_d_*`
- **OpenCL 特定**：`is_opencl`、`opencl_device`、`opencl_kernel*`、`opencl_d_*`

### 3.3 哈希配置 `hashconfig_t`（`include/types.h:1123-1203`）

定义哈希模式的所有属性：`hash_mode`、`hash_name`、`dgst_size`、`opti_type`、`opts_type`、`pw_min/pw_max`、`salt_min/salt_max`、内核调优参数范围等。

### 3.4 模块接口 `module_ctx_t`（`include/types.h:3136-3234`）

动态加载的哈希模块导出的函数指针表，包含 60+ 个函数指针：
- 基础信息：`module_hash_name`、`module_hash_mode`、`module_hash_category`
- 参数配置：`module_pw_min/max`、`module_salt_min/max`、`module_kernel_accel/loops/threads_min/max`
- 编解码：`module_hash_encode`、`module_hash_decode`、`module_hash_encode_potfile` 等
- 调优与自检：`module_st_hash`、`module_st_pass`、`module_extra_tuningdb_block`
- 钩子：`module_hook12`、`module_hook23`
- JIT 编译：`module_jit_build_options`、`module_jit_cache_disable`
- 桥接：`module_bridge_type`、`module_bridge_name`

---

## 4. 攻击模式

定义在 `include/types.h` 的 `attack_mode_t` 枚举（第 266-280 行）：

| 模式 | 枚举值 | 说明 |
|------|--------|------|
| 0 | `ATTACK_MODE_STRAIGHT` | 字典攻击（Wordlist） |
| 1 | `ATTACK_MODE_COMBI` | 组合攻击（Combinator） |
| 3 | `ATTACK_MODE_BF` | 暴力破解/掩码攻击（Brute-Force/Mask） |
| 6 | `ATTACK_MODE_HYBRID1` | 混合攻击：字典+掩码 |
| 7 | `ATTACK_MODE_HYBRID2` | 混合攻击：掩码+字典 |
| 9 | `ATTACK_MODE_ASSOCIATION` | 关联攻击 |
| 10 | `ATTACK_MODE_GENERIC` | 通用插件攻击模式 |

内核级攻击类型 `attack_kern_t`（第 282-289 行）：
- `ATTACK_KERN_STRAIGHT` — 直连内核
- `ATTACK_KERN_COMBI` — 组合内核
- `ATTACK_KERN_BF` — 暴力破解内核（含掩码）

---

## 5. 后端抽象层

### 5.1 支持的硬件后端

| 后端 | 源文件 | 说明 |
|------|--------|------|
| OpenCL | `ext_OpenCL.c` | 跨平台 GPU/CPU 计算 |
| CUDA | `ext_cuda.c`、`ext_nvrtc.c` | NVIDIA GPU |
| HIP | `ext_hip.c`、`ext_hiprtc.c` | AMD GPU (ROCm) |
| Metal | `ext_metal.m` | Apple GPU |

### 5.2 硬件监控

| 后端 | 源文件 | 说明 |
|------|--------|------|
| NVML | `ext_nvml.c` | NVIDIA 管理库 |
| NVAPI | `ext_nvapi.c` | NVIDIA API |
| ADL | `ext_ADL.c` | AMD 显示库 |
| sysfs/amdgpu | `ext_sysfs_amdgpu.c` | AMD GPU sysfs |
| sysfs/intel | `ext_sysfs_intelgpu.c` | Intel GPU sysfs |
| sysfs/cpu | `ext_sysfs_cpu.c` | CPU sysfs |
| IOKit | `ext_iokit.m` | macOS IOKit |

---

## 6. 内核执行管道

内核分为多阶段执行，定义在 `kern_run_t` 枚举（`include/types.h:291-309`）：

```
KERN_RUN_1    → 第一阶段（amp/preprocess）
KERN_RUN_12   → 1→2 转换
KERN_RUN_2    → 第二阶段（主计算）
KERN_RUN_23   → 2→3 转换
KERN_RUN_3    → 第三阶段（后处理/比较）
KERN_RUN_4    → 第四阶段（附加比较）
KERN_RUN_INIT2 → 初始化第二阶段
KERN_RUN_LOOP2 → 循环第二阶段（迭代哈希）
KERN_RUN_AUX1~4 → 辅助内核
```

钩子函数 `HOOK12`/`HOOK23` 允许特定哈希模式在阶段之间插入自定义转换逻辑。

---

## 7. OpenCL 内核系统

### 7.1 命名约定

```
OpenCL/mXXXXX_aY-{optimized|pure}.cl
```

- `XXXXX` = 哈希模式编号
- `Y` = 攻击模式（0=straight, 1=combinator, 3=brute-force）
- `optimized` = 手工优化的内核变体
- `pure` = 参考/未优化变体

### 7.2 共享包含文件

| 类别 | 文件前缀 | 示例 |
|------|----------|------|
| 哈希函数 | `inc_hash_*.cl` | `inc_hash_md5.cl`、`inc_hash_sha1.cl`、`inc_hash_sha256.cl` 等 |
| 密码算法 | `inc_cipher_*.cl` | `inc_cipher_aes.cl`、`inc_cipher_des.cl`、`inc_cipher_serpent.cl` 等 |
| 磁盘加密 | `inc_luks_*.cl`、`inc_truecrypt_*.cl`、`inc_veracrypt_*.cl` | LUKS/TrueCrypt/VeraCrypt 相关 |
| 规则引擎 | `inc_rp.cl`、`inc_rp_optimized.cl` | GPU 端规则处理器 |
| 公共 | `inc_common.cl`、`inc_platform.cl`、`inc_simd.cl` | 公共宏和平台定义 |
| 比较 | `inc_comp_single.cl`、`inc_comp_multi.cl` | 单/多哈希比较逻辑 |
| 放大器 | `amp_a0.cl`、`amp_a1.cl`、`amp_a3.cl` | 词放大器内核 |

### 7.3 共享内核

- `shared.cl` — 所有内核间共享的 GPU 工具函数
- `markov_le.cl` / `markov_be.cl` — Markov 模型（小端/大端）

---

## 8. 模块系统

### 8.1 模块加载

- `src/dynloader.c` — 动态加载器，通过 `dlopen()/LoadLibrary()` 加载 `.so/.dll`
- 模块位于 `modules/` 目录
- 命名：`module_XXXXX.so`（XXXXX = 哈希模式编号）
- 每个模块导出 `MODULE_INIT` 函数指针来初始化 `module_ctx_t`
- 附带 `.su` 文件（自检校验和）

### 8.2 模块源文件位置

模块源码在 `src/modules/` 目录下，每个哈希模式有独立的 `.c` 源文件。

---

## 9. 关键子系统详解

### 9.1 位图（Bitmap）

- `src/bitmap.c` + `include/bitmap.h`
- 实现布隆过滤器，在 GPU 计算前快速排除不匹配的哈希
- 两层结构（s1/s2），每层 4 个 32 位数组（a/b/c/d）

### 9.2 规则引擎

- `src/rp.c` + `src/rp_cpu.c` + `OpenCL/inc_rp*.cl`
- 支持 80+ 种规则操作（定义在 `rule_functions_t` 枚举，`include/types.h:319-401`）
- 可在 CPU（`rp_cpu.c`）或 GPU（OpenCL 内核）上执行
- 支持规则文件、随机规则生成（`rp_gen`）

### 9.3 分布式破解（Brain）

- `src/brain.c` + `include/brain.h`
- 客户端-服务器模型，通过 TCP 协调多台机器
- 共享已破解密码，避免重复工作

### 9.4 字典统计（Dictstat）

- `src/dictstat.c` + `include/dictstat.h`
- 缓存字典文件元数据，加速重复运行

### 9.5 自动调优

- `src/autotune.c` — 运行时自动调优内核参数
- `src/tuningdb.c` — 调优数据库（预存设备-模式最佳参数）
- 对每个设备/哈希模式组合寻找最佳 `kernel_accel`、`kernel_loops`、`kernel_threads`

### 9.6 自检（Selftest）

- `src/selftest.c`
- 使用模块提供的 `module_st_hash` 和 `module_st_pass` 验证哈希计算正确性

---

## 10. 源文件速查表

### 10.1 核心流程

| 文件 | 职责 |
|------|------|
| `src/main.c` | 入口点、事件处理、日志、UI |
| `src/hashcat.c` | 会话生命周期管理 |
| `src/hashcat.h` | （`include/hashcat.h`）公共 API 头文件 |
| `src/dispatch.c` | 内核调度和工作分配 |
| `src/backend.c` | 后端设备管理 |
| `src/interface.c` | 命令行交互界面 |
| `src/user_options.c` | 命令行参数解析 |
| `src/usage.c` | 帮助信息生成 |

### 10.2 攻击模式

| 文件 | 攻击模式 |
|------|----------|
| `src/straight.c` | 字典攻击（模式 0） |
| `src/combinator.c` | 组合攻击（模式 1） |
| `src/mask.c` + `src/mpsp.c` | 掩码/Markov 攻击（模式 3） |
| `src/stdout.c` | 候选输出模式 |
| `src/slow_candidates.c` | 慢速候选模式 |

### 10.3 规则系统

| 文件 | 职责 |
|------|------|
| `src/rp.c` | 规则解析器和引擎核心 |
| `src/rp_cpu.c` | CPU 端规则执行 |
| `src/keyboard_layout.c` | 键盘布局映射 |

### 10.4 数据处理

| 文件 | 职责 |
|------|------|
| `src/hashes.c` | 哈希列表管理 |
| `src/hlfmt.c` | 哈希格式解析（pwdump/shadow/DCC 等） |
| `src/convert.c` | 编码转换（UTF-8/UTF-16/Base64 等） |
| `src/bitmap.c` | 布隆过滤器 |
| `src/shared.c` | 共享工具函数 |
| `src/common.c` | 通用帮助函数 |
| `src/memory.c` | 内存管理 |

### 10.5 文件 I/O

| 文件 | 职责 |
|------|------|
| `src/filehandling.c` | 文件打开/读/写（支持 gz/xz/unrar） |
| `src/folder.c` | 目录配置管理 |
| `src/potfile.c` | 破解结果持久化 |
| `src/outfile.c` | 结果输出 |
| `src/outfile_check.c` | 输出目录监控 |
| `src/logfile.c` | 日志记录 |
| `src/restore.c` | 会话恢复 |
| `src/pidfile.c` | PID 文件管理 |
| `src/wordlist.c` | 字典文件读取 |
| `src/dictstat.c` | 字典统计缓存 |
| `src/loopback.c` | 回环字典 |
| `src/induct.c` | 字典归纳/循环 |

### 10.6 后端

| 文件 | 后端 |
|------|------|
| `src/ext_OpenCL.c` | OpenCL 后端 |
| `src/ext_cuda.c` | CUDA 后端 |
| `src/ext_hip.c` | HIP/ROCm 后端 |
| `src/ext_metal.m` | Metal/Apple 后端 |
| `src/ext_nvrtc.c` | NVIDIA 运行时编译 |
| `src/ext_hiprtc.c` | HIP 运行时编译 |
| `src/ext_lzma.c` | LZMA 压缩支持 |

### 10.7 硬件监控

| 文件 | 职责 |
|------|------|
| `src/hwmon.c` | 硬件监控统一接口 |
| `src/ext_nvml.c` | NVIDIA 管理库 |
| `src/ext_nvapi.c` | NVIDIA API |
| `src/ext_ADL.c` | AMD 显示库 |
| `src/ext_sysfs_amdgpu.c` | AMD GPU sysfs |
| `src/ext_sysfs_intelgpu.c` | Intel GPU sysfs |
| `src/ext_sysfs_cpu.c` | CPU sysfs |
| `src/ext_iokit.m` | macOS IOKit |

### 10.8 模拟器（用于调试和纯 CPU 内核）

| 文件 | 职责 |
|------|------|
| `src/emu_general.c` | 通用模拟器基础设施 |
| `src/emu_inc_hash_*.c` | 各种哈希函数的 CPU 模拟实现 |
| `src/emu_inc_cipher_*.c` | 各种密码算法的 CPU 模拟实现 |
| `src/emu_inc_rp*.c` | 规则引擎的 CPU 模拟实现 |
| `src/emu_inc_simd.c` | SIMD 操作的 CPU 模拟 |
| `src/emu_inc_scalar.c` | 标量操作的 CPU 模拟 |
| `src/emu_inc_platform.c` | 平台抽象模拟 |
| `src/emu_inc_common.c` | 通用模拟 |

### 10.9 其他

| 文件 | 职责 |
|------|------|
| `src/affinity.c` | CPU 亲和性设置 |
| `src/autotune.c` | 内核自动调优 |
| `src/tuningdb.c` | 调优数据库 |
| `src/benchmark.c` | 基准测试 |
| `src/selftest.c` | 自检 |
| `src/brain.c` | 分布式破解客户端/服务器 |
| `src/bridges.c` | 桥接管理 |
| `src/cpt.c` | 破解时间统计 |
| `src/debugfile.c` | 调试文件 |
| `src/dynloader.c` | 动态库加载 |
| `src/event.c` | 事件系统 |
| `src/bitops.c` | 位操作工具 |
| `src/cpu_crc32.c` | CPU CRC32 |
| `src/cpu_features.c` | CPU 特性检测 |
| `src/generic.c` | 通用攻击模式插件 |
| `src/locking.c` | 线程锁 |
| `src/monitor.c` | 运行时监控（温度/性能） |
| `src/status.c` | 状态报告生成 |
| `src/terminal.c` | 终端交互 |
| `src/thread.c` | 线程管理 |
| `src/timer.c` | 计时器 |

---

## 11. 构建系统

- **主构建**：GNU `Makefile`（项目根目录）
- **子构建**：`src/Makefile`
- **支持平台**：macOS (`BUILD_macOS.md`)、Linux、Windows MSYS2 (`BUILD_MSYS2.md`)、Cygwin (`BUILD_CYGWIN.md`)、WSL (`BUILD_WSL.md`)、Android (`BUILD_Android.md`)、Docker (`BUILD_Docker.md`)
- **编译器要求**：GCC 或 Clang，`-std=gnu99`
- **第三方依赖**（均在 `deps/` 下）：LZMA-SDK、OpenCL-Headers、Argon2、scrypt-jane、xxHash、yescrypt、zlib、unrar、sse2neon

---

## 12. 扩展点

### 12.1 添加新哈希模式

1. 在 `src/modules/` 下创建 `module_XXXXX.c`
2. 实现 `MODULE_INIT` 函数，填充 `module_ctx_t` 各字段
3. 实现 `module_hash_encode/decode` 等必要函数
4. 创建 OpenCL 内核 `OpenCL/mXXXXX_a0-pure.cl`、`-optimized.cl`、`a1`、`a3` 变体
5. 更新 `src/Makefile` 添加编译目标
6. 参考文档：`docs/hashcat-plugin-development-guide.md`

### 12.2 添加桥接（Bridge）

- 桥接允许连接外部计算后端
- Rust 实现位于 `Rust/bridges/`
- 配置位于 `bridges/`
- C 端接口定义在 `src/bridges.c` 和 `include/bridges.h`
- 参考文档：`docs/hashcat-assimilation-bridge-development.md`

### 12.3 添加馈送（Feed）

- 馈送允许连接外部候选生成器
- Rust 实现位于 `Rust/feeds/`
- 配置位于 `feeds/`

### 12.4 Python 插件

- 通过 `Python/` 中的 `hcsp.py`（会话协议）和 `hcmp.py`（管理协议）
- 参考文档：`docs/hashcat-python-plugin-development-guide.md`

---

## 13. 代码风格约定

来自 `README.md` 的贡献指南：

1. MIT 许可证
2. 遵循 gnu99 标准
3. 使用 `-W -Wall -std=gnu99` 无警告编译
4. **Allman 风格**代码块和缩进
5. 使用 **2 空格**缩进（Makefile 中可用 Tab）
6. 小写函数名和变量名
7. 避免使用 `!`，使用正向条件（如 `if (foo == 0)` 而非 `if (!foo)`）
8. 使用 `array[index + 0]` 风格保持对齐

可使用 GNU Indent 自动格式化：
```sh
indent -st -bad -bap -sc -bl -bli0 -ncdw -nce -cli0 -cbi0 -pcs -cs -npsl -bs -nbc -bls -blf -lp -i2 -ts2 -nut -l1024 -nbbo -fca -lc1024 -fc1
```

---

## 14. 关键枚举速查

### 哈希类别（`hash_category_t`，`include/types.h:3330-3357`）

`RAW_HASH`, `RAW_HASH_SALTED`, `RAW_HASH_AUTHENTICATED`, `RAW_CHECKSUM`, `RAW_CIPHER_KPA`, `GENERIC_KDF`, `NETWORK_PROTOCOL`, `OS`, `DATABASE_SERVER`, `NETWORK_SERVER`, `EAS`, `FDE`, `DOCUMENTS`, `PASSWORD_MANAGER`, `ARCHIVE`, `FORUM_SOFTWARE`, `OTP`, `PLAIN`, `FRAMEWORK`, `PRIVATE_KEY`, `IMS`, `CRYPTOCURRENCY_WALLET`, `FBE`, `APPLICATION_DATABASE`

### 优化类型（`opti_type_t`，`include/types.h:412-441`）

`OPTIMIZED_KERNEL`, `ZERO_BYTE`, `PRECOMPUTE_INIT`, `MEET_IN_MIDDLE`, `EARLY_SKIP`, `NOT_SALTED`, `NOT_ITERATED`, `PREPENDED_SALT`, `APPENDED_SALT`, `SINGLE_HASH`, `SINGLE_SALT`, `BRUTE_FORCE`, `RAW_HASH`, `SLOW_HASH_SIMD_*`, `USES_BITS_*`, `REGISTER_LIMIT`

### 状态码（`status_rc_t`，`include/types.h:216-234`）

`STATUS_INIT` → `STATUS_AUTOTUNE` → `STATUS_SELFTEST` → `STATUS_RUNNING` → `STATUS_PAUSED` / `STATUS_EXHAUSTED` / `STATUS_CRACKED` / `STATUS_ABORTED` / `STATUS_QUIT` / `STATUS_BYPASS` / `STATUS_ERROR`

---

## 15. Rust 子系统概览

```
Rust/
├── hashcat-sys/    # -sys crate: C FFI 绑定
│   └── src/        # 绑定到 hashcat.h 的 C API
├── bridges/        # 桥接插件工作区成员
│   └── src/        # 桥接实现
└── feeds/          # 馈送插件工作区成员
    └── src/        # 馈送实现
```

Rust 桥接是 v7.x 引入的下一代扩展机制，允许用 Rust 编写高性能的扩展后端和候选生成器。

---

## 16. 快速导航（对 AI 最重要的文件）

调试和理解问题时，建议按以下优先级阅读：

1. **`include/types.h`** — 所有数据结构定义，理解项目的关键
2. **`src/main.c`** — 入口点和事件处理
3. **`src/hashcat.c`** — 会话生命周期
4. **`src/dispatch.c`** — 内核调度逻辑
5. **`src/backend.c`** — 设备后端管理
6. **`src/user_options.c`** — 命令行参数解析
7. **`src/hashes.c`** + **`src/hlfmt.c`** — 哈希解析
8. **`OpenCL/inc_common.cl`** + **`OpenCL/shared.cl`** — GPU 内核基础

---

> **最后更新**：2025-07-15
> **维护说明**：本文档随项目演进需要同步更新。当项目结构发生重大变化（如新增目录、重构模块系统、更新版本号等）时，请更新对应章节。
