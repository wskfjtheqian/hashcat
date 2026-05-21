#ifndef MNEMONIC_TYPES_H
#define MNEMONIC_TYPES_H

#include <stdint.h>
#include <stdbool.h>

// BIP39 语言枚举
typedef enum
{
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
  LANG_COUNT
} bip39_language_t;

// 地址类型枚举
typedef enum
{
  ADDR_ETH,             // 0x + 40 hex → 20 bytes
  ADDR_BTC_P2PKH,       // 1... Base58Check → 20 bytes
  ADDR_BTC_P2SH_P2WPKH, // 3... Base58Check → 20 bytes
  ADDR_BTC_P2WPKH,      // bc1q... Bech32 → 20 bytes
  ADDR_TRON,            // T... Base58Check → 20 bytes
  ADDR_DOGE,            // D... Base58Check → 20 bytes
  ADDR_UNKNOWN
} address_type_t;

// BIP39 单词条目
typedef struct
{
  uint16_t index;        // BIP39 索引 (0-2047)
  char     word[16];     // 单词 (UTF-8)
  uint8_t  word_len;     // 字节长度
  bool     is_ascii;     // 是否纯 ASCII
} bip39_word_t;

// Trie 节点
typedef struct trie_node
{
  struct trie_node *children[256];  // UTF-8 字节索引
  uint16_t          index;          // BIP39 索引 (0xFFFF = 非叶子)
  bool              is_leaf;
} trie_node_t;

// 语言词表
typedef struct
{
  bip39_language_t lang;
  bip39_word_t     words[2048];
  trie_node_t     *trie_root;
  const char      *separator;  // 单词分隔符
} bip39_wordlist_t;

// 单个位置的候选索引集
typedef struct
{
  uint16_t *indices;
  uint32_t  count;
  bool      is_exact;
} pos_candidates_t;

// 全部位置的候选
typedef struct
{
  uint32_t          word_count;  // 12 或 15
  bip39_language_t  language;
  pos_candidates_t  pos[15];
  uint64_t          total_combinations;
} mnemonic_candidates_t;

// 单个目标地址
typedef struct
{
  uint8_t raw[20];
} target_address_t;

// 多地址列表
typedef struct
{
  address_type_t    chain;
  uint32_t          coin_type;
  target_address_t *addrs;
  uint32_t          count;
  uint32_t          index_start;
  uint32_t          index_end;
} target_address_list_t;

// 排列迭代器
typedef struct
{
  mnemonic_candidates_t *candidates;

  uint64_t perm_idx;
  uint64_t comb_idx;
  uint64_t total_perms;
  uint64_t total_combs;
  uint64_t total_work;

  uint16_t *current_order;
  uint32_t *heap_c;
  uint16_t *comb_buf;

  uint16_t *output_buf;
  uint32_t  batch_size;
  uint32_t  batch_count;
} perm_iterator_t;

// GPU 通信批次
typedef struct
{
  uint16_t *h_indices;
  uint16_t *d_indices;
  uint32_t  batch_count;
  uint32_t  word_count;
  uint32_t  stride;

  uint8_t  *d_targets;
  uint32_t  target_count;
  uint32_t  coin_type;
  uint32_t  index_start;
  uint32_t  index_end;
} gpu_batch_t;

// 破解结果
typedef struct
{
  bool     found;
  uint64_t perm_index;
  uint32_t order[24];
  char     mnemonic[512];
  char     derived_address[128];
  uint32_t matched_index;
} crack_result_t;

#endif // MNEMONIC_TYPES_H
