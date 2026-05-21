#include "mnemonic/bip39_wordlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIP39_WORD_COUNT 2048

// ── 各语言嵌入词表 (extern 声明, 定义在 bip39_data_XX.c) ──

extern const char *bip39_words_en[2048];
extern const char *bip39_words_zh_hans[2048];
extern const char *bip39_words_zh_hant[2048];
extern const char *bip39_words_ja[2048];
extern const char *bip39_words_ko[2048];
extern const char *bip39_words_es[2048];
extern const char *bip39_words_fr[2048];
extern const char *bip39_words_it[2048];
extern const char *bip39_words_cs[2048];
extern const char *bip39_words_pt[2048];

// ── 语言名称映射 ──

static const char *lang_names[] =
{
  [LANG_EN]   = "en",
  [LANG_ZH_S] = "zh-hans",
  [LANG_ZH_T] = "zh-hant",
  [LANG_JP]   = "ja",
  [LANG_KR]   = "ko",
  [LANG_ES]   = "es",
  [LANG_FR]   = "fr",
  [LANG_IT]   = "it",
  [LANG_CZ]   = "cs",
  [LANG_PT]   = "pt",
};

static const char *lang_seps[] =
{
  [LANG_EN]   = " ",
  [LANG_ZH_S] = "",
  [LANG_ZH_T] = "",
  [LANG_JP]   = "\xe3\x80\x80",  // U+3000 全角空格 UTF-8
  [LANG_KR]   = " ",
  [LANG_ES]   = " ",
  [LANG_FR]   = " ",
  [LANG_IT]   = " ",
  [LANG_CZ]   = " ",
  [LANG_PT]   = " ",
};

const char* bip39_language_name (bip39_language_t lang)
{
  if (lang >= LANG_COUNT) return "??";
  return lang_names[lang];
}

const char* bip39_language_separator (bip39_language_t lang)
{
  if (lang >= LANG_COUNT) return " ";
  return lang_seps[lang];
}

// ── 嵌入词表查找 ──

static const char** bip39_embedded_lookup (const char *lang_code)
{
  if (strcmp (lang_code, "en")       == 0) return bip39_words_en;
  if (strcmp (lang_code, "zh-hans") == 0) return bip39_words_zh_hans;
  if (strcmp (lang_code, "zh-hant") == 0) return bip39_words_zh_hant;
  if (strcmp (lang_code, "ja")      == 0) return bip39_words_ja;
  if (strcmp (lang_code, "ko")      == 0) return bip39_words_ko;
  if (strcmp (lang_code, "es")      == 0) return bip39_words_es;
  if (strcmp (lang_code, "fr")      == 0) return bip39_words_fr;
  if (strcmp (lang_code, "it")      == 0) return bip39_words_it;
  if (strcmp (lang_code, "cs")      == 0) return bip39_words_cs;
  if (strcmp (lang_code, "pt")      == 0) return bip39_words_pt;
  return NULL;
}

// ── Trie 操作 ──

static trie_node_t* trie_node_alloc (void)
{
  trie_node_t *node = (trie_node_t *) calloc (1, sizeof (trie_node_t));
  if (node == NULL) return NULL;

  node->index   = 0xFFFF;
  node->is_leaf = false;

  return node;
}

static void trie_insert (trie_node_t *root, const char *word, uint16_t index)
{
  trie_node_t *cur = root;

  for (const uint8_t *p = (const uint8_t *) word; *p != '\0'; p++)
  {
    if (cur->children[*p] == NULL)
    {
      cur->children[*p] = trie_node_alloc ();
    }
    cur = cur->children[*p];
  }

  cur->index   = index;
  cur->is_leaf = true;
}

static uint16_t trie_lookup (trie_node_t *root, const char *word)
{
  trie_node_t *cur = root;

  for (const uint8_t *p = (const uint8_t *) word; *p != '\0'; p++)
  {
    if (cur->children[*p] == NULL) return 0xFFFF;

    cur = cur->children[*p];
  }

  if (cur->is_leaf == false) return 0xFFFF;

  return cur->index;
}

static void trie_destroy (trie_node_t *node)
{
  if (node == NULL) return;

  for (int i = 0; i < 256; i++)
  {
    trie_destroy (node->children[i]);
  }

  free (node);
}

// ── 词表初始化（仅嵌入数据）──

int bip39_wordlist_init (bip39_wordlist_t *list, bip39_language_t lang)
{
  if (list == NULL || lang >= LANG_COUNT) return -1;

  memset (list, 0, sizeof (bip39_wordlist_t));

  list->lang      = lang;
  list->separator = lang_seps[lang];

  const char *code = lang_names[lang];
  const char **words = bip39_embedded_lookup (code);

  if (words == NULL)
  {
    fprintf (stderr, "bip39_wordlist: language '%s' not embedded at compile time\n", code);
    return -1;
  }

  list->trie_root = trie_node_alloc ();
  if (list->trie_root == NULL) return -1;

  for (int i = 0; i < BIP39_WORD_COUNT; i++)
  {
    const char *word = words[i];
    size_t      len  = strlen (word);

    bip39_word_t *w = &list->words[i];
    w->index    = (uint16_t) i;
    w->word_len = (uint8_t) len;
    snprintf (w->word, sizeof (w->word), "%s", word);

    w->is_ascii = true;
    for (size_t j = 0; j < len; j++)
    {
      if ((uint8_t) word[j] > 0x7F) { w->is_ascii = false; break; }
    }

    trie_insert (list->trie_root, word, (uint16_t) i);
  }

  return 0;
}

void bip39_wordlist_destroy (bip39_wordlist_t *list)
{
  if (list == NULL) return;

  trie_destroy (list->trie_root);
  list->trie_root = NULL;

  memset (list, 0, sizeof (bip39_wordlist_t));
}

uint16_t bip39_wordlist_lookup_idx (bip39_wordlist_t *list, const char *word)
{
  if (list == NULL || word == NULL) return 0xFFFF;

  return trie_lookup (list->trie_root, word);
}

const char* bip39_wordlist_lookup_word (bip39_wordlist_t *list, uint16_t index)
{
  if (list == NULL || index >= BIP39_WORD_COUNT) return NULL;

  return list->words[index].word;
}
