#include "mnemonic/mnemonic_fuzzy.h"
#include "mnemonic/bip39_wordlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 256

// ── 解析单个位置的模式 ──
// 返回候选索引数组，调用者负责管理 mc->pos[slot]
static int parse_one_slot (pos_candidates_t *pos, bip39_wordlist_t *wl, const char *pattern)
{
  char pat[MAX_LINE];
  strncpy (pat, pattern, MAX_LINE - 1);
  pat[MAX_LINE - 1] = '\0';

  // 去除首尾空白
  char *s = pat;
  while (*s == ' ' || *s == '\t') s++;
  char *e = s + strlen (s) - 1;
  while (e > s && (*e == ' ' || *e == '\t')) { *e = '\0'; e--; }

  if (*s == '\0' || (*s == '?' && *(s + 1) == '\0'))
  {
    // 完全不确定：全部 2048 个候选
    pos->indices = (uint16_t *) malloc (2048 * sizeof (uint16_t));
    if (pos->indices == NULL) return -1;

    for (int i = 0; i < 2048; i++) pos->indices[i] = (uint16_t) i;

    pos->count    = 2048;
    pos->is_exact = false;

    return 0;
  }

  // 检查是否包含逗号（手动多个候选）
  if (strchr (s, ',') != NULL)
  {
    // 先数个数
    uint32_t cnt = 1;
    for (const char *p = s; *p; p++) if (*p == ',') cnt++;

    pos->indices = (uint16_t *) malloc (cnt * sizeof (uint16_t));
    if (pos->indices == NULL) return -1;

    pos->count = 0;

    char *token = strtok (s, ",");
    while (token != NULL)
    {
      // 去除 token 首尾空白
      while (*token == ' ') token++;
      char *te = token + strlen (token) - 1;
      while (te > token && *te == ' ') { *te = '\0'; te--; }

      uint16_t idx = bip39_wordlist_lookup_idx (wl, token);
      if (idx == 0xFFFF)
      {
        fprintf (stderr, "mnemonic_fuzzy: word '%s' not in wordlist\n", token);
        free (pos->indices);
        return -1;
      }

      pos->indices[pos->count++] = idx;
      token = strtok (NULL, ",");
    }

    pos->is_exact = (pos->count == 1);

    return 0;
  }

  // ── 通配符模式 ──
  bool has_prefix_star = (*s == '*');
  bool has_suffix_star = (s[strlen (s) - 1] == '*');

  if (has_prefix_star == false && has_suffix_star == false)
  {
    // 精确匹配
    uint16_t idx = bip39_wordlist_lookup_idx (wl, s);
    if (idx == 0xFFFF)
    {
      fprintf (stderr, "mnemonic_fuzzy: word '%s' not in wordlist\n", s);
      return -1;
    }

    pos->indices = (uint16_t *) malloc (sizeof (uint16_t));
    if (pos->indices == NULL) return -1;

    pos->indices[0] = idx;
    pos->count      = 1;
    pos->is_exact   = true;

    return 0;
  }

  // 提取匹配子串（去掉 *）
  char sub[MAX_LINE];
  if (has_prefix_star && has_suffix_star)
  {
    // *包含* → 提取中间部分
    size_t len = strlen (s);
    memcpy (sub, s + 1, len - 2);
    sub[len - 2] = '\0';
  }
  else if (has_prefix_star)
  {
    // *后缀
    strcpy (sub, s + 1);
  }
  else
  {
    // 前缀*
    size_t len = strlen (s);
    memcpy (sub, s, len - 1);
    sub[len - 1] = '\0';
  }

  // 分配最大可能空间
  pos->indices = (uint16_t *) malloc (2048 * sizeof (uint16_t));
  if (pos->indices == NULL) return -1;

  pos->count    = 0;
  pos->is_exact = false;

  for (int i = 0; i < 2048; i++)
  {
    const char *word = bip39_wordlist_lookup_word (wl, (uint16_t) i);
    if (word == NULL) continue;

    bool match = false;

    if (has_prefix_star && has_suffix_star)
    {
      match = (strstr (word, sub) != NULL);
    }
    else if (has_prefix_star)
    {
      // 后缀匹配：word 以 sub 结尾
      size_t wlen = strlen (word);
      size_t slen = strlen (sub);
      if (wlen >= slen) match = (strcmp (word + wlen - slen, sub) == 0);
    }
    else
    {
      // 前缀匹配：word 以 sub 开头
      match = (strncmp (word, sub, strlen (sub)) == 0);
    }

    if (match == true)
    {
      pos->indices[pos->count++] = (uint16_t) i;
    }
  }

  if (pos->count == 0)
  {
    fprintf (stderr, "mnemonic_fuzzy: no match for pattern '%s'\n", pattern);
    free (pos->indices);
    return -1;
  }

  return 0;
}

// ── 解析 .mnem 文件 ──

int mnemonic_fuzzy_parse (mnemonic_candidates_t *mc, bip39_wordlist_t *wl, const char *filename)
{
  if (mc == NULL || wl == NULL || filename == NULL) return -1;

  memset (mc, 0, sizeof (mnemonic_candidates_t));
  mc->language = wl->lang;

  FILE *fp = fopen (filename, "r");
  if (fp == NULL)
  {
    fprintf (stderr, "mnemonic_fuzzy: cannot open %s\n", filename);
    return -1;
  }

  char  line[MAX_LINE];
  int   slot = 0;

  while (fgets (line, sizeof (line), fp) != NULL && slot < 15)
  {
    // 去除末尾换行
    size_t len = strlen (line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';

    // 跳过空行和注释
    if (len == 0 || line[0] == '#') continue;

    if (parse_one_slot (&mc->pos[slot], wl, line) != 0)
    {
      fclose (fp);
      mnemonic_fuzzy_destroy (mc);
      return -1;
    }

    slot++;
  }

  fclose (fp);

  mc->word_count = (uint32_t) slot;

  if (mc->word_count != 12 && mc->word_count != 15)
  {
    fprintf (stderr, "mnemonic_fuzzy: expected 12 or 15 words, got %u\n", mc->word_count);
    mnemonic_fuzzy_destroy (mc);
    return -1;
  }

  // 计算总组合数（候选数乘积，不含排列）
  mc->total_combinations = 1;
  for (uint32_t i = 0; i < mc->word_count; i++)
  {
    mc->total_combinations *= mc->pos[i].count;
  }

  return 0;
}

void mnemonic_fuzzy_destroy (mnemonic_candidates_t *mc)
{
  if (mc == NULL) return;

  for (uint32_t i = 0; i < mc->word_count; i++)
  {
    free (mc->pos[i].indices);
    mc->pos[i].indices = NULL;
  }

  memset (mc, 0, sizeof (mnemonic_candidates_t));
}
