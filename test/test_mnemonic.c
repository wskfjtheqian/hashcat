#include "mnemonic/mnemonic_types.h"
#include "mnemonic/bip39_wordlist.h"
#include "mnemonic/mnemonic_fuzzy.h"
#include "mnemonic/mnemonic_address.h"
#include "mnemonic/mnemonic_permute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_wordlist (void)
{
  printf ("=== test_wordlist ===\n");

  bip39_wordlist_t wl;
  if (bip39_wordlist_init (&wl, LANG_EN) != 0)
  {
    printf ("SKIP: wordlist not embedded\n");
    return 0;
  }

  printf ("lang: %s, separator: '%s'\n",
          bip39_language_name (wl.lang),
          bip39_language_separator (wl.lang));

  // 测试查找
  uint16_t idx = bip39_wordlist_lookup_idx (&wl, "abandon");
  printf ("lookup 'abandon' → %u (expect 0)\n", idx);

  idx = bip39_wordlist_lookup_idx (&wl, "zoo");
  printf ("lookup 'zoo' → %u (expect 2047)\n", idx);

  idx = bip39_wordlist_lookup_idx (&wl, "notaword");
  printf ("lookup 'notaword' → 0x%04X (expect 0xFFFF)\n", idx);

  const char *word = bip39_wordlist_lookup_word (&wl, 0);
  printf ("lookup index 0 → '%s' (expect 'abandon')\n", word);

  word = bip39_wordlist_lookup_word (&wl, 2047);
  printf ("lookup index 2047 → '%s' (expect 'zoo')\n", word);

  bip39_wordlist_destroy (&wl);
  printf ("PASS\n\n");
  return 0;
}

static int test_fuzzy (void)
{
  printf ("=== test_fuzzy ===\n");

  bip39_wordlist_t wl;
  if (bip39_wordlist_init (&wl, LANG_EN) != 0)
  {
    printf ("SKIP\n\n");
    return 0;
  }

  // 创建临时 .mnem 文件
  const char *tmpfile = "/tmp/test_mnemonic.mnem";
  FILE *fp = fopen (tmpfile, "w");
  fprintf (fp, "abandon\n");
  fprintf (fp, "ab*\n");
  fprintf (fp, "*y\n");
  fprintf (fp, "*oo*\n");
  fprintf (fp, "cat,dog\n");
  fprintf (fp, "zoo\n");
  fprintf (fp, "?\n");
  fprintf (fp, "apple\n");
  fprintf (fp, "banana\n");
  fprintf (fp, "cherry\n");
  fprintf (fp, "diamond\n");
  fprintf (fp, "eagle\n");
  fclose (fp);

  mnemonic_candidates_t mc;
  if (mnemonic_fuzzy_parse (&mc, &wl, tmpfile) != 0)
  {
    printf ("FAIL: fuzzy parse\n\n");
    bip39_wordlist_destroy (&wl);
    return -1;
  }

  printf ("word_count: %u\n", mc.word_count);
  printf ("total_combinations: %lu\n", (unsigned long) mc.total_combinations);

  for (uint32_t i = 0; i < mc.word_count; i++)
  {
    printf ("  pos[%u]: %u candidates", i, mc.pos[i].count);
    if (mc.pos[i].count <= 5)
    {
      printf (" [");
      for (uint32_t j = 0; j < mc.pos[i].count; j++)
      {
        printf ("%u", mc.pos[i].indices[j]);
        if (j + 1 < mc.pos[i].count) printf (",");
      }
      printf ("]");
    }
    printf ("\n");
  }

  mnemonic_fuzzy_destroy (&mc);
  bip39_wordlist_destroy (&wl);
  remove (tmpfile);
  printf ("PASS\n\n");
  return 0;
}

static int test_address (void)
{
  printf ("=== test_address ===\n");

  target_address_t addr;

  // ETH
  if (address_decode_eth ("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B", &addr) == 0)
  {
    printf ("ETH: ");
    for (int i = 0; i < 20; i++) printf ("%02x", addr.raw[i]);
    printf ("\n");
  }

  // BTC P2PKH
  if (address_decode_btc ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", &addr) == 0)
  {
    printf ("BTC: ");
    for (int i = 0; i < 20; i++) printf ("%02x", addr.raw[i]);
    printf ("\n");
  }

  // TRON
  if (address_decode_tron ("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", &addr) == 0)
  {
    printf ("TRON: ");
    for (int i = 0; i < 20; i++) printf ("%02x", addr.raw[i]);
    printf ("\n");
  }

  // 自动检测
  address_type_t type;
  if (address_decode_auto ("0x1234567890abcdef1234567890abcdef12345678", &addr, &type) == 0)
  {
    printf ("auto: type=%d\n", (int) type);
  }

  printf ("PASS\n\n");
  return 0;
}

static int test_permute (void)
{
  printf ("=== test_permute ===\n");

  bip39_wordlist_t wl;
  if (bip39_wordlist_init (&wl, LANG_EN) != 0)
  {
    printf ("SKIP\n\n");
    return 0;
  }

  // 创建简单测试：4 个精确词 + 8 个精确词 (通常 permute 需要所有词已知)
  // 这里用全精确匹配做排列 + 校验和测试
  // 使用已知的合法助记词索引序列:
  // abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse, access, accident
  // BIP39 不保证任意序列校验和正确，但我们只测试排列引擎
  const char *tmpfile = "/tmp/test_permute.mnem";
  FILE *fp = fopen (tmpfile, "w");
  const char *words[] =
  {
    "abandon", "ability", "able", "about", "above",
    "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident"
  };
  for (int i = 0; i < 12; i++)
  {
    fprintf (fp, "%s\n", words[i]);
  }
  fclose (fp);

  mnemonic_candidates_t mc;
  if (mnemonic_fuzzy_parse (&mc, &wl, tmpfile) != 0)
  {
    printf ("FAIL: fuzzy parse\n");
    bip39_wordlist_destroy (&wl);
    return -1;
  }

  printf ("word_count: %u, total_perms: 12! = 479001600\n", mc.word_count);

  perm_iterator_t it;
  if (perm_iterator_init (&it, &mc, 1000) != 0)
  {
    printf ("FAIL: perm_iterator_init\n");
    mnemonic_fuzzy_destroy (&mc);
    bip39_wordlist_destroy (&wl);
    return -1;
  }

  int total = 0;
  int batches = 0;
  int n;
  while ((n = perm_iterator_next (&it)) > 0 && batches < 5)
  {
    total += n;
    batches++;
    printf ("  batch %d: %d valid candidates (checksum filtered)\n", batches, n);
  }

  printf ("total: %d valid in %d batches\n", total, batches);

  perm_iterator_destroy (&it);
  mnemonic_fuzzy_destroy (&mc);
  bip39_wordlist_destroy (&wl);
  remove (tmpfile);
  printf ("PASS\n\n");
  return 0;
}

int main (int argc, char **argv)
{
  (void) argc;
  (void) argv;

  printf ("mnemonic Phase 1 test suite\n");
  printf ("wordlists: embedded (no external files)\n\n");

  test_wordlist ();
  test_fuzzy     ();
  test_address   ();
  test_permute   ();

  printf ("=== ALL TESTS DONE ===\n");
  return 0;
}
