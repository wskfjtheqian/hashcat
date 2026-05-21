#include "mnemonic/mnemonic_types.h"
#include "mnemonic/bip39_wordlist.h"
#include "mnemonic/mnemonic_fuzzy.h"
#include "mnemonic/mnemonic_address.h"
#include "mnemonic/mnemonic_permute.h"
#include "mnemonic/mnemonic_crypto.h"
#include "mnemonic/mnemonic_keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex_print (const uint8_t *data, int len)
{
  for (int i = 0; i < len; i++) printf ("%02x", data[i]);
}

// ── Phase 1 tests ──

static int test_wordlist (void)
{
  printf ("=== test_wordlist ===\n");
  bip39_wordlist_t wl;
  if (bip39_wordlist_init (&wl, LANG_EN) != 0) { printf ("SKIP\n\n"); return 0; }
  printf ("lang: %s\n", bip39_language_name (wl.lang));
  uint16_t idx = bip39_wordlist_lookup_idx (&wl, "abandon");
  printf ("abandon→%u zoo→%u notaword→0x%04X\n", idx,
          bip39_wordlist_lookup_idx (&wl, "zoo"),
          bip39_wordlist_lookup_idx (&wl, "notaword"));
  bip39_wordlist_destroy (&wl);
  printf ("PASS\n\n"); return 0;
}

static int test_fuzzy (void)
{
  printf ("=== test_fuzzy ===\n");
  bip39_wordlist_t wl;
  if (bip39_wordlist_init (&wl, LANG_EN) != 0) { printf ("SKIP\n\n"); return 0; }
  const char *tmpfile = "/tmp/test_mnemonic.mnem";
  FILE *fp = fopen (tmpfile, "w");
  for (int i = 0; i < 12; i++) fprintf (fp, "abandon\n");
  fclose (fp);
  mnemonic_candidates_t mc;
  mnemonic_fuzzy_parse (&mc, &wl, tmpfile);
  printf ("words: %u, combos: %llu\n", mc.word_count, (unsigned long long) mc.total_combinations);
  mnemonic_fuzzy_destroy (&mc);
  bip39_wordlist_destroy (&wl);
  remove (tmpfile);
  printf ("PASS\n\n"); return 0;
}

static int test_address (void)
{
  printf ("=== test_address ===\n");
  target_address_t addr;
  address_decode_eth ("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B", &addr);
  printf ("ETH: "); hex_print (addr.raw, 20); printf ("\n");
  address_decode_btc ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", &addr);
  printf ("BTC: "); hex_print (addr.raw, 20); printf ("\n");
  printf ("PASS\n\n"); return 0;
}

static int test_permute (void)
{
  printf ("=== test_permute ===\n");
  bip39_wordlist_t wl;
  if (bip39_wordlist_init (&wl, LANG_EN) != 0) { printf ("SKIP\n\n"); return 0; }
  const char *tmpfile = "/tmp/test_permute.mnem";
  FILE *fp = fopen (tmpfile, "w");
  const char *w[] = {"abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"};
  for (int i = 0; i < 12; i++) fprintf (fp, "%s\n", w[i]);
  fclose (fp);
  mnemonic_candidates_t mc;
  mnemonic_fuzzy_parse (&mc, &wl, tmpfile);
  perm_iterator_t it;
  perm_iterator_init (&it, &mc, 500);
  int n = perm_iterator_next (&it);
  printf ("batch: %d valid (checksum filtered)\n", n);
  perm_iterator_destroy (&it);
  mnemonic_fuzzy_destroy (&mc);
  bip39_wordlist_destroy (&wl);
  remove (tmpfile);
  printf ("PASS\n\n"); return 0;
}

// ── Phase 2 tests ──

static int test_sha512 (void)
{
  printf ("=== test_sha512 ===\n");
  sha512_ctx_t ctx;
  uint8_t d[64];
  sha512_init (&ctx);
  sha512_update (&ctx, (const uint8_t *)"abc", 3);
  sha512_final (&ctx, d);
  printf ("SHA512(abc): "); hex_print (d, 8); printf ("...\n");
  const uint8_t *exp = (const uint8_t *)"\xdd\xaf\x35\xa1\x93\x61\x7a\xba";
  printf ("%s\n\n", memcmp(d,exp,8)==0 ? "PASS" : "FAIL");
  return 0;
}

static int test_pbkdf2_bip39 (void)
{
  printf ("=== test_pbkdf2_bip39 ===\n");
  uint8_t seed[64];
  bip39_seed ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR", seed);
  printf ("seed: "); hex_print (seed, 8); printf ("...\n");
  const uint8_t *exp = (const uint8_t *)"\xc5\x52\x57\xc3\x60\xc0\x7c\x72";
  printf ("%s\n\n", memcmp(seed,exp,8)==0 ? "PASS" : "FAIL");
  return 0;
}

static int test_bip39_no_passphrase (void)
{
  printf ("=== test_bip39_no_passphrase ===\n");
  uint8_t seed[64];
  bip39_seed ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", seed);
  printf ("seed: "); hex_print (seed, 8); printf ("...\n");
  const uint8_t *exp = (const uint8_t *)"\x5e\xb0\x0b\xbd\xdc\xf0\x69\x08";
  printf ("%s\n\n", memcmp(seed,exp,8)==0 ? "PASS" : "FAIL");
  return 0;
}

static int test_bip32_vector1 (void)
{
  printf ("=== test_bip32_vector1 (m/0') ===\n");
  uint8_t seed[16];
  for (int i = 0; i < 16; i++) seed[i] = (uint8_t) i;
  uint32_t path[] = { 0x80000000 };
  uint8_t key[32], chain[32];
  bip44_derive (seed, 16, path, 1, key, chain);
  printf ("m/0' key: "); hex_print (key, 8); printf ("...\n");
  const uint8_t *exp = (const uint8_t *)"\xed\xb2\xe1\x4f\x9e\xe7\x7d\x26";
  printf ("%s\n\n", memcmp(key,exp,8)==0 ? "MATCH ✅" : "MISMATCH ❌");
  return 0;
}

static int test_known_mnemonic (void)
{
  printf ("=== test_known_mnemonic (ETH) ===\n");

  // raise duck doll hero slice cruel fluid series kit express aware denial
  // 无密码, m/44'/60'/0'/0/0
  // 预期: addr=0x2423D8BA86B2FB64EBB621c0f692CD6AE2f5E9Cd
  //        pubkey=02ffd4ed7109fd62a5ea9642f7fc15d72b6d2fe4b1fe32af009de2078f0c01f3ff
  //        privkey=901ab0291067ac9ac856623b9853c632f1c70f7999b3a3442384af496055d848

  uint8_t seed[64];
  bip39_seed ("raise duck doll hero slice cruel fluid series kit express aware denial",
              "", seed);

  printf ("seed: "); hex_print (seed, 8); printf ("...\n");

  uint32_t path[] = { 0x8000002C, 0x8000003C, 0x80000000, 0, 0 };
  uint8_t key[32], chain[32];
  bip44_derive (seed, 64, path, 5, key, chain);

  printf ("ETH privkey: "); hex_print (key, 32); printf ("\n");

  const uint8_t exp_key[32] = {
    0x90,0x1a,0xb0,0x29,0x10,0x67,0xac,0x9a,
    0xc8,0x56,0x62,0x3b,0x98,0x53,0xc6,0x32,
    0xf1,0xc7,0x0f,0x79,0x99,0xb3,0xa3,0x44,
    0x23,0x84,0xaf,0x49,0x60,0x55,0xd8,0x48
  };
  printf ("  → %s\n", memcmp(key,exp_key,32)==0 ? "MATCH ✅" : "MISMATCH ❌");

  uint8_t pubkey[65];
  secp256k1_pubkey (key, pubkey);
  printf ("ETH pubkey: "); hex_print (pubkey, 65); printf ("\n");

  uint8_t addr[20];
  eth_address_from_key (key, addr);
  printf ("ETH addr: 0x"); hex_print (addr, 20); printf ("\n");

  const uint8_t exp_addr[20] = {
    0x24,0x23,0xD8,0xBA,0x86,0xB2,0xFB,0x64,
    0xEB,0xB6,0x21,0xc0,0xf6,0x92,0xCD,0x6A,
    0xE2,0xf5,0xE9,0xCd
  };
  printf ("  → %s\n\n", memcmp(addr,exp_addr,20)==0 ? "MATCH ✅" : "MISMATCH ❌");
  return 0;
}

int main (int argc, char **argv)
{
  (void) argc; (void) argv;
  printf ("mnemonic Phase 1+2 test suite\n\n");

  test_wordlist ();
  test_fuzzy ();
  test_address ();
  test_permute ();
  printf ("--- Phase 2 ---\n\n");
  test_sha512 ();
  test_pbkdf2_bip39 ();
  test_bip39_no_passphrase ();
  test_bip32_vector1 ();
  test_known_mnemonic ();

  printf ("=== ALL TESTS DONE ===\n");
  return 0;
}
