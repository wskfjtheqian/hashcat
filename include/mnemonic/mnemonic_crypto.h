#ifndef MNEMONIC_CRYPTO_H
#define MNEMONIC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ── SHA512 ──
typedef struct
{
  uint64_t state[8];
  uint64_t count[2];
  uint8_t  buf[128];
} sha512_ctx_t;

void sha512_init   (sha512_ctx_t *ctx);
void sha512_update (sha512_ctx_t *ctx, const uint8_t *data, size_t len);
void sha512_final  (sha512_ctx_t *ctx, uint8_t digest[64]);

// ── HMAC-SHA512 ──
void hmac_sha512 (const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[64]);

// ── PBKDF2-HMAC-SHA512 ──
void pbkdf2_hmac_sha512 (const uint8_t *password, size_t password_len,
                         const uint8_t *salt,     size_t salt_len,
                         uint32_t iterations,
                         uint8_t *derived_key,    size_t dk_len);

// ── BIP32 密钥派生 ──
// CKDpriv: 从父密钥派生子密钥
// hardened = true  → 硬化派生 (index >= 0x80000000)
// hardened = false → 普通派生
void bip32_ckd_priv (const uint8_t parent_key[32],
                     const uint8_t parent_chain[32],
                     uint32_t      index,
                     bool          hardened,
                     uint8_t child_key[32],
                     uint8_t child_chain[32]);

// BIP32 主密钥生成: I = HMAC-SHA512("Bitcoin seed", seed)
// master_key  = I[0:32], master_chain = I[32:64]
void bip32_master (const uint8_t *seed, size_t seed_len,
                   uint8_t master_key[32], uint8_t master_chain[32]);

// ── BIP44 路径派生 ──
void bip44_derive (const uint8_t *seed, size_t seed_len,
                   const uint32_t *path,
                   uint32_t        path_levels,
                   uint8_t         derived_key[32],
                   uint8_t         derived_chain[32]);

// ── BIP39 种子生成 ──
void bip39_seed (const char *mnemonic, const char *passphrase,
                 uint8_t seed[64]);

#endif
