#include "mnemonic/mnemonic_crypto.h"
#include <string.h>
#include <stdio.h>

// ═══════════════════════════════════════════════
//  SHA-512
// ═══════════════════════════════════════════════

static const uint64_t sha512_k[80] =
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define SHA512_ROR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHA512_S0(x) (SHA512_ROR64(x,28) ^ SHA512_ROR64(x,34) ^ SHA512_ROR64(x,39))
#define SHA512_S1(x) (SHA512_ROR64(x,14) ^ SHA512_ROR64(x,18) ^ SHA512_ROR64(x,41))
#define SHA512_s0(x) (SHA512_ROR64(x, 1) ^ SHA512_ROR64(x, 8) ^ ((x) >> 7))
#define SHA512_s1(x) (SHA512_ROR64(x,19) ^ SHA512_ROR64(x,61) ^ ((x) >> 6))
#define SHA512_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static void sha512_transform (sha512_ctx_t *ctx, const uint8_t *block)
{
  uint64_t w[80];

  for (int i = 0; i < 16; i++)
  {
    w[i] = ((uint64_t) block[i * 8 + 0] << 56)
         | ((uint64_t) block[i * 8 + 1] << 48)
         | ((uint64_t) block[i * 8 + 2] << 40)
         | ((uint64_t) block[i * 8 + 3] << 32)
         | ((uint64_t) block[i * 8 + 4] << 24)
         | ((uint64_t) block[i * 8 + 5] << 16)
         | ((uint64_t) block[i * 8 + 6] <<  8)
         | ((uint64_t) block[i * 8 + 7] <<  0);
  }

  for (int i = 16; i < 80; i++)
  {
    w[i] = SHA512_s1(w[i-2]) + w[i-7] + SHA512_s0(w[i-15]) + w[i-16];
  }

  uint64_t a = ctx->state[0];
  uint64_t b = ctx->state[1];
  uint64_t c = ctx->state[2];
  uint64_t d = ctx->state[3];
  uint64_t e = ctx->state[4];
  uint64_t f = ctx->state[5];
  uint64_t g = ctx->state[6];
  uint64_t h = ctx->state[7];

  for (int i = 0; i < 80; i++)
  {
    uint64_t t1 = h + SHA512_S1(e) + SHA512_CH(e,f,g) + sha512_k[i] + w[i];
    uint64_t t2 = SHA512_S0(a) + SHA512_MAJ(a,b,c);
    h = g;  g = f;  f = e;
    e = d + t1;
    d = c;  c = b;  b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;  ctx->state[1] += b;
  ctx->state[2] += c;  ctx->state[3] += d;
  ctx->state[4] += e;  ctx->state[5] += f;
  ctx->state[6] += g;  ctx->state[7] += h;
}

void sha512_init (sha512_ctx_t *ctx)
{
  ctx->state[0] = 0x6a09e667f3bcc908ULL;
  ctx->state[1] = 0xbb67ae8584caa73bULL;
  ctx->state[2] = 0x3c6ef372fe94f82bULL;
  ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->state[4] = 0x510e527fade682d1ULL;
  ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  ctx->state[6] = 0x1f83d9abfb41bd6bULL;
  ctx->state[7] = 0x5be0cd19137e2179ULL;
  ctx->count[0] = ctx->count[1] = 0;
}

void sha512_update (sha512_ctx_t *ctx, const uint8_t *data, size_t len)
{
  size_t idx = (size_t) (ctx->count[0] & 0x7F);
  ctx->count[0] += (uint64_t) len;
  if (ctx->count[0] < (uint64_t) len) ctx->count[1]++;

  if (idx > 0)
  {
    size_t fill = 128 - idx;
    if (len < fill) { memcpy (ctx->buf + idx, data, len); return; }
    memcpy (ctx->buf + idx, data, fill);
    sha512_transform (ctx, ctx->buf);
    data += fill;  len -= fill;
  }
  while (len >= 128) { sha512_transform (ctx, data); data += 128; len -= 128; }
  if (len > 0) memcpy (ctx->buf, data, len);
}

void sha512_final (sha512_ctx_t *ctx, uint8_t digest[64])
{
  uint64_t bits_hi = (ctx->count[1] << 3) | (ctx->count[0] >> 61);
  uint64_t bits_lo = ctx->count[0] << 3;
  size_t   idx     = (size_t) (ctx->count[0] & 0x7F);

  ctx->buf[idx++] = 0x80;
  if (idx > 112) { memset (ctx->buf + idx, 0, 128 - idx); sha512_transform (ctx, ctx->buf); idx = 0; }
  memset (ctx->buf + idx, 0, 112 - idx);

  // 大端写入位数
  for (int i = 0; i < 8; i++) { ctx->buf[112 + i] = (uint8_t) (bits_hi >> (56 - i * 8)); }
  for (int i = 0; i < 8; i++) { ctx->buf[120 + i] = (uint8_t) (bits_lo >> (56 - i * 8)); }

  sha512_transform (ctx, ctx->buf);

  for (int i = 0; i < 8; i++)
  {
    digest[i*8 + 0] = (uint8_t)(ctx->state[i] >> 56);
    digest[i*8 + 1] = (uint8_t)(ctx->state[i] >> 48);
    digest[i*8 + 2] = (uint8_t)(ctx->state[i] >> 40);
    digest[i*8 + 3] = (uint8_t)(ctx->state[i] >> 32);
    digest[i*8 + 4] = (uint8_t)(ctx->state[i] >> 24);
    digest[i*8 + 5] = (uint8_t)(ctx->state[i] >> 16);
    digest[i*8 + 6] = (uint8_t)(ctx->state[i] >>  8);
    digest[i*8 + 7] = (uint8_t)(ctx->state[i] >>  0);
  }
}

// ═══════════════════════════════════════════════
//  HMAC-SHA512
// ═══════════════════════════════════════════════

void hmac_sha512 (const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[64])
{
  uint8_t k_ipad[128], k_opad[128];
  uint8_t tkey[64];
  sha512_ctx_t ctx;

  if (key_len > 128)
  {
    sha512_init (&ctx);
    sha512_update (&ctx, key, key_len);
    sha512_final (&ctx, tkey);
    key = tkey;  key_len = 64;
  }

  memset (k_ipad, 0x36, 128);
  memset (k_opad, 0x5c, 128);

  for (size_t i = 0; i < key_len; i++)
  {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  uint8_t inner_hash[64];
  sha512_init (&ctx);
  sha512_update (&ctx, k_ipad, 128);
  sha512_update (&ctx, data, data_len);
  sha512_final (&ctx, inner_hash);

  sha512_init (&ctx);
  sha512_update (&ctx, k_opad, 128);
  sha512_update (&ctx, inner_hash, 64);
  sha512_final (&ctx, digest);
}

// ═══════════════════════════════════════════════
//  PBKDF2-HMAC-SHA512
// ═══════════════════════════════════════════════

void pbkdf2_hmac_sha512 (const uint8_t *password, size_t password_len,
                         const uint8_t *salt,     size_t salt_len,
                         uint32_t iterations,
                         uint8_t *derived_key,    size_t dk_len)
{
  uint8_t block[64], u[64];
  uint32_t block_idx = 1;

  while (dk_len > 0)
  {
    // salt || block_idx (big-endian)
    uint8_t salt_block[256];
    size_t  sl = salt_len;
    memcpy (salt_block, salt, sl);
    salt_block[sl++] = (uint8_t)(block_idx >> 24);
    salt_block[sl++] = (uint8_t)(block_idx >> 16);
    salt_block[sl++] = (uint8_t)(block_idx >>  8);
    salt_block[sl++] = (uint8_t)(block_idx >>  0);

    hmac_sha512 (password, password_len, salt_block, sl, u);
    memcpy (block, u, 64);

    for (uint32_t i = 1; i < iterations; i++)
    {
      hmac_sha512 (password, password_len, u, 64, u);
      for (int j = 0; j < 64; j++) block[j] ^= u[j];
    }

    size_t copy = (dk_len < 64) ? dk_len : 64;
    memcpy (derived_key, block, copy);
    derived_key += copy;  dk_len -= copy;  block_idx++;
  }
}

// ═══════════════════════════════════════════════
//  BIP32
// ═══════════════════════════════════════════════

void bip32_master (const uint8_t *seed, size_t seed_len,
                   uint8_t master_key[32], uint8_t master_chain[32])
{
  const char *key = "Bitcoin seed";
  uint8_t I[64];
  hmac_sha512 ((const uint8_t *) key, strlen (key), seed, seed_len, I);
  memcpy (master_key,  I,      32);
  memcpy (master_chain, I + 32, 32);
}

// 跨模块声明 (实现在 mnemonic_keygen.c)
extern void secp256k1_get_compressed_pubkey (const uint8_t priv[32], uint8_t comp[33]);

void bip32_ckd_priv (const uint8_t parent_key[32],
                     const uint8_t parent_chain[32],
                     uint32_t      index,
                     bool          hardened,
                     uint8_t child_key[32],
                     uint8_t child_chain[32])
{
  uint8_t I[64];

  if (hardened)
  {
    uint8_t data[37];
    data[0] = 0x00;
    memcpy (data + 1, parent_key, 32);
    data[33] = (uint8_t)(index >> 24);
    data[34] = (uint8_t)(index >> 16);
    data[35] = (uint8_t)(index >>  8);
    data[36] = (uint8_t)(index >>  0);
    hmac_sha512 (parent_chain, 32, data, 37, I);

    // child_key = (IL + parent_key) mod n
    // secp256k1 n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
    uint8_t n[32] = {
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
      0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
      0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    };

    // 大整数加法: IL + parent_key, 溢出时减 n
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--)
    {
      carry += (uint16_t) I[i] + parent_key[i];
      child_key[i] = (uint8_t) carry;
      carry >>= 8;
    }

    // 如果结果 >= n, 减 n
    if (carry || memcmp (child_key, n, 32) >= 0)
    {
      uint16_t borrow = 0;
      for (int i = 31; i >= 0; i--)
      {
        int diff = (int) child_key[i] - n[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else borrow = 0;
        child_key[i] = (uint8_t) diff;
      }
    }
  }
  else
  {
    // 非硬化派生: Data = ser256(point(kpar)) || ser32(i)
    uint8_t pub_compressed[33];
    secp256k1_get_compressed_pubkey (parent_key, pub_compressed);

    uint8_t data[37];
    memcpy (data, pub_compressed, 33);
    data[33] = (uint8_t)(index >> 24);
    data[34] = (uint8_t)(index >> 16);
    data[35] = (uint8_t)(index >>  8);
    data[36] = (uint8_t)(index >>  0);
    hmac_sha512 (parent_chain, 32, data, 37, I);

    // child_key = (IL + parent_key) mod n (复用上方的 n)
    uint8_t n[32] = {
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
      0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
      0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    };

    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--)
    {
      carry += (uint16_t) I[i] + parent_key[i];
      child_key[i] = (uint8_t) carry;
      carry >>= 8;
    }

    if (carry || memcmp (child_key, n, 32) >= 0)
    {
      uint16_t borrow = 0;
      for (int i = 31; i >= 0; i--)
      {
        int diff = (int) child_key[i] - n[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else borrow = 0;
        child_key[i] = (uint8_t) diff;
      }
    }
  }

  memcpy (child_chain, I + 32, 32);
}

// ═══════════════════════════════════════════════
//  BIP44
// ═══════════════════════════════════════════════

void bip44_derive (const uint8_t *seed, size_t seed_len,
                   const uint32_t *path,
                   uint32_t        path_levels,
                   uint8_t         derived_key[32],
                   uint8_t         derived_chain[32])
{
  uint8_t key[32], chain[32];

  bip32_master (seed, seed_len, key, chain);

  for (uint32_t i = 0; i < path_levels; i++)
  {
    bool hardened = (path[i] >= 0x80000000);
    uint32_t idx  = path[i];  // 完整索引, ser32 编码需要包含硬化位
    uint8_t  new_key[32], new_chain[32];

    bip32_ckd_priv (key, chain, idx, hardened, new_key, new_chain);
    memcpy (key, new_key, 32);
    memcpy (chain, new_chain, 32);
  }

  memcpy (derived_key, key, 32);
  memcpy (derived_chain, chain, 32);
}

// ═══════════════════════════════════════════════
//  BIP39 种子
// ═══════════════════════════════════════════════

void bip39_seed (const char *mnemonic, const char *passphrase, uint8_t seed[64])
{
  const char *salt_prefix = "mnemonic";
  char  salt[512];
  int   salt_len = (int) strlen (salt_prefix);

  memcpy (salt, salt_prefix, salt_len);

  if (passphrase != NULL && passphrase[0] != '\0')
  {
    salt_len += (int) strlen (passphrase);
    memcpy (salt + strlen (salt_prefix), passphrase, strlen (passphrase));
  }

  pbkdf2_hmac_sha512 ((const uint8_t *) mnemonic, strlen (mnemonic),
                      (const uint8_t *) salt, (size_t) salt_len,
                      2048, seed, 64);
}
