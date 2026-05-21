#include "mnemonic/mnemonic_permute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── 简易 SHA256 (仅用于 BIP39 校验和) ──
// 使用小端 32 位字

typedef struct
{
  uint32_t state[8];
  uint64_t count;
  uint8_t  buf[64];
} sha256_ctx_t;

static const uint32_t sha256_k[64] =
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define SHA256_ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_S0(x) (SHA256_ROR(x,2) ^ SHA256_ROR(x,13) ^ SHA256_ROR(x,22))
#define SHA256_S1(x) (SHA256_ROR(x,6) ^ SHA256_ROR(x,11) ^ SHA256_ROR(x,25))
#define SHA256_s0(x) (SHA256_ROR(x,7) ^ SHA256_ROR(x,18) ^ ((x) >> 3))
#define SHA256_s1(x) (SHA256_ROR(x,17) ^ SHA256_ROR(x,19) ^ ((x) >> 10))

static void sha256_init (sha256_ctx_t *ctx)
{
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->count    = 0;
}

static void sha256_transform (sha256_ctx_t *ctx, const uint8_t *data)
{
  uint32_t w[64];

  for (int i = 0; i < 16; i++)
  {
    w[i] = ((uint32_t) data[i * 4 + 0] << 24)
         | ((uint32_t) data[i * 4 + 1] << 16)
         | ((uint32_t) data[i * 4 + 2] <<  8)
         | ((uint32_t) data[i * 4 + 3] <<  0);
  }

  for (int i = 16; i < 64; i++)
  {
    w[i] = SHA256_s1 (w[i - 2]) + w[i - 7] + SHA256_s0 (w[i - 15]) + w[i - 16];
  }

  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];

  for (int i = 0; i < 64; i++)
  {
    uint32_t t1 = h + SHA256_S1 (e) + SHA256_CH (e, f, g) + sha256_k[i] + w[i];
    uint32_t t2 = SHA256_S0 (a) + SHA256_MAJ (a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_update (sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
  size_t idx = (size_t) (ctx->count & 0x3F);
  ctx->count += (uint64_t) len;

  if (idx > 0)
  {
    size_t fill = 64 - idx;
    if (len < fill)
    {
      memcpy (ctx->buf + idx, data, len);
      return;
    }
    memcpy (ctx->buf + idx, data, fill);
    sha256_transform (ctx, ctx->buf);
    data += fill;
    len  -= fill;
  }

  while (len >= 64)
  {
    sha256_transform (ctx, data);
    data += 64;
    len  -= 64;
  }

  if (len > 0) memcpy (ctx->buf, data, len);
}

static void sha256_final (sha256_ctx_t *ctx, uint8_t *digest)
{
  uint64_t bits = ctx->count * 8;
  size_t   idx  = (size_t) (ctx->count & 0x3F);

  ctx->buf[idx++] = 0x80;

  if (idx > 56)
  {
    memset (ctx->buf + idx, 0, 64 - idx);
    sha256_transform (ctx, ctx->buf);
    idx = 0;
  }

  memset (ctx->buf + idx, 0, 56 - idx);

  // 大端写入位数
  for (int i = 0; i < 8; i++)
  {
    ctx->buf[56 + i] = (uint8_t) (bits >> (56 - i * 8));
  }

  sha256_transform (ctx, ctx->buf);

  // 大端输出
  for (int i = 0; i < 8; i++)
  {
    digest[i * 4 + 0] = (uint8_t) (ctx->state[i] >> 24);
    digest[i * 4 + 1] = (uint8_t) (ctx->state[i] >> 16);
    digest[i * 4 + 2] = (uint8_t) (ctx->state[i] >>  8);
    digest[i * 4 + 3] = (uint8_t) (ctx->state[i] >>  0);
  }
}

// ── 阶乘计算 ──
static uint64_t factorial (uint32_t n)
{
  uint64_t r = 1;
  for (uint32_t i = 2; i <= n; i++) r *= i;
  return r;
}

// ── BIP39 校验和验证 ──
// 12 词 → 4 bit checksum, 15 词 → 5 bit checksum
// 返回 true 表示校验和有效
static bool bip39_checksum_verify (const uint16_t *indices, uint32_t word_count)
{
  // 将 11-bit 索引转换为位串
  int total_bits = (int) word_count * 11;
  int entropy_bits;
  int checksum_bits;

  if (word_count == 12)      { entropy_bits = 128; checksum_bits = 4;  }
  else if (word_count == 15) { entropy_bits = 160; checksum_bits = 5;  }
  else if (word_count == 18) { entropy_bits = 192; checksum_bits = 6;  }
  else if (word_count == 21) { entropy_bits = 224; checksum_bits = 7;  }
  else if (word_count == 24) { entropy_bits = 256; checksum_bits = 8;  }
  else return false;

  (void) total_bits;

  // 将索引转换为字节
  uint8_t bytes[33]; // 最大 264 bits = 33 bytes
  memset (bytes, 0, sizeof (bytes));

  int bit_pos = 0;
  for (uint32_t i = 0; i < word_count; i++)
  {
    for (int b = 10; b >= 0; b--)
    {
      int byte_idx  = bit_pos / 8;
      int bit_idx   = 7 - (bit_pos % 8);
      if ((indices[i] >> b) & 1) bytes[byte_idx] |= (1 << bit_idx);
      bit_pos++;
    }
  }

  // SHA256
  uint8_t hash[32];
  sha256_ctx_t ctx;
  sha256_init (&ctx);
  sha256_update (&ctx, bytes, (size_t) (entropy_bits / 8));
  sha256_final (&ctx, hash);

  // 验证校验和
  int checksum_expected = hash[0] >> (8 - checksum_bits);
  int checksum_actual   = bytes[entropy_bits / 8] >> (8 - checksum_bits);

  return checksum_expected == checksum_actual;
}

// ── Heap 排列算法辅助 ──
static void swap_u16 (uint16_t *a, uint16_t *b)
{
  uint16_t tmp = *a;
  *a = *b;
  *b = tmp;
}

// ── 排列迭代器 ──

int perm_iterator_init (perm_iterator_t *it, mnemonic_candidates_t *mc, uint32_t batch_size)
{
  if (it == NULL || mc == NULL) return -1;

  memset (it, 0, sizeof (perm_iterator_t));

  it->candidates = mc;
  it->total_perms = factorial (mc->word_count);
  it->total_combs = mc->total_combinations;
  it->total_work  = it->total_perms * it->total_combs;

  it->batch_size = batch_size;

  // 分配工作缓冲
  it->current_order = (uint16_t *) calloc (mc->word_count, sizeof (uint16_t));
  it->heap_c        = (uint32_t *) calloc (mc->word_count, sizeof (uint32_t));
  it->comb_buf      = (uint16_t *) calloc (mc->word_count, sizeof (uint16_t));

  if (it->current_order == NULL || it->heap_c == NULL || it->comb_buf == NULL)
  {
    perm_iterator_destroy (it);
    return -1;
  }

  // 初始顺序：0, 1, 2, ..., N-1
  for (uint32_t i = 0; i < mc->word_count; i++)
  {
    it->current_order[i] = (uint16_t) i;
  }

  // 输出缓冲
  it->output_buf = (uint16_t *) malloc (batch_size * mc->word_count * sizeof (uint16_t));
  if (it->output_buf == NULL)
  {
    perm_iterator_destroy (it);
    return -1;
  }

  // 初始化组合索引
  memset (it->comb_buf, 0, mc->word_count * sizeof (uint16_t));

  return 0;
}

int perm_iterator_next (perm_iterator_t *it)
{
  if (it == NULL || it->output_buf == NULL) return 0;

  it->batch_count = 0;

  uint32_t N = it->candidates->word_count;

  while (it->batch_count < it->batch_size)
  {
    if (it->perm_idx >= it->total_perms)
    {
      break;
    }

    // 当前排列：从 current_order 获取候选集顺序
    // 当前组合：从 comb_buf 获取每个位置选第几个候选
    // 生成索引序列并做校验和验证
    uint16_t indices[24];

    for (uint32_t i = 0; i < N; i++)
    {
      uint32_t pos_idx = it->current_order[i];   // 候选集在排列中的位置
      uint32_t comb    = it->comb_buf[i];         // 该候选集中选第几个
      indices[i] = it->candidates->pos[pos_idx].indices[comb];
    }

    // BIP39 校验和验证
    if (bip39_checksum_verify (indices, N) == true)
    {
      // 写入输出缓冲
      uint16_t *dst = it->output_buf + it->batch_count * N;
      memcpy (dst, indices, N * sizeof (uint16_t));
      it->batch_count++;
    }

    // 推进组合计数器
    it->comb_idx++;
    bool carry = false;
    for (int i = (int) N - 1; i >= 0; i--)
    {
      uint32_t pos_idx = it->current_order[i];
      it->comb_buf[i]++;
      if (it->comb_buf[i] < it->candidates->pos[pos_idx].count)
      {
        carry = false;
        break;
      }
      it->comb_buf[i] = 0;
      carry = true;
    }

    if (carry == true)
    {
      // 组合枚举完毕，推进排列
      // Heap 算法
      uint32_t k = 1;
      while (k < N && it->heap_c[k] >= k) { it->heap_c[k] = 0; k++; }

      if (k >= N)
      {
        // 所有排列完成
        it->perm_idx = it->total_perms;
        break;
      }

      if (k % 2 == 0)
      {
        swap_u16 (&it->current_order[0], &it->current_order[k]);
      }
      else
      {
        swap_u16 (&it->current_order[it->heap_c[k]], &it->current_order[k]);
      }

      it->heap_c[k]++;
      it->perm_idx++;
      it->comb_idx = 0;
      memset (it->comb_buf, 0, N * sizeof (uint16_t));
    }
  }

  return (int) it->batch_count;
}

void perm_iterator_destroy (perm_iterator_t *it)
{
  if (it == NULL) return;

  free (it->current_order);
  free (it->heap_c);
  free (it->comb_buf);
  free (it->output_buf);

  it->current_order = NULL;
  it->heap_c        = NULL;
  it->comb_buf      = NULL;
  it->output_buf    = NULL;
}
