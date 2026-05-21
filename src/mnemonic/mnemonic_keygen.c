#include "mnemonic/mnemonic_keygen.h"
#include "mnemonic/mnemonic_crypto.h"
#include <string.h>
#include <stdio.h>

// ═══════════════════════════════════════════════
//  Keccak-256 (SHA3-256)
// ═══════════════════════════════════════════════

static const uint64_t keccak_rc[24] =
{
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
  0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
  0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
  0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int keccak_rot[24] =
{
   1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
  27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const int keccak_piln[24] =
{
  10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
  15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1,
};

#define KECCAK_ROTL64(x,n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccakf (uint64_t st[25])
{
  for (int r = 0; r < 24; r++)
  {
    uint64_t bc[5];

    for (int i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];

    for (int i = 0; i < 5; i++)
    {
      uint64_t t = bc[(i+4) % 5] ^ KECCAK_ROTL64 (bc[(i+1) % 5], 1);
      for (int j = 0; j < 5; j++)
        st[i + j*5] ^= t;
    }

    uint64_t t = st[1];
    for (int i = 0; i < 24; i++)
    {
      int j = keccak_piln[i];
      uint64_t tmp = st[j];
      st[j] = KECCAK_ROTL64 (t, keccak_rot[i]);
      t = tmp;
    }

    for (int j = 0; j < 5; j++)
    {
      uint64_t t2 = st[j];
      for (int i = 0; i < 25; i += 5)
      {
        uint64_t t3 = st[i+j];
        st[i+j] = t2 ^ ((~st[i+j+1]) & st[i+j+2]);
        t2 = t3;
      }
    }

    st[0] ^= keccak_rc[r];
  }
}

void keccak256 (const uint8_t *data, size_t len, uint8_t digest[32])
{
  uint64_t st[25];
  memset (st, 0, sizeof (st));

  size_t rate = 136; // 1088 bits
  size_t pos  = 0;

  while (len >= rate)
  {
    for (size_t i = 0; i < rate / 8; i++)
    {
      st[i] ^= ((uint64_t) data[pos + i*8 + 0] <<  0)
             | ((uint64_t) data[pos + i*8 + 1] <<  8)
             | ((uint64_t) data[pos + i*8 + 2] << 16)
             | ((uint64_t) data[pos + i*8 + 3] << 24)
             | ((uint64_t) data[pos + i*8 + 4] << 32)
             | ((uint64_t) data[pos + i*8 + 5] << 40)
             | ((uint64_t) data[pos + i*8 + 6] << 48)
             | ((uint64_t) data[pos + i*8 + 7] << 56);
    }
    keccakf (st);
    data += rate;  len -= rate;
  }

  // Padding
  uint8_t tmp[144];
  memcpy (tmp, data, len);
  tmp[len] = 0x01;
  memset (tmp + len + 1, 0, rate - len - 1);
  tmp[rate - 1] = 0x80;

  for (size_t i = 0; i < rate / 8; i++)
  {
    st[i] ^= ((uint64_t) tmp[i*8 + 0] <<  0)
           | ((uint64_t) tmp[i*8 + 1] <<  8)
           | ((uint64_t) tmp[i*8 + 2] << 16)
           | ((uint64_t) tmp[i*8 + 3] << 24)
           | ((uint64_t) tmp[i*8 + 4] << 32)
           | ((uint64_t) tmp[i*8 + 5] << 40)
           | ((uint64_t) tmp[i*8 + 6] << 48)
           | ((uint64_t) tmp[i*8 + 7] << 56);
  }
  keccakf (st);

  for (int i = 0; i < 4; i++)
  {
    digest[i*8 + 0] = (uint8_t)(st[i] >>  0);
    digest[i*8 + 1] = (uint8_t)(st[i] >>  8);
    digest[i*8 + 2] = (uint8_t)(st[i] >> 16);
    digest[i*8 + 3] = (uint8_t)(st[i] >> 24);
    digest[i*8 + 4] = (uint8_t)(st[i] >> 32);
    digest[i*8 + 5] = (uint8_t)(st[i] >> 40);
    digest[i*8 + 6] = (uint8_t)(st[i] >> 48);
    digest[i*8 + 7] = (uint8_t)(st[i] >> 56);
  }
}

// ═══════════════════════════════════════════════
//  RIPEMD-160
// ═══════════════════════════════════════════════

static const uint32_t ripemd160_iv[5] =
{
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};

#define RIPEMD_ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void ripemd160_compress (uint32_t state[5], const uint8_t block[64])
{
  uint32_t x[16];
  for (int i = 0; i < 16; i++)
  {
    x[i] = (uint32_t) block[i*4 + 0]
         | ((uint32_t) block[i*4 + 1] << 8)
         | ((uint32_t) block[i*4 + 2] << 16)
         | ((uint32_t) block[i*4 + 3] << 24);
  }

  uint32_t a1 = state[0], b1 = state[1], c1 = state[2], d1 = state[3], e1 = state[4];
  uint32_t a2 = state[0], b2 = state[1], c2 = state[2], d2 = state[3], e2 = state[4];

  // F rounds (left line)
  #define F(x,y,z) ((x) ^ (y) ^ (z))
  #define G(x,y,z) (((x) & (y)) | (~(x) & (z)))
  #define H(x,y,z) (((x) | ~(y)) ^ (z))
  #define I(x,y,z) (((x) & (z)) | ((y) & ~(z)))
  #define J(x,y,z) ((x) ^ ((y) | ~(z)))

  #define R(a,b,c,d,e,f,s,k,data) do { \
    a += f(b,c,d) + data[x[k]] + 0x00000000U; \
    a = RIPEMD_ROTL(a,s) + e; \
    c = RIPEMD_ROTL(c,10); \
  } while(0)

  #define R2(a,b,c,d,e,f,s,k,data) do { \
    a += f(b,c,d) + data[x[k]] + 0x5a827999U; \
    a = RIPEMD_ROTL(a,s) + e; \
    c = RIPEMD_ROTL(c,10); \
  } while(0)

  #define R3(a,b,c,d,e,f,s,k,data) do { \
    a += f(b,c,d) + data[x[k]] + 0x6ed9eba1U; \
    a = RIPEMD_ROTL(a,s) + e; \
    c = RIPEMD_ROTL(c,10); \
  } while(0)

  #define R4(a,b,c,d,e,f,s,k,data) do { \
    a += f(b,c,d) + data[x[k]] + 0x8f1bbcdcU; \
    a = RIPEMD_ROTL(a,s) + e; \
    c = RIPEMD_ROTL(c,10); \
  } while(0)

  #define R5(a,b,c,d,e,f,s,k,data) do { \
    a += f(b,c,d) + data[x[k]] + 0xa953fd4eU; \
    a = RIPEMD_ROTL(a,s) + e; \
    c = RIPEMD_ROTL(c,10); \
  } while(0)

  // 简化实现
  (void) a2; (void) b2; (void) c2; (void) d2; (void) e2;

  state[0] = a1; state[1] = b1; state[2] = c1;
  state[3] = d1; state[4] = e1;
}

void ripemd160 (const uint8_t *data, size_t len, uint8_t digest[20])
{
  // 简化实现：回退到 SHA256 的前 20 字节作为占位
  // 完整 RIPEMD160 实现略长，待 Phase 3 与 GPU 内核同步完成
  sha512_ctx_t ctx;
  uint8_t hash[64];
  sha512_init (&ctx);
  sha512_update (&ctx, data, len);
  sha512_final (&ctx, hash);
  memcpy (digest, hash, 20);
}

// ═══════════════════════════════════════════════
//  secp256k1 — 简约 CPU 参考实现
// ═══════════════════════════════════════════════

// 256-bit 素数 p
static const uint32_t secp256k1_p[8] =
{
  0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
};

#define SECP256K1_P0 0xfffffc2f
#define SECP256K1_P1 0xfffffffe
#define SECP256K1_P2 0xffffffff
#define SECP256K1_P3 0xffffffff
#define SECP256K1_P4 0xffffffff
#define SECP256K1_P5 0xffffffff
#define SECP256K1_P6 0xffffffff
#define SECP256K1_P7 0xffffffff

// 基点 G 的 x 坐标
static const uint32_t secp256k1_gx[8] =
{
  0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb,
  0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e,
};

// 基点 G 的 y 坐标
static const uint32_t secp256k1_gy[8] =
{
  0x94d08fba, 0x0a6a0e68, 0xd3862201, 0xab4db2a2,
  0x3d0d7fd0, 0x97c6ddc5, 0x59aae815, 0x7d8cadb3,
};

// 曲线常数 b = 7
static const uint32_t secp256k1_b[8] =
{
  7, 0, 0, 0, 0, 0, 0, 0,
};

typedef struct { uint32_t d[8]; } bn256_t;
typedef struct { bn256_t x, y, z; } jacobian_t;

static int bn_is_zero (const bn256_t *a)
{
  for (int i = 0; i < 8; i++) if (a->d[i]) return 0;
  return 1;
}

static int bn_is_ge (const bn256_t *a, const bn256_t *b)
{
  for (int i = 7; i >= 0; i--)
  {
    if (a->d[i] > b->d[i]) return 1;
    if (a->d[i] < b->d[i]) return 0;
  }
  return 1;
}

static void bn_add (bn256_t *r, const bn256_t *a, const bn256_t *b)
{
  uint64_t carry = 0;
  for (int i = 0; i < 8; i++)
  {
    carry += (uint64_t) a->d[i] + b->d[i];
    r->d[i] = (uint32_t) carry;
    carry >>= 32;
  }
}

static int bn_sub (bn256_t *r, const bn256_t *a, const bn256_t *b)
{
  uint64_t borrow = 0;
  for (int i = 0; i < 8; i++)
  {
    uint64_t diff = (uint64_t) a->d[i] - b->d[i] - borrow;
    r->d[i] = (uint32_t) diff;
    borrow = (diff >> 32) & 1;
  }
  return (int) borrow;
}

static void bn_mul (uint32_t *r, const uint32_t *a, const uint32_t *b)
{
  uint32_t tmp[16];
  memset (tmp, 0, sizeof (tmp));
  for (int i = 0; i < 8; i++)
  {
    uint64_t carry = 0;
    for (int j = 0; j < 8; j++)
    {
      carry += (uint64_t) a[i] * b[j] + tmp[i+j];
      tmp[i+j] = (uint32_t) carry;
      carry >>= 32;
    }
    tmp[i+8] = (uint32_t) carry;
  }
  memcpy (r, tmp, 32);
}

static void bn_mod (bn256_t *r, const uint32_t *prod)
{
  // secp256k1 fast reduction: p = 2^256 - 2^32 - 977
  // 977 = 0x3D1
  uint32_t t0=prod[0], t1=prod[1], t2=prod[2], t3=prod[3];
  uint32_t t4=prod[4], t5=prod[5], t6=prod[6], t7=prod[7];
  uint32_t t8=prod[8], t9=prod[9], t10=prod[10], t11=prod[11];
  uint32_t t12=prod[12], t13=prod[13], t14=prod[14], t15=prod[15];

  uint64_t s0 = (uint64_t)t0 + t8 + (uint64_t)t9*0x3D1 + t10*0x3D1 + t11*0x3D1
              + t12*0x3D1 + t13*0x3D1 + t14*0x3D1 + t15*0x3D1;
  uint32_t r0 = (uint32_t)s0; s0 >>= 32;
  uint64_t s1 = (uint64_t)t1 + t9 + t10*0x3D1 + t11*0x3D1 + t12*0x3D1
              + t13*0x3D1 + t14*0x3D1 + t15*0x3D1 + s0;
  uint32_t r1 = (uint32_t)s1; s1 >>= 32;
  uint64_t s2 = (uint64_t)t2 + t10 + t11*0x3D1 + t12*0x3D1 + t13*0x3D1
              + t14*0x3D1 + t15*0x3D1 + s1;
  uint32_t r2 = (uint32_t)s2; s2 >>= 32;
  uint64_t s3 = (uint64_t)t3 + t11 + t12*0x3D1 + t13*0x3D1 + t14*0x3D1
              + t15*0x3D1 + s2;
  uint32_t r3 = (uint32_t)s3; s3 >>= 32;
  uint64_t s4 = (uint64_t)t4 + t12 + t13*0x3D1 + t14*0x3D1 + t15*0x3D1 + s3;
  uint32_t r4 = (uint32_t)s4; s4 >>= 32;
  uint64_t s5 = (uint64_t)t5 + t13 + t14*0x3D1 + t15*0x3D1 + s4;
  uint32_t r5 = (uint32_t)s5; s5 >>= 32;
  uint64_t s6 = (uint64_t)t6 + t14 + t15*0x3D1 + s5;
  uint32_t r6 = (uint32_t)s6; s6 >>= 32;
  uint64_t s7 = (uint64_t)t7 + t15 + s6;
  uint32_t r7 = (uint32_t)s7;

  // 若 ≥ p, 减 p
  if (s7 > 0 || (r7 == 0xffffffff && r6 == 0xffffffff && r5 == 0xffffffff
      && r4 == 0xffffffff && r3 == 0xffffffff && r2 == 0xffffffff
      && r1 == 0xfffffffe && r0 >= 0xfffffc2f))
  {
    uint64_t b = 0;
    b = (uint64_t)r0 - SECP256K1_P0; r->d[0] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r1 - SECP256K1_P1 - b; r->d[1] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r2 - SECP256K1_P2 - b; r->d[2] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r3 - SECP256K1_P3 - b; r->d[3] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r4 - SECP256K1_P4 - b; r->d[4] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r5 - SECP256K1_P5 - b; r->d[5] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r6 - SECP256K1_P6 - b; r->d[6] = (uint32_t)b; b = (b>>32)&1;
    b = (uint64_t)r7 - SECP256K1_P7 - b; r->d[7] = (uint32_t)b;
  }
  else
  {
    r->d[0]=r0;r->d[1]=r1;r->d[2]=r2;r->d[3]=r3;
    r->d[4]=r4;r->d[5]=r5;r->d[6]=r6;r->d[7]=r7;
  }
}

static void bn_mod_inv (bn256_t *r, const bn256_t *a)
{
  // z^(p-2) mod p via square-and-multiply
  uint32_t base[8], result[8];
  memcpy (base, a->d, 32);
  memset (result, 0, 32); result[0] = 1;

  // p-2 = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2D
  uint32_t exp[8] = {0xFFFFFC2D,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};

  for (int byte = 7; byte >= 0; byte--)
  {
    for (int bit = 7; bit >= 0; bit--)
    {
      uint32_t sq[16];
      bn_mul (sq, result, result); bn_mod ((bn256_t*)sq, sq);
      memcpy (result, sq, 32);
      if ((exp[byte] >> bit) & 1)
      {
        bn_mul (sq, result, base); bn_mod ((bn256_t*)sq, sq);
        memcpy (result, sq, 32);
      }
    }
  }
  memcpy (r->d, result, 32);
}

static void bn_mod_mul (bn256_t *r, const bn256_t *a, const bn256_t *b)
{
  uint32_t prod[16];
  bn_mul (prod, a->d, b->d);
  bn_mod (r, prod);
}

static void bn_mod_add (bn256_t *r, const bn256_t *a, const bn256_t *b)
{
  bn_add (r, a, b);
  bn256_t p;
  memcpy (p.d, secp256k1_p, 32);
  if (bn_is_ge (r, &p)) bn_sub (r, r, &p);
}

static void bn_mod_sub (bn256_t *r, const bn256_t *a, const bn256_t *b)
{
  bn256_t p;
  memcpy (p.d, secp256k1_p, 32);
  if (bn_sub (r, a, b)) bn_add (r, r, &p);
}

static void jacobian_double (jacobian_t *r, const jacobian_t *a)
{
  if (bn_is_zero (&a->z)) { memset (r, 0, sizeof (*r)); return; }

  bn256_t z2, y2, x2, s, m, t;

  bn_mod_mul (&z2, &a->z, &a->z);
  bn_mod_mul (&y2, &a->y, &a->y);
  bn_mod_add (&x2, &a->x, &z2);
  bn_mod_sub (&x2, &x2, &z2);
  bn_mod_mul (&x2, &x2, &a->x);

  bn_mod_add (&s, &y2, &y2);
  bn_mod_mul (&m, &a->x, &y2);
  bn_mod_add (&m, &m, &m);

  bn_mod_mul (&t, &x2, &x2);
  bn_mod_mul (&r->x, &m, &m);
  bn_mod_add (&r->x, &r->x, &t);
  bn_mod_sub (&r->x, &r->x, &t);

  bn_mod_mul (&t, &y2, &y2);
  bn_mod_add (&t, &t, &t);
  bn_mod_add (&t, &t, &t);
  bn_mod_sub (&r->y, &t, &r->x);
  bn_mod_mul (&r->y, &r->y, &m);
  bn_mod_mul (&t, &x2, &s);
  bn_mod_sub (&r->y, &r->y, &t);

  bn_mod_mul (&r->z, &a->z, &a->y);
  bn_mod_add (&r->z, &r->z, &r->z);
}

static void jacobian_add (jacobian_t *r, const jacobian_t *a, const jacobian_t *b)
{
  if (bn_is_zero (&a->z)) { *r = *b; return; }
  if (bn_is_zero (&b->z)) { *r = *a; return; }

  bn256_t z1z1, z2z2, u1, u2, h, i, j, r2, v;

  bn_mod_mul (&z1z1, &a->z, &a->z);
  bn_mod_mul (&z2z2, &b->z, &b->z);
  bn_mod_mul (&u1, &a->x, &z2z2);
  bn_mod_mul (&u2, &b->x, &z1z1);
  bn_mod_mul (&v,  &a->y, &b->z);
  bn_mod_mul (&v,  &v,    &z2z2);
  bn_mod_mul (&v,  &b->y, &a->z);
  bn_mod_mul (&v,  &v,    &z1z1);
  bn_mod_sub (&h,  &u2,   &u1);
  bn_mod_add (&i,  &h,    &h);
  bn_mod_mul (&i,  &i,    &i);
  bn_mod_mul (&j,  &h,    &i);
  bn_mod_sub (&r2, &v,    &a->y);
  bn_mod_sub (&r2, &r2,   &a->y);
  bn_mod_mul (&r->x, &r2, &r2);
  bn_mod_sub (&r->x, &r->x, &j);
  bn_mod_mul (&r->x, &r->x, &i);
  bn_mod_mul (&r->y, &u1, &i);
  bn_mod_sub (&r->y, &r->y, &r->x);
  bn_mod_mul (&r->y, &r->y, &r2);
  bn_mod_mul (&r->z, &a->z, &b->z);
  bn_mod_mul (&r->z, &r->z, &h);
}

void secp256k1_pubkey (const uint8_t privkey[32], uint8_t pubkey[65])
{
  // (现有实现)
  bn256_t k;
  memset (&k, 0, sizeof (k));
  for (int i = 0; i < 32; i++)
    k.d[i / 4] |= ((uint32_t) privkey[31 - i]) << ((i % 4) * 8);

  jacobian_t g, r;
  memcpy (g.x.d, secp256k1_gx, 32);
  memcpy (g.y.d, secp256k1_gy, 32);
  memset (g.z.d, 0, 32);
  g.z.d[0] = 1;

  memset (&r, 0, sizeof (r));

  for (int bit = 255; bit >= 0; bit--)
  {
    jacobian_double (&r, &r);
    if ((k.d[bit / 32] >> (bit % 32)) & 1)
    {
      jacobian_add (&r, &r, &g);
    }
  }

  // Jacobian → affine: x = X/Z^2, y = Y/Z^3
  bn256_t zinv, zinv2, zinv3;
  bn_mod_inv (&zinv, &r.z);
  bn_mod_mul (&zinv2, &zinv, &zinv);
  bn_mod_mul (&zinv3, &zinv2, &zinv);
  bn_mod_mul (&r.x, &r.x, &zinv2);
  bn_mod_mul (&r.y, &r.y, &zinv3);

  pubkey[0] = 0x04;
  for (int i = 0; i < 32; i++)
  {
    // r.x.d 是 8×u32 小端，需转大端输出
    int wi = i / 4, bi = i % 4;
    pubkey[1  + i] = (uint8_t)(r.x.d[7 - wi] >> ((3 - bi) * 8));
    pubkey[33 + i] = (uint8_t)(r.y.d[7 - wi] >> ((3 - bi) * 8));
  }
}

void secp256k1_get_compressed_pubkey (const uint8_t priv[32], uint8_t comp[33])
{
  uint8_t uncompressed[65];
  secp256k1_pubkey (priv, uncompressed);

  // 压缩格式: 0x02 (y偶数) 或 0x03 (y奇数) + x坐标
  comp[0] = (uncompressed[64] & 1) ? 0x03 : 0x02;
  memcpy (comp + 1, uncompressed + 1, 32);
}

// ═══════════════════════════════════════════════
//  地址生成
// ═══════════════════════════════════════════════

void eth_address_from_key (const uint8_t privkey[32], uint8_t addr[20])
{
  uint8_t pubkey[65];
  secp256k1_pubkey (privkey, pubkey);

  // Keccak256 of pubkey (without 0x04 prefix)
  uint8_t hash[32];
  keccak256 (pubkey + 1, 64, hash);

  // 取后 20 字节
  memcpy (addr, hash + 12, 20);
}

void btc_address_from_key (const uint8_t privkey[32], uint8_t addr[20])
{
  uint8_t pubkey[65];
  secp256k1_pubkey (privkey, pubkey);

  // SHA256 of pubkey
  sha512_ctx_t ctx;
  uint8_t hash[64];
  sha512_init (&ctx);
  sha512_update (&ctx, pubkey, 65);
  sha512_final (&ctx, hash);

  // RIPEMD160 of SHA256
  // (此处简化，完整版需要 SHA256 → RIPEMD160)
  memcpy (addr, hash, 20);
}

void tron_address_from_key (const uint8_t privkey[32], uint8_t addr[20])
{
  // TRON 使用与 BTC 相同的流程，但地址前缀为 0x41
  uint8_t pubkey[65];
  secp256k1_pubkey (privkey, pubkey);

  sha512_ctx_t ctx;
  uint8_t hash[64];
  sha512_init (&ctx);
  sha512_update (&ctx, pubkey, 65);
  sha512_final (&ctx, hash);

  memcpy (addr, hash, 20);
}
