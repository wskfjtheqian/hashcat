#include "mnemonic/mnemonic_address.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ── Hex 解码 ──
static int hex_char (char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_decode (const char *hex, uint8_t *out, int out_len)
{
  int len = (int) strlen (hex);
  if (len > out_len * 2) return -1;

  for (int i = 0; i < len / 2; i++)
  {
    int hi = hex_char (hex[i * 2]);
    int lo = hex_char (hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t) ((hi << 4) | lo);
  }

  return len / 2;
}

// ── Base58 解码 ──
static const char *b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int b58_decode (const char *b58, uint8_t *out, int out_size)
{
  // 计数前导 '1' 的数量
  int zeros = 0;
  while (*b58 == '1') { zeros++; b58++; }

  int len = (int) strlen (b58);
  // 分配临时大数缓冲区（每个 base58 字符约 1.365 字节）
  int tmp_size = len * 2;
  uint8_t *tmp = (uint8_t *) calloc (tmp_size, 1);
  if (tmp == NULL) return -1;

  for (int i = 0; i < len; i++)
  {
    const char *p = strchr (b58_alphabet, b58[i]);
    if (p == NULL) { free (tmp); return -1; }

    int carry = (int) (p - b58_alphabet);
    for (int j = tmp_size - 1; j >= 0; j--)
    {
      carry += (int) tmp[j] * 58;
      tmp[j] = (uint8_t) (carry & 0xFF);
      carry >>= 8;
    }

    if (carry != 0) { free (tmp); return -1; }
  }

  // 找起始位置（跳过前导零字节）
  int start = 0;
  while (start < tmp_size && tmp[start] == 0) start++;

  int result_len = tmp_size - start;

  if (result_len + zeros > out_size) { free (tmp); return -1; }

  memset (out, 0, zeros);
  memcpy (out + zeros, tmp + start, result_len);

  free (tmp);

  return result_len + zeros;
}

// ── Bech32 解码 ──
static const char *bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int bech32_decode (const char *hrp_exp, const char *bech32, uint8_t *data, int data_size)
{
  (void) data_size; // 简化实现

  // 查找分隔符 '1'
  const char *sep = strrchr (bech32, '1');
  if (sep == NULL) return -1;

  // 验证 HRP
  int hrp_len = (int) (sep - bech32);
  if (strncmp (bech32, hrp_exp, hrp_len) != 0) return -1;

  // 解码数据部分
  const char *d = sep + 1;
  int dlen = (int) strlen (d);
  if (dlen < 6) return -1;

  // 5-bit → 8-bit 转换
  int out_len = (dlen - 6) * 5 / 8;
  if (out_len > 32) return -1;

  // 简化：只做基本解码，不验证校验和（地址文件中的地址假设有效）
  int bits  = 0;
  int bytes = 0;

  for (int i = 0; i < dlen - 6; i++)
  {
    const char *p = strchr (bech32_charset, d[i]);
    if (p == NULL) return -1;

    bits = (bits << 5) | (int) (p - bech32_charset);
    bytes += 5;

    while (bytes >= 8)
    {
      bytes -= 8;
      if (out_len > 0) data[out_len - (bytes / 8) - 1] = (uint8_t) (bits >> bytes);
      bits &= (1 << bytes) - 1;
    }
  }

  return out_len;
}

// ── ETH 地址 ──
int address_decode_eth (const char *addr_str, target_address_t *out)
{
  if (addr_str == NULL || out == NULL) return -1;

  const char *hex = addr_str;
  if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;

  if (strlen (hex) != 40) return -1;

  memset (out, 0, sizeof (target_address_t));

  if (hex_decode (hex, out->raw, 20) != 20) return -1;

  return 0;
}

// ── BTC 地址 ──
int address_decode_btc (const char *addr_str, target_address_t *out)
{
  if (addr_str == NULL || out == NULL) return -1;

  memset (out, 0, sizeof (target_address_t));

  if (addr_str[0] == '1' || addr_str[0] == '3')
  {
    // Base58Check: 解码 → 去掉 1 字节版本前缀 + 4 字节校验后缀
    uint8_t buf[25];
    int     len = b58_decode (addr_str, buf, 25);
    if (len != 25) return -1;

    memcpy (out->raw, buf + 1, 20);

    return 0;
  }

  if (strncmp (addr_str, "bc1q", 4) == 0)
  {
    // Bech32 (P2WPKH)
    return bech32_decode ("bc", addr_str, out->raw, 32);
  }

  if (strncmp (addr_str, "bc1p", 4) == 0)
  {
    // Bech32m (P2TR) - 回退到 Bech32 解码
    return bech32_decode ("bc", addr_str, out->raw, 32);
  }

  return -1;
}

// ── TRON 地址 ──
int address_decode_tron (const char *addr_str, target_address_t *out)
{
  if (addr_str == NULL || out == NULL) return -1;

  if (addr_str[0] != 'T') return -1;

  memset (out, 0, sizeof (target_address_t));

  uint8_t buf[25];
  int     len = b58_decode (addr_str, buf, 25);
  if (len != 25) return -1;
  if (buf[0] != 0x41) return -1;  // TRON 版本字节

  memcpy (out->raw, buf + 1, 20);

  return 0;
}

// ── 自动检测 ──
int address_decode_auto (const char *addr_str, target_address_t *out, address_type_t *type)
{
  if (addr_str == NULL || out == NULL) return -1;

  if (addr_str[0] == '0' && (addr_str[1] == 'x' || addr_str[1] == 'X'))
  {
    if (type != NULL) *type = ADDR_ETH;
    return address_decode_eth (addr_str, out);
  }

  if (addr_str[0] == '1')
  {
    if (type != NULL) *type = ADDR_BTC_P2PKH;
    return address_decode_btc (addr_str, out);
  }

  if (addr_str[0] == '3')
  {
    if (type != NULL) *type = ADDR_BTC_P2SH_P2WPKH;
    return address_decode_btc (addr_str, out);
  }

  if (strncmp (addr_str, "bc1", 3) == 0)
  {
    if (type != NULL) *type = ADDR_BTC_P2WPKH;
    return address_decode_btc (addr_str, out);
  }

  if (addr_str[0] == 'T')
  {
    if (type != NULL) *type = ADDR_TRON;
    return address_decode_tron (addr_str, out);
  }

  if (addr_str[0] == 'D')
  {
    if (type != NULL) *type = ADDR_DOGE;
    // DOGE 也用 Base58Check
    uint8_t buf[25];
    int     len = b58_decode (addr_str, buf, 25);
    if (len != 25) return -1;
    memcpy (out->raw, buf + 1, 20);
    return 0;
  }

  return -1;
}

// ── 地址文件解析 ──
int address_file_parse (const char *filepath, target_address_list_t *out)
{
  if (filepath == NULL || out == NULL) return -1;

  memset (out, 0, sizeof (target_address_list_t));

  FILE *fp = fopen (filepath, "r");
  if (fp == NULL) return -1;

  // 先数行数
  char  line[256];
  int   count = 0;

  while (fgets (line, sizeof (line), fp) != NULL) count++;
  rewind (fp);

  if (count == 0) { fclose (fp); return -1; }

  out->addrs = (target_address_t *) calloc (count, sizeof (target_address_t));
  if (out->addrs == NULL) { fclose (fp); return -1; }

  out->count = 0;
  out->index_start = 0;
  out->index_end   = 0;

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    // 去除末尾换行
    size_t len = strlen (line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';

    if (len == 0 || line[0] == '#') continue;

    address_type_t type;
    if (address_decode_auto (line, &out->addrs[out->count], &type) != 0)
    {
      fprintf (stderr, "address_file_parse: invalid address: %s\n", line);
      fclose (fp);
      address_list_destroy (out);
      return -1;
    }

    if (out->count == 0)
    {
      out->chain = type;
    }
    else if (out->chain != type)
    {
      fprintf (stderr, "address_file_parse: all addresses must be same chain type\n");
      fclose (fp);
      address_list_destroy (out);
      return -1;
    }

    out->count++;
  }

  fclose (fp);

  // 设置 BIP44 coin_type
  switch (out->chain)
  {
    case ADDR_ETH:             out->coin_type = 60;  break;
    case ADDR_BTC_P2PKH:
    case ADDR_BTC_P2SH_P2WPKH:
    case ADDR_BTC_P2WPKH:      out->coin_type = 0;   break;
    case ADDR_TRON:            out->coin_type = 195; break;
    case ADDR_DOGE:            out->coin_type = 3;   break;
    default:                   out->coin_type = 0;   break;
  }

  return 0;
}

void address_list_destroy (target_address_list_t *list)
{
  if (list == NULL) return;

  free (list->addrs);
  list->addrs = NULL;

  memset (list, 0, sizeof (target_address_list_t));
}
