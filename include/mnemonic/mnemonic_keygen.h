#ifndef MNEMONIC_KEYGEN_H
#define MNEMONIC_KEYGEN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ── secp256k1 公钥生成 ──
// privkey: 32 字节私钥 (big-endian)
// pubkey:  65 字节未压缩公钥 (0x04 || x || y)
void secp256k1_pubkey (const uint8_t privkey[32], uint8_t pubkey[65]);

// ── 地址生成 ──
// 输入: 32 字节私钥
// 输出: 原始地址字节 (ETH/BTC/TRON 均为 20 字节)

void eth_address_from_key    (const uint8_t privkey[32], uint8_t addr[20]);
void btc_address_from_key    (const uint8_t privkey[32], uint8_t addr[20]);
void tron_address_from_key   (const uint8_t privkey[32], uint8_t addr[20]);

// ── Keccak256 ──
void keccak256 (const uint8_t *data, size_t len, uint8_t digest[32]);

// ── RIPEMD160 ──
void ripemd160 (const uint8_t *data, size_t len, uint8_t digest[20]);

#endif
