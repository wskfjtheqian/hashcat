#ifndef MNEMONIC_ADDRESS_H
#define MNEMONIC_ADDRESS_H

#include "mnemonic/mnemonic_types.h"

int  address_decode_eth  (const char *addr_str, target_address_t *out);
int  address_decode_btc  (const char *addr_str, target_address_t *out);
int  address_decode_tron (const char *addr_str, target_address_t *out);
int  address_decode_auto (const char *addr_str, target_address_t *out, address_type_t *type);
int  address_file_parse  (const char *filepath, target_address_list_t *out);
void address_list_destroy(target_address_list_t *list);

#endif
