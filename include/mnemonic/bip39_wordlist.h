#ifndef BIP39_WORDLIST_H
#define BIP39_WORDLIST_H

#include "mnemonic/mnemonic_types.h"

int         bip39_wordlist_init       (bip39_wordlist_t *list, bip39_language_t lang);
void        bip39_wordlist_destroy    (bip39_wordlist_t *list);
uint16_t    bip39_wordlist_lookup_idx (bip39_wordlist_t *list, const char *word);
const char* bip39_wordlist_lookup_word(bip39_wordlist_t *list, uint16_t index);
const char* bip39_language_name       (bip39_language_t lang);
const char* bip39_language_separator  (bip39_language_t lang);

#endif
