#ifndef MNEMONIC_FUZZY_H
#define MNEMONIC_FUZZY_H

#include "mnemonic/mnemonic_types.h"

int  mnemonic_fuzzy_parse  (mnemonic_candidates_t *mc, bip39_wordlist_t *wl,
                            const char *filename);
void mnemonic_fuzzy_destroy(mnemonic_candidates_t *mc);

#endif
