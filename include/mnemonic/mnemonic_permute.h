#ifndef MNEMONIC_PERMUTE_H
#define MNEMONIC_PERMUTE_H

#include "mnemonic/mnemonic_types.h"

int  perm_iterator_init   (perm_iterator_t *it, mnemonic_candidates_t *mc, uint32_t batch_size);
int  perm_iterator_next   (perm_iterator_t *it);
void perm_iterator_destroy(perm_iterator_t *it);

#endif
