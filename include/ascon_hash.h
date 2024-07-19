#ifndef _DHASH_CRYPTO_ASCON_HASH_H
#define _DHASH_CRYPTO_ASCON_HASH_H

#define LOSCFG_CRYPTO_ASCON_HASH

#include <string.h>
#include <byteswap.h>

#include <types.h>
#include <bitops.h>

typedef union
{
  uint_64 x[5];
  uint_64 w[5][2];
  uint_8 b[5][8];
} ascon_state;

#define CRYPTO_BYTES 32

#endif /* _DHASH_CRYPTO_ASCON_HASH_H */
