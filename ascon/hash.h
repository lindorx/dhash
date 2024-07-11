#ifndef _HWLITEOS_CRYPTO_ASCON_HASH_H
#define _HWLITEOS_CRYPTO_ASCON_HASH_H

#define LOSCFG_CRYPTO_ASCON_HASH

#include <string.h>
#include <byteswap.h>

#include "los_compiler.h"
#include "bitops.h"
#include "config.h"

typedef union {
  UINT64 x[5];
  UINT64 w[5][2];
  UINT8 b[5][8];
} AsconState;

#define CRYPTO_BYTES 32

#endif /* _HWLITEOS_CRYPTO_ASCON_HASH_H */