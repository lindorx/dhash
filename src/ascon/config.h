#ifndef _DHASH_CRYPTO_ASCON_CONFIG_H
#define _DHASH_CRYPTO_ASCON_CONFIG_H

#include "constants.h"

#if defined(LOSCFG_CRYPTO_ASCON_HASH)
#define ASCON_HASH_BYTES 32
#define PnRounds P12Rounds
#define ASCON_IV0 ASCON_HASH_IV0
#define ASCON_IV1 ASCON_HASH_IV1
#define ASCON_IV2 ASCON_HASH_IV2
#define ASCON_IV3 ASCON_HASH_IV3
#define ASCON_IV4 ASCON_HASH_IV4

#elif defined(LOSCFG_CRYPTO_ASCON_HASHA)
#define ASCON_HASH_BYTES 32
#define PnRounds P8Rounds
#define ASCON_IV0 ASCON_HASHA_IV0
#define ASCON_IV1 ASCON_HASHA_IV1
#define ASCON_IV2 ASCON_HASHA_IV2
#define ASCON_IV3 ASCON_HASHA_IV3
#define ASCON_IV4 ASCON_HASHA_IV4

#elif defined(LOSCFG_CRYPTO_ASCON_XOF)
#define ASCON_HASH_BYTES 0
#define PnRounds P12Rounds
#define ASCON_IV0 ASCON_XOF_IV0
#define ASCON_IV1 ASCON_XOF_IV1
#define ASCON_IV2 ASCON_XOF_IV2
#define ASCON_IV3 ASCON_XOF_IV3
#define ASCON_IV4 ASCON_XOF_IV4

#elif defined(LOSCFG_CRYPTO_ASCON_XOFA)
#define ASCON_HASH_BYTES 0
#define PnRounds P8Rounds
#define ASCON_IV0 ASCON_XOFA_IV0
#define ASCON_IV1 ASCON_XOFA_IV1
#define ASCON_IV2 ASCON_XOFA_IV2
#define ASCON_IV3 ASCON_XOFA_IV3
#define ASCON_IV4 ASCON_XOFA_IV4

#endif

#endif /* _DHASH_CRYPTO_ASCON_CONFIG_H */
