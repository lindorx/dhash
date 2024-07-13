#ifndef _HWLITEOS_CRYPTO_SM3_H
#define _HWLITEOS_CRYPTO_SM3_H
#include <string.h>
#include <byteswap.h>

#include "types.h"
#include "bitops.h"

#define SM3_LBLOCK (16)
#define SM3_DIGEST_LENGTH (32)

typedef struct sm3_context {
    uint_32 h[8];                    /* 初始向量 */
    uint_64 n;                       /* 存储已经处理的数据长度，最大长度为2^128，nl存储低64位，nh存储高64位 */
    uint_32 data[SM3_LBLOCK];        /* 存储一轮需要处理的数据，如果本轮数据没有处理完，剩余不足512位，则也存在这里 */
    unsigned int num;               /* 记录当前块尚未处理的数据量 */
} Sm3Ctx;

int SM3Init(Sm3Ctx *c);
int SM3Update(Sm3Ctx *c, const void *msg, size_t len);
int SM3Final(unsigned char *md, Sm3Ctx *c);
unsigned char *SM3(const void *msg, size_t len, unsigned char* md);


#endif /* _HWLITEOS_CRYPTO_SM3_H */