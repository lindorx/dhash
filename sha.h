#ifndef _HWLITEOS_CRYPTO_SHA_H
#define _HWLITEOS_CRYPTO_SHA_H
#include <string.h>
#include <byteswap.h>

#include "los_compiler.h"
#include "bitops.h"

#define SHA224_DIGEST_LENGTH (28)
#define SHA256_DIGEST_LENGTH (32)
#define SHA384_DIGEST_LENGTH (48)
#define SHA512_DIGEST_LENGTH (64)

#define B(x, j)     (((UINT64)(*(((const unsigned char *)(&x)) + j))) << ((7 - j) * 8))
#define PULL64(x)   (B(x, 0) | B(x, 1) | B(x, 2) | B(x, 3) | B(x, 4) | B(x, 5) | B(x, 6) | B(x, 7))

/* 摘要长度，16*8字节 */
#define SHA_LBLOCK 16

typedef struct sha256_context {
    UINT32 h[8];
    UINT64 n;
    UINT32 data[SHA_LBLOCK];
    unsigned int num;
    unsigned int md_len;
} SHA256Ctx, SHA224Ctx;

typedef struct sha512_context {
    UINT64 h[8];                    /* 初始向量 */
    UINT64 nl, nh;                  /* 存储已经处理的数据长度，最大长度为2^128，nl存储低64位，nh存储高64位 */
    UINT64 data[SHA_LBLOCK];        /* 存储一轮需要处理的数据，如果本轮数据没有处理完，剩余不足1024位，则也存在这里 */
    unsigned int num;               /* 记录当前块尚未处理的数据量 */
    unsigned int md_len;            /* 要截取摘要的长度 */
} SHA512Ctx, SHA384Ctx;

int SHA224Init(SHA224Ctx *ctx);
int SHA224Update(SHA224Ctx *ctx,const void *msg, size_t len);
int SHA224Final(unsigned char *md, SHA224Ctx *ctx);
unsigned char *SHA224(const void *msg, size_t len, unsigned char* md);

int SHA256Init(SHA256Ctx *c);
int SHA256Update(SHA256Ctx *c, const void *msg, size_t len);
int SHA256Final(unsigned char *md, SHA256Ctx *ctx);
unsigned char *SHA256(const void *msg, size_t len, unsigned char *md);

int SHA384Init(SHA384Ctx *ctx);
int SHA384Update(SHA384Ctx *ctx,const void *msg, size_t len);
int SHA384Final(unsigned char *md, SHA384Ctx *ctx);
unsigned char *SHA384(const void *msg, size_t len, unsigned char* md);

int SHA512Init(SHA512Ctx *ctx);
int SHA512Update(SHA512Ctx *ctx,const void *msg, size_t len);
int SHA512Final(unsigned char *md, SHA512Ctx *ctx);
unsigned char *SHA512(const void *msg, size_t len, unsigned char* md);

#endif /* _HWLITEOS_CRYPTO_SHA_H */