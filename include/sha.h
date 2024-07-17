#ifndef _DHASH_CRYPTO_SHA_H
#define _DHASH_CRYPTO_SHA_H
#include <string.h>
#include <byteswap.h>

#include "types.h"
#include "bitops.h"

#define SHA224_DIGEST_LENGTH (28)
#define SHA256_DIGEST_LENGTH (32)
#define SHA384_DIGEST_LENGTH (48)
#define SHA512_DIGEST_LENGTH (64)

#define B(x, j) (((uint_64)(*(((const unsigned char *)(&x)) + j))) << ((7 - j) * 8))
#define PULL64(x) (B(x, 0) | B(x, 1) | B(x, 2) | B(x, 3) | B(x, 4) | B(x, 5) | B(x, 6) | B(x, 7))

/* 摘要长度，16*8字节 */
#define SHA_LBLOCK 16

typedef struct sha256_context
{
    uint_32 h[8];
    uint_64 n;
    uint_32 data[SHA_LBLOCK];
    unsigned int num;
    unsigned int md_len;
} sha256_ctx, sha224_ctx;

typedef struct sha512_context
{
    uint_64 h[8];             /* 初始向量 */
    uint_64 nl, nh;           /* 存储已经处理的数据长度，最大长度为2^128，nl存储低64位，nh存储高64位 */
    uint_64 data[SHA_LBLOCK]; /* 存储一轮需要处理的数据，如果本轮数据没有处理完，剩余不足1024位，则也存在这里 */
    unsigned int num;         /* 记录当前块尚未处理的数据量 */
    unsigned int md_len;      /* 要截取摘要的长度 */
} sha512_ctx, sha384_ctx;

int sha224_init(sha224_ctx *ctx);
int sha224_update(sha224_ctx *ctx, const void *msg, size_t len);
int sha224_final(unsigned char *md, sha224_ctx *ctx);
unsigned char *sha224(const void *msg, size_t len, unsigned char *md);

int sha256_init(sha256_ctx *c);
int sha256_update(sha256_ctx *c, const void *msg, size_t len);
int sha256_final(unsigned char *md, sha256_ctx *ctx);
unsigned char *sha256(const void *msg, size_t len, unsigned char *md);

int sha384_init(sha384_ctx *ctx);
int sha384_update(sha384_ctx *ctx, const void *msg, size_t len);
int sha384_final(unsigned char *md, sha384_ctx *ctx);
unsigned char *sha384(const void *msg, size_t len, unsigned char *md);

int sha512_init(sha512_ctx *ctx);
int sha512_update(sha512_ctx *ctx, const void *msg, size_t len);
int sha512_final(unsigned char *md, sha512_ctx *ctx);
unsigned char *sha512(const void *msg, size_t len, unsigned char *md);

#endif /* _DHASH_CRYPTO_SHA_H */
