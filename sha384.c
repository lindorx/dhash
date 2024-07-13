#include "sha.h"

/*
 * sha512_init: 初始化信息结构
 * ctx: sha512信息结构
 */
int sha384_init(sha384_ctx *ctx)
{
    ctx->h[0] = 0xCBBB9D5DC1059ED8ULL;
    ctx->h[1] = 0x629A292A367CD507ULL;
    ctx->h[2] = 0x9159015A3070DD17ULL;
    ctx->h[3] = 0x152FECD8F70E5939ULL;
    ctx->h[4] = 0x67332667FFC00B31ULL;
    ctx->h[5] = 0x8EB44A8768581511ULL;
    ctx->h[6] = 0xDB0C2E0D64F98FA7ULL;
    ctx->h[7] = 0x47B5481DBEFA4FA4ULL;
    ctx->nl = 0;
    ctx->nh = 0;
    ctx->num = 0;
    ctx->md_len = SHA384_DIGEST_LENGTH;
    return 1;
}

int sha384_update(sha384_ctx *ctx, const void *msg, size_t len)
{
    return sha512_update((sha512_ctx *)ctx, msg, len);
}

int sha384_final(unsigned char *md, sha384_ctx *ctx)
{
    return sha512_final(md, (sha512_ctx *)ctx);
}

unsigned char *sha384(const void *msg, size_t len, unsigned char *md)
{
    sha384_ctx ctx;

    sha384_init(&ctx);
    if (sha384_update(&ctx, msg, len)) {
        if (sha384_final(md, &ctx)) {
            return md;
        }
    }
    return md;
}
