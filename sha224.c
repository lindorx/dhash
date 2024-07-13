#include "sha.h"

int sha224_init(sha224_ctx *ctx)
{
    ctx->h[0] = 0xC1059ED8;
    ctx->h[1] = 0x367CD507;
    ctx->h[2] = 0x3070DD17;
    ctx->h[3] = 0xF70E5939;
    ctx->h[4] = 0xFFC00B31;
    ctx->h[5] = 0x68581511;
    ctx->h[6] = 0x64F98FA7;
    ctx->h[7] = 0xBEFA4FA4;
    ctx->n = 0;
    ctx->num = 0;
    ctx->md_len = SHA224_DIGEST_LENGTH;
    return 1;
}

int sha224_update(sha224_ctx *ctx, const void *msg, size_t len)
{
    return sha256_update((sha256_ctx *)ctx, msg, len);
}

int sha224_final(unsigned char *md, sha224_ctx *ctx)
{
    return sha256_final(md, (sha256_ctx *)ctx);
}

unsigned char *sha224(const void *msg, size_t len, unsigned char *md)
{
    sha224_ctx ctx;

    sha224_init(&ctx);
    if (sha224_update(&ctx, msg, len)) {
        if (sha224_final(md, &ctx)) {
            return md;
        }
    }
    return md;
}