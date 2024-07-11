#include "sha.h"

int SHA224Init(SHA224Ctx *ctx)
{
    ctx->h[0]=0xC1059ED8;
    ctx->h[1]=0x367CD507;
    ctx->h[2]=0x3070DD17;
    ctx->h[3]=0xF70E5939;
    ctx->h[4]=0xFFC00B31;
    ctx->h[5]=0x68581511;
    ctx->h[6]=0x64F98FA7;
    ctx->h[7]=0xBEFA4FA4;
    ctx->n=0;
    ctx->num=0;
    ctx->md_len = SHA224_DIGEST_LENGTH;
    return 1;
}

int SHA224Update(SHA224Ctx *ctx,const void *msg, size_t len)
{
    return SHA256Update((SHA256Ctx*)ctx, msg, len);
}

int SHA224Final(unsigned char *md, SHA224Ctx *ctx)
{
    return SHA256Final(md, (SHA256Ctx*)ctx);
}

unsigned char *SHA224(const void *msg, size_t len, unsigned char* md)
{
    SHA224Ctx ctx;

    SHA224Init(&ctx);
    if (SHA224Update(&ctx, msg, len)) {
        if (SHA224Final(md, &ctx)) {
            return md;
        }
    }
    return md;
}