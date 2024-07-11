#include "sha.h"

/*
 * SHA512Init: 初始化信息结构
 * ctx: sha512信息结构
 */
int SHA384Init(SHA384Ctx *ctx)
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
    ctx->md_len=SHA384_DIGEST_LENGTH;
    return 1;
}

int SHA384Update(SHA384Ctx *ctx,const void *msg, size_t len)
{
    return SHA512Update((SHA512Ctx*)ctx, msg, len);
}

int SHA384Final(unsigned char *md, SHA384Ctx *ctx)
{
    return SHA512Final(md, (SHA512Ctx*)ctx);
}

unsigned char *SHA384(const void *msg, size_t len, unsigned char* md)
{
    SHA384Ctx ctx;

    SHA384Init(&ctx);
    if (SHA384Update(&ctx, msg, len)) {
        if (SHA384Final(md, &ctx)) {
            return md;
        }
    }
    return md;
}
