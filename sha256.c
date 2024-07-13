#include "sha.h"

typedef uint_32 uint32_t;

const uint32_t sha256_K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

int sha256_init(sha256_ctx *c)
{
    c->h[0] = 0x6A09E667UL;
    c->h[1] = 0xBB67AE85UL;
    c->h[2] = 0x3C6EF372UL;
    c->h[3] = 0xA54FF53AUL;
    c->h[4] = 0x510E527FUL;
    c->h[5] = 0x9B05688CUL;
    c->h[6] = 0x1F83D9ABUL;
    c->h[7] = 0x5BE0CD19UL;
    c->n = 0;
    c->num = 0;
    c->md_len = SHA256_DIGEST_LENGTH;
    return 1;
}

/* 6个函数 */
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22))
#define Sigma1(x) (ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25))
#define sigma0(x) (ror32(x, 7) ^ ror32(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ror32(x, 17) ^ ror32(x, 19) ^ ((x) >> 10))

/* 分块计算 */
void SHA256BlockCal(sha256_ctx *ctx, const void *msg, size_t num)
{
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2, i, w[16];
    const uint32_t *m = (const uint32_t *)msg;

    while (num--) {
        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];
        for (i = 0; i < 16; ++i) {
            t1 = w[i] = bswap_32(m[i]);
            t1 += h + Sigma1(e) + Ch(e, f, g) + sha256_K[i];
            t2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        for (; i < 64; ++i) {
            t1 = w[i & 0xf] += sigma1(w[(i + 14) & 0xf]) + w[(i + 9) & 0xf] + sigma0(w[(i + 1) & 0xf]);
            t1 += h + Sigma1(e) + Ch(e, f, g) + sha256_K[i];
            t2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        m += (sizeof(ctx->data) / sizeof(uint32_t));
    }
}

int sha256_update(sha256_ctx *c, const void *msg, size_t len)
{
    uint_32 l;
    unsigned char *p = (unsigned char *)c->data;
    const unsigned char *data = (const unsigned char *)msg;

    if (len == 0)
        return 0;
    l = c->n + (len << 3);
    if (l < c->n) { /* 超出最大数据量 */
        return 0;
    }
    c->n = l;
    if (c->num != 0) {
        size_t n = sizeof(c->data) - c->num;
        if (len < n) {
            memcpy(p + c->num, data, len);
            return 1;
        } else {
            memcpy(p + c->num, data, n);
            len -= n;
            data += n;
            SHA256BlockCal(c, c->data, 1);
        }
    }
    if (len >= sizeof(c->data)) {
        SHA256BlockCal(c, data, len / sizeof(c->data));
        data += len;
        len %= sizeof(c->data);
        data -= len;
    }
    /* 数据不够一个块，记录到c.data中，等待下次输入 */
    if (len != 0) {
        memcpy(c->data, data, len);
        c->num = len;
    }
    return 1;
}

int sha256_final(unsigned char *md, sha256_ctx *ctx)
{
    unsigned char *p = (unsigned char *)ctx->data;
    size_t n = ctx->num;

    /* 在数据最后一位加1 */
    p[n] = 0x80;
    n++;

    /* 数据末尾要预留128位=16字节 */
    if (n > (sizeof(ctx->data) - 16)) {
        memset(p + n, 0, sizeof(ctx->data) - n);
        n = 0;
        SHA256BlockCal(ctx, p, 1);
    }

    memset(p + n, 0, sizeof(ctx->data) - n - 8);
    /* 小端存储 */
    p[sizeof(ctx->data) - 1] = (unsigned char)(ctx->n);
    p[sizeof(ctx->data) - 2] = (unsigned char)(ctx->n >> 8);
    p[sizeof(ctx->data) - 3] = (unsigned char)(ctx->n >> 16);
    p[sizeof(ctx->data) - 4] = (unsigned char)(ctx->n >> 24);
    p[sizeof(ctx->data) - 5] = (unsigned char)(ctx->n >> 32);
    p[sizeof(ctx->data) - 6] = (unsigned char)(ctx->n >> 40);
    p[sizeof(ctx->data) - 7] = (unsigned char)(ctx->n >> 48);
    p[sizeof(ctx->data) - 8] = (unsigned char)(ctx->n >> 56);

    SHA256BlockCal(ctx, p, 1);

    if (md == NULL) {
        return 0;
    }

    switch (ctx->md_len) {
    case SHA224_DIGEST_LENGTH:
        for (n = 0; n < SHA224_DIGEST_LENGTH / sizeof(uint_32); n++) {
            uint_32 t = ctx->h[n];

            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    case SHA256_DIGEST_LENGTH:
        for (n = 0; n < SHA256_DIGEST_LENGTH / sizeof(uint_32); n++) {
            uint_32 t = ctx->h[n];

            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    default:
        return 0;
    }

    return 1;
}

/*
 * sha512: 根据输入数据生成摘要
 * msg: 原始数据
 * len: 数据长度，单位字节
 * md: 摘要
 * 返回值: 0表示发生错误，不等于0表示工作正常
 */
unsigned char *sha256(const void *msg, size_t len, unsigned char *md)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    if (sha256_update(&ctx, msg, len)) {
        if (sha256_final(md, &ctx)) {
            return md;
        }
    }
    return 0;
}