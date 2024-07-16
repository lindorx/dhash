#include <sm3.h>

int sm3_init(sm3_ctx *c)
{
    c->h[0] = 0x7380166F;
    c->h[1] = 0x4914B2B9;
    c->h[2] = 0x172442D7;
    c->h[3] = 0xDA8A0600;
    c->h[4] = 0xA96F30BC;
    c->h[5] = 0x163138AA;
    c->h[6] = 0xE38DEE4D;
    c->h[7] = 0xB0FB0E4E;
    c->n = 0;
    c->num = 0;
    return 1;
}

#define FF_00_15(x, y, z) (x ^ y ^ z)
#define FF_16_63(x, y, z) ((x & y) | (x & z) | (y & z))

#define GG_00_15(x, y, z) (x ^ y ^ z)
#define GG_16_63(x, y, z) ((x & y) | ((~x) & z))

#define P_0(x) (x ^ rol32(x, 9) ^ rol32(x, 17))
#define P_1(x) (x ^ rol32(x, 15) ^ rol32(x, 23))

/* Block: 处理512位整数倍的数据
 * ctx: 指针
 * data: 数据地址
 * n: 要处理的块数
 */
static void SM3BlockCal(sm3_ctx *ctx, const void *data, size_t n)
{
    volatile uint_32 a, b, c, d, e, f, g, h;
    volatile uint_32 ss1, ss2, tt1, tt2;
    uint_32 w[68], w1[64], i;
    uint_32 *p = (uint_32 *)data;

    while (n--) {
        /* 大端化处理 */
        for (i = 0; i < 16; ++i) {
            w[i] = bswap_32(p[i]);
        }
        /* 分组 */
        for (; i < 68; ++i) {
            w[i] = P_1(w[i - 16] ^ w[i - 9] ^ rol32(w[i - 3], 15)) ^ rol32(w[i - 13], 7) ^ w[i - 6];
        }
        for (i = 0; i < 64; ++i) {
            w1[i] = w[i] ^ w[i + 4];
        }
        /* 迭代 */
        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];
        for (i = 0; i < 16; ++i) {
            ss1 = rol32((rol32(a, 12) + e + rol32(0x79CC4519, i)), 7);
            ss2 = ss1 ^ rol32(a, 12);
            tt1 = FF_00_15(a, b, c) + d + ss2 + w1[i];
            tt2 = GG_00_15(e, f, g) + h + ss1 + w[i];
            d = c;
            c = rol32(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rol32(f, 19);
            f = e;
            e = P_0(tt2);
        }

        for (; i < 64; ++i) {
            ss1 = rol32((rol32(a, 12) + e + rol32(0x7A879D8A, i)), 7);
            ss2 = ss1 ^ rol32(a, 12);
            tt1 = FF_16_63(a, b, c) + d + ss2 + w1[i];
            tt2 = GG_16_63(e, f, g) + h + ss1 + w[i];
            d = c;
            c = rol32(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rol32(f, 19);
            f = e;
            e = P_0(tt2);
        }

        ctx->h[0] ^= a;
        ctx->h[1] ^= b;
        ctx->h[2] ^= c;
        ctx->h[3] ^= d;
        ctx->h[4] ^= e;
        ctx->h[5] ^= f;
        ctx->h[6] ^= g;
        ctx->h[7] ^= h;
        p += sizeof(ctx->data);
    }
}

int sm3_update(sm3_ctx *c, const void *msg, size_t len)
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
    /* 上轮处理还有剩余数据 */
    if (c->num != 0) {
        size_t n = sizeof(c->data) - c->num;
        if (len < n) {
            memcpy(p + c->num, data, len);
            return 1;
        }
        else
        {
            memcpy(p + c->num, data, n);
            len -= n;
            data += n;
            SM3BlockCal(c, c->data, 1);
        }
    }
    /* 此时data指向要处理的数据，len表示要处理的长度
     * 如果len大于一个块（64字节）的长度，可以进行处理
     */
    if (len >= sizeof(c->data)) {
        SM3BlockCal(c, data, len / sizeof(c->data));
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

int sm3_final(unsigned char *md, sm3_ctx *c)
{
    unsigned char *p = (unsigned char *)c->data;
    size_t n = c->num;

    /* 此时c->data肯定是不足64字节的，在数据最后一位加1 */
    p[n] = 0x80;
    n++;

    /* 如果此时data中的数据量不够留出8字节，则先处理当前块 */
    if (n > (sizeof(c->data) - 8)) {
        memset(p + n, 0, sizeof(c->data) - n);
        n = 0;
        SM3BlockCal(c, p, 1);
    }

    memset(p + n, 0, sizeof(c->data) - n - 8);
    p[sizeof(c->data) - 1] = (unsigned char)(c->n);
    p[sizeof(c->data) - 2] = (unsigned char)(c->n >> 8);
    p[sizeof(c->data) - 3] = (unsigned char)(c->n >> 16);
    p[sizeof(c->data) - 4] = (unsigned char)(c->n >> 24);
    p[sizeof(c->data) - 5] = (unsigned char)(c->n >> 32);
    p[sizeof(c->data) - 6] = (unsigned char)(c->n >> 40);
    p[sizeof(c->data) - 7] = (unsigned char)(c->n >> 48);
    p[sizeof(c->data) - 8] = (unsigned char)(c->n >> 56);
    SM3BlockCal(c, p, 1);
    if (md == NULL) {
        return 0;
    }
    uint_32 t;

    for (n = 0; n < SM3_DIGEST_LENGTH / 4; ++n) {
        t = c->h[n];
        *(md++) = (unsigned char)(t >> 24);
        *(md++) = (unsigned char)(t >> 16);
        *(md++) = (unsigned char)(t >> 8);
        *(md++) = (unsigned char)(t);
    }
    return 1;
}

unsigned char *sm3(const void *msg, size_t len, unsigned char *md)
{
    sm3_ctx ctx;

    sm3_init(&ctx);
    if (sm3_update(&ctx, msg, len)) {
        if (sm3_final(md, &ctx)) {
            return md;
        }
    }
    return 0;
}
