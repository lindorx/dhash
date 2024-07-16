#include <sha.h>

/* 常数表 */
static const uint_64 sha512_K[80] = {
    0x428a2f98d728ae22ULL,
    0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL,
    0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL,
    0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,
    0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,
    0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL,
    0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL,
    0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,
    0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL,
    0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,
    0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,
    0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL,
    0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL,
    0xf40e35855771202aULL,
    0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,
    0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,
    0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL,
    0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,
    0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL,
    0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL,
    0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL,
    0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,
    0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,
    0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL,
    0x6c44198c4a475817ULL,
};

/*
 * sha512_init: 初始化信息结构
 * ctx: sha512信息结构
 */
int sha512_init(sha512_ctx *ctx)
{
    ctx->h[0] = 0x6A09E667F3BCC908ULL;
    ctx->h[1] = 0xBB67AE8584CAA73BULL;
    ctx->h[2] = 0x3C6EF372FE94F82BULL;
    ctx->h[3] = 0xA54FF53A5F1D36F1ULL;
    ctx->h[4] = 0x510E527FADE682D1ULL;
    ctx->h[5] = 0x9B05688C2B3E6C1FULL;
    ctx->h[6] = 0x1F83D9ABFB41BD6BULL;
    ctx->h[7] = 0x5BE0CD19137E2179ULL;
    ctx->nl = 0;
    ctx->nh = 0;
    ctx->num = 0;
    ctx->md_len = SHA512_DIGEST_LENGTH;
    return 1;
}

#define CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SIGMA0(x) (ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39))
#define SIGMA1(x) (ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41))

#define GAMMA0(x) (ror64(x, 1) ^ ror64(x, 8) ^ (x >> 7))
#define GAMMA1(x) (ror64(x, 19) ^ ror64(x, 61) ^ (x >> 6))

#define ROUND_00_15(i, a, b, c, d, e, f, g, h)             \
    do                                                     \
    {                                                      \
        temp += h + SIGMA1(e) + CH(e, f, g) + sha512_K[i]; \
        h = SIGMA0(a) + MAJ(a, b, c);                      \
        d += temp;                                         \
        h += temp;                                         \
    } while (0)

#define ROUND_16_80(i, j, a, b, c, d, e, f, g, h, x)         \
    do                                                       \
    {                                                        \
        s0 = x[(j + 1) & 0x0f];                              \
        s0 = GAMMA0(s0);                                     \
        s1 = x[(j + 14) & 0x0f];                             \
        s1 = GAMMA1(s1);                                     \
        temp = x[(j) & 0x0f] += s0 + s1 + x[(j + 9) & 0x0f]; \
        ROUND_00_15(i + j, a, b, c, d, e, f, g, h);          \
    } while (0)

/*
 * SHA512BlockCal: 按块计算数据
 * ctx: sha512信息
 * data: 块数据起始地址
 * num: 块数量
 */
static void SHA512BlockCal(sha512_ctx *ctx, const void *data, size_t num)
{
    uint_64 a, b, c, d, e, f, g, h;
    uint_64 s0, s1, temp, x[16];
    const uint_64 *w = data;
    int i;

    while (num--) {
        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

#if 0
    //大端模式
        temp = x[0] = w[0];
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        temp = x[1] = w[1];
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        temp = x[2] = w[2];
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        temp = x[3] = w[3];
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        temp = x[4] = w[4];
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        temp = x[5] = w[5];
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        temp = x[6] = w[6];
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        temp = x[7] = w[7];
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        temp = x[8] = w[8];
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        temp = x[9] = w[9];
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        temp = x[10] = w[10];
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        temp = x[11] = w[11];
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        temp = x[12] = w[12];
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        temp = x[13] = w[13];
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        temp = x[14] = w[14];
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        temp = x[15] = w[15];
        ROUND_00_15(15, b, c, d, e, f, g, h, a);
#else
        temp = x[0] = PULL64(w[0]);
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        temp = x[1] = PULL64(w[1]);
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        temp = x[2] = PULL64(w[2]);
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        temp = x[3] = PULL64(w[3]);
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        temp = x[4] = PULL64(w[4]);
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        temp = x[5] = PULL64(w[5]);
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        temp = x[6] = PULL64(w[6]);
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        temp = x[7] = PULL64(w[7]);
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        temp = x[8] = PULL64(w[8]);
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        temp = x[9] = PULL64(w[9]);
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        temp = x[10] = PULL64(w[10]);
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        temp = x[11] = PULL64(w[11]);
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        temp = x[12] = PULL64(w[12]);
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        temp = x[13] = PULL64(w[13]);
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        temp = x[14] = PULL64(w[14]);
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        temp = x[15] = PULL64(w[15]);
        ROUND_00_15(15, b, c, d, e, f, g, h, a);
#endif

        for (i = 16; i < 80; i += 16) {
            ROUND_16_80(i, 0, a, b, c, d, e, f, g, h, x);
            ROUND_16_80(i, 1, h, a, b, c, d, e, f, g, x);
            ROUND_16_80(i, 2, g, h, a, b, c, d, e, f, x);
            ROUND_16_80(i, 3, f, g, h, a, b, c, d, e, x);
            ROUND_16_80(i, 4, e, f, g, h, a, b, c, d, x);
            ROUND_16_80(i, 5, d, e, f, g, h, a, b, c, x);
            ROUND_16_80(i, 6, c, d, e, f, g, h, a, b, x);
            ROUND_16_80(i, 7, b, c, d, e, f, g, h, a, x);
            ROUND_16_80(i, 8, a, b, c, d, e, f, g, h, x);
            ROUND_16_80(i, 9, h, a, b, c, d, e, f, g, x);
            ROUND_16_80(i, 10, g, h, a, b, c, d, e, f, x);
            ROUND_16_80(i, 11, f, g, h, a, b, c, d, e, x);
            ROUND_16_80(i, 12, e, f, g, h, a, b, c, d, x);
            ROUND_16_80(i, 13, d, e, f, g, h, a, b, c, x);
            ROUND_16_80(i, 14, c, d, e, f, g, h, a, b, x);
            ROUND_16_80(i, 15, b, c, d, e, f, g, h, a, x);
        }
        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        w += sizeof(ctx->data);
    }
}

/*
 * sha512_update: 更新摘要
 * ctx: sha512信息结构
 * msg: 待处理数据
 * len: 数据长度，单位字节
 * 返回值: 1表示成功，0表示失败
 */
int sha512_update(sha512_ctx *ctx, const void *msg, size_t len)
{
    uint_64 l;
    unsigned char *p = (unsigned char *)ctx->data;
    const unsigned char *data = (const unsigned char *)msg;

    if (len == 0) {
        return 0;
    }
    /*  记录已经处理过的长度 */
    l = (ctx->nl + (((uint_64)len) << 3)) & 0xffffffffffffffffULL;
    /* 如果l小于nl说明发生进位 */
    if (l < ctx->nl) {
        ctx->nh++;
    }
    /* 如果len变量类型大小大于等于8，说明至少是64位系统，以下操作保证处理极大数据量时也可以保证精度，这块参考了openssl */
    if (sizeof(len) >= 8) {
        /* 由于要记录位数，因此实际结果要乘以8，即左移3位，所以这里是61 */
        ctx->nh += (((uint_64)len) >> 61);
    }
    ctx->nl = l;

    /* 如果num不等于0，说明上次update没有处理完所有数据，memcpy时需要将新数据追加到旧数据之后 */
    if (ctx->num != 0) {
        size_t n = sizeof(ctx->data) - ctx->num;

        if (len < n) { /* 本轮待处理数据加上上次未处理数据量不足一个块 */
            memcpy(p + ctx->num, msg, len);
            return 1;
        }
        else
        { /* 超过一个块了 */
            memcpy(p + ctx->num, msg, n);
            len -= n;
            data += n;
            SHA512BlockCal(ctx, p, 1);
        }
    }

    /* 正式进行处理
     * 此时data指向要处理的数据起始地址，p指向ctx记录临时数据的数组data
     * len表示要处理的数据长度
     * 如果len大于一个块，可以调用SHA512BlockCal进行处理，否则将数据记录到ctx->data中，待用户下次提供数据
     */
    if (len >= sizeof(ctx->data)) {
        SHA512BlockCal(ctx, data, len / sizeof(ctx->data));
        data += len;
        len %= sizeof(ctx->data);
        data -= len;
    }

    if (len != 0) {
        memcpy(p, data, len);
        ctx->num = len;
    }
    return 1;
}

/*
 * sha512_final: 结束摘要过程
 * md: 摘要存储位置
 * ctx: sha512信息结构
 * 返回值: 1表示成功，0表示失败
 */
int sha512_final(unsigned char *md, sha512_ctx *ctx)
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
        SHA512BlockCal(ctx, p, 1);
    }

    memset(p + n, 0, sizeof(ctx->data) - n - 16);
    /* 小端存储 */
    p[sizeof(ctx->data) - 1] = (unsigned char)(ctx->nl);
    p[sizeof(ctx->data) - 2] = (unsigned char)(ctx->nl >> 8);
    p[sizeof(ctx->data) - 3] = (unsigned char)(ctx->nl >> 16);
    p[sizeof(ctx->data) - 4] = (unsigned char)(ctx->nl >> 24);
    p[sizeof(ctx->data) - 5] = (unsigned char)(ctx->nl >> 32);
    p[sizeof(ctx->data) - 6] = (unsigned char)(ctx->nl >> 40);
    p[sizeof(ctx->data) - 7] = (unsigned char)(ctx->nl >> 48);
    p[sizeof(ctx->data) - 8] = (unsigned char)(ctx->nl >> 56);
    p[sizeof(ctx->data) - 9] = (unsigned char)(ctx->nh);
    p[sizeof(ctx->data) - 10] = (unsigned char)(ctx->nh >> 8);
    p[sizeof(ctx->data) - 11] = (unsigned char)(ctx->nh >> 16);
    p[sizeof(ctx->data) - 12] = (unsigned char)(ctx->nh >> 24);
    p[sizeof(ctx->data) - 13] = (unsigned char)(ctx->nh >> 32);
    p[sizeof(ctx->data) - 14] = (unsigned char)(ctx->nh >> 40);
    p[sizeof(ctx->data) - 15] = (unsigned char)(ctx->nh >> 48);
    p[sizeof(ctx->data) - 16] = (unsigned char)(ctx->nh >> 56);

    SHA512BlockCal(ctx, p, 1);

    if (md == NULL) {
        return 0;
    }

    /* 根据md_len记录的大小设置要到处摘要的长度，此时ctx->h存储了摘要值 */
    switch (ctx->md_len) {
    case SHA224_DIGEST_LENGTH:
        for (n = 0; n < SHA224_DIGEST_LENGTH / 8; n++) {
            uint_64 t = ctx->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        {
            uint_64 t = ctx->h[SHA224_DIGEST_LENGTH / 8];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
        }
        break;
    case SHA256_DIGEST_LENGTH:
        for (n = 0; n < SHA256_DIGEST_LENGTH / 8; n++) {
            uint_64 t = ctx->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    case SHA384_DIGEST_LENGTH:
        for (n = 0; n < SHA384_DIGEST_LENGTH / 8; n++) {
            uint_64 t = ctx->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    case SHA512_DIGEST_LENGTH:
        for (n = 0; n < SHA512_DIGEST_LENGTH / 8; n++) {
            uint_64 t = ctx->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
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
unsigned char *sha512(const void *msg, size_t len, unsigned char *md)
{
    sha512_ctx ctx;

    sha512_init(&ctx);
    if (sha512_update(&ctx, msg, len)) {
        if (sha512_final(md, &ctx)) {
            return md;
        }
    }
    return 0;
}
