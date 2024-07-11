#include "hash.h"

static inline void Round(AsconState *s, UINT8 c)
{
    AsconState t;
    /* round constant */
    s->x[2] ^= c;
    /* s-box layer, 对应pdf的2.6.3 Figure 4a */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[1] ^= t.x[0];
    t.x[3] ^= t.x[2];
    t.x[0] ^= t.x[4];
    /* linear layer, 对应pdf的2.6.3 Figure 4b */
    s->x[2] = t.x[2] ^ ror64(t.x[2], 6 - 1);
    s->x[3] = t.x[3] ^ ror64(t.x[3], 17 - 10);
    s->x[4] = t.x[4] ^ ror64(t.x[4], 41 - 7);
    s->x[0] = t.x[0] ^ ror64(t.x[0], 28 - 19);
    s->x[1] = t.x[1] ^ ror64(t.x[1], 61 - 39);
    s->x[2] = t.x[2] ^ ror64(s->x[2], 1);
    s->x[3] = t.x[3] ^ ror64(s->x[3], 10);
    s->x[4] = t.x[4] ^ ror64(s->x[4], 7);
    s->x[0] = t.x[0] ^ ror64(s->x[0], 19);
    s->x[1] = t.x[1] ^ ror64(s->x[1], 39);
    s->x[2] = ~s->x[2];
}

/* P12常数加法 */
static inline void P12Rounds(AsconState *s)
{
    Round(s, RC0);
    Round(s, RC1);
    Round(s, RC2);
    Round(s, RC3);
    Round(s, RC4);
    Round(s, RC5);
    Round(s, RC6);
    Round(s, RC7);
    Round(s, RC8);
    Round(s, RC9);
    Round(s, RCa);
    Round(s, RCb);
}

/* P8常数加法 */
static inline void P8Rounds(AsconState *s)
{
    Round(s, RC4);
    Round(s, RC5);
    Round(s, RC6);
    Round(s, RC7);
    Round(s, RC8);
    Round(s, RC9);
    Round(s, RCa);
    Round(s, RCb);
}

/* P6常数加法 */
static inline void P6Rounds(AsconState *s)
{
    Round(s, RC6);
    Round(s, RC7);
    Round(s, RC8);
    Round(s, RC9);
    Round(s, RCa);
    Round(s, RCb);
}

static inline UINT64 PAD(int i)
{
    return 0x80ull << (56 - 8 * i);
}

static inline void AsconHashInit(AsconState *s)
{
    s->x[0]=ASCON_IV0;
    s->x[1]=ASCON_IV1;
    s->x[2]=ASCON_IV2;
    s->x[3]=ASCON_IV3;
    s->x[4]=ASCON_IV4;
}

static inline void AsconAbsorb(AsconState *s, const UINT8 *in, UINT64 inlen)
{
    const UINT64 *in64 = (const UINT64*)in;
    UINT64 len = inlen/ASCON_HASH_RATE, i = 0;
    while (len--) {
        s->x[0] ^= bswap_64(in64[i]);
        PnRounds(s);
        i++;
    }
    s->x[0] ^= load_bytes(in, inlen);
    s->x[0] ^= PAD(inlen);
}

static inline void AsconSqueeze(AsconState *s, UINT8 *out, UINT64 outlen)
{
    UINT64 *out64 = (UINT64 *)out;
    UINT64 len = outlen/ASCON_HASH_RATE, i = 0;
    PnRounds(s);
    while (len--) {
        out64[i]=bswap_64(s->x[0]);
        PnRounds(s);
        i++;
    }
    store_bytes(out, s->x[0], outlen);
}

int AsconXof(UINT8 *out, UINT64 outlen, const UINT8 *in, UINT64 inlen)
{
    AsconState s;
    AsconHashInit(&s);
    AsconAbsorb(&s, in, inlen);
    AsconSqueeze(&s, out, outlen);
    return 0;
}

int AsconHash(const void *msg, size_t len, unsigned char *md)
{
    return AsconXof(md, CRYPTO_BYTES, msg, len);
}
