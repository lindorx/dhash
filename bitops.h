#ifndef _HWLITEOS_CRYPTO_BITOPS_H
#define _HWLITEOS_CRYPTO_BITOPS_H

#include <stdlib.h>
#include <byteswap.h>

typedef unsigned char buint8_t;
typedef unsigned int buint32_t;
typedef unsigned long long buint64_t;

static inline buint32_t rol32(buint32_t x, buint32_t n)
{
    return (x << (n & 31)) | (x >> ((-n) & 31));
}

static inline buint32_t ror32(buint32_t x, buint32_t n)
{
    return (x >> (n & 31)) | (x << ((-n) & 31));
}

static inline buint64_t rol64(buint64_t x, buint32_t n)
{
    return (x << (n & 63)) | (x >> ((-n) & 63));
}

static inline buint64_t ror64(buint64_t x, buint32_t n)
{
    return (x >> (n & 63)) | (x << ((-n) & 63));
}

static inline buint64_t load_bytes_64(const buint8_t *bytes, buint32_t n)
{
    buint64_t x = 0;
    memcpy(&x, bytes, n > 8 ? 8 : n);
    return x;
}

static inline void store_bytes_64(buint8_t *bytes, buint64_t w, buint32_t n)
{
    buint64_t x = bswap_64(w);
    memcpy(bytes, &x, n);
}

#endif /* _HWLITEOS_CRYPTO_BITOPS_H */