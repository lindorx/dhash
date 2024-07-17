#include <stdio.h>

#define HEX2CAPITAL(c) (((c) > 9) ? ((c) - 10 + 'A') : ((c) + '0'))

void *binary2string(const void *p, size_t pn, char *s, size_t sn)
{
    int i, j;
    const unsigned char *bin = (const unsigned char *)p;

    if (pn * 2 > sn)
    {
        return NULL;
    }

    for (i = 0, j = 0; i < pn; i++)
    {
        s[j++] = HEX2CAPITAL((bin[i] & 0xf0) >> 4);
        s[j++] = HEX2CAPITAL(bin[i] & 0x0f);
    }
    return s;
}

void print_binary(const void *p, size_t n)
{
    int i, j;
    char str[n * 2 + 1];

    if (binary2string(p, n, str, n * 2))
    {
        str[n * 2] = '\0';
        printf("%s\n", str);
    }
}
