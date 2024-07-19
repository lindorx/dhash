#include <stdio.h>
#include <string.h>
#include <binary.h>
#include <sha.h>
#include <sm3.h>
#include <ascon_hash.h>

int main()
{
    char str[] = "hello";
    uint_8 dig[SHA512_DIGEST_LENGTH];
    sha224(str, 5, dig);
    print_binary(dig, SHA224_DIGEST_LENGTH);
    sha256(str, 5, dig);
    print_binary(dig, SHA256_DIGEST_LENGTH);
    sha384(str, 5, dig);
    print_binary(dig, SHA384_DIGEST_LENGTH);
    sha512(str, 5, dig);
    print_binary(dig, SHA512_DIGEST_LENGTH);
    sm3(str, 5, dig);
    print_binary(dig, SM3_DIGEST_LENGTH);
    ascon_hash(str, 5, dig);
    print_binary(dig, CRYPTO_BYTES);
    return 0;
}
