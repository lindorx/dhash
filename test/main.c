#include <sha.h>
#include <stdio.h>
#include <string.h>
#include <binary.h>

int main()
{
    char str[] = "hello";
    uint_8 dig[SHA512_DIGEST_LENGTH];
    sha512(str, 5, dig);
    print_binary(dig, SHA512_DIGEST_LENGTH);
    return 0;
}
