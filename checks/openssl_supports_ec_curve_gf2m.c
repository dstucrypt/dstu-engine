#include <openssl/bn.h>
#include <openssl/ec.h>

int main()
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();

    EC_GROUP* curve = EC_GROUP_new_curve_GF2m(p, a, b, ctx);
    return 0;
}
