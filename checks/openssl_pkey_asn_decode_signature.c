#include <openssl/evp.h>

int decodeMethod(EVP_PKEY* pk, const X509_PUBKEY* pubk)
{
    (void)pk;
    (void)pubk;
    return 0;
}

int main()
{
    EVP_PKEY_asn1_set_public(NULL, decodeMethod, NULL, NULL, NULL, NULL, NULL);
    return 0;
}
