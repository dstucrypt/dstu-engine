#include <openssl/evp.h>

int copyMethod(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
    (void)dst;
    (void)src;
    return 0;
}

int main()
{
    EVP_PKEY_meth_set_copy(NULL, copyMethod);
    return 0;
}
