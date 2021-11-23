#include "pkcs12.h"

#include "keystore_internal.h"

#include <openssl/pkcs12.h>
#include <openssl/bio.h>

static int fromBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos);
static int countKeysCertsInBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts);

static int countKeysCertsInBag(const PKCS12_SAFEBAG* bag, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts)
{
    switch (PKCS12_SAFEBAG_get_nid(bag))
    {
        case NID_keyBag:
        case NID_pkcs8ShroudedKeyBag:
            if (numKeys)
                ++*numKeys;
            break;
        case NID_certBag:
            if (numCerts)
                ++*numCerts;
            break;
        case NID_safeContentsBag:
            return countKeysCertsInBags(PKCS12_SAFEBAG_get0_safes(bag), password, passSize, numKeys, numCerts);
    }
    return 1;
}

static int countKeysCertsInBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts)
{
    int i = 0;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); ++i)
    {
        if (countKeysCertsInBag(sk_PKCS12_SAFEBAG_value(bags, i), password, passSize, numKeys, numCerts) == 0)
            return 0;
    }
    return 1;
}

static int countKeysCerts(const STACK_OF(PKCS7)* safes, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts)
{
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    PKCS7* pkcs7 = NULL;
    int bagNID = 0;
    int i = 0;

    for (i = 0; i < sk_PKCS7_num(safes); ++i)
    {
        pkcs7 = sk_PKCS7_value(safes, i);
        if (pkcs7 == NULL)
            continue;
        bagNID = OBJ_obj2nid(pkcs7->type);
        if (bagNID == NID_pkcs7_data)
            bags = PKCS12_unpack_p7data(pkcs7);
        else if (bagNID == NID_pkcs7_encrypted)
            bags = PKCS12_unpack_p7encdata(pkcs7, password, passSize);
        else
            continue;
        if (bags == NULL)
            return 0;

        if (countKeysCertsInBags(bags, password, passSize, numKeys, numCerts) == 0)
        {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            return 0;
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    return 1;
}

static int fromBag(const PKCS12_SAFEBAG* bag, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    EVP_PKEY* pkey = NULL;
    PKCS8_PRIV_KEY_INFO* pkcs8;
    const PKCS8_PRIV_KEY_INFO* pkcs8c = NULL;
    X509* x509 = NULL;

    switch (PKCS12_SAFEBAG_get_nid(bag))
    {
        case NID_keyBag:
            pkcs8c = PKCS12_SAFEBAG_get0_p8inf(bag);
            pkey = EVP_PKCS82PKEY(pkcs8c);
            if (pkey == NULL)
                return 0;
            KeyStoreSetKey(ks, (*keyPos)++, pkey);
            break;
        case NID_pkcs8ShroudedKeyBag:
            pkcs8 = PKCS12_decrypt_skey(bag, password, passSize);
            if (pkcs8 == NULL)
                return 0;
            pkey = EVP_PKCS82PKEY(pkcs8);
            if (pkey == NULL)
            {
                PKCS8_PRIV_KEY_INFO_free(pkcs8);
                return 0;
            }
            KeyStoreSetKey(ks, (*keyPos)++, pkey);
            PKCS8_PRIV_KEY_INFO_free(pkcs8);
            break;
        case NID_certBag:
            x509 = PKCS12_SAFEBAG_get1_cert(bag);
            if (x509 == NULL)
               return 0;
            KeyStoreSetCert(ks, (*certPos)++, x509);
            break;
        case NID_safeContentsBag:
            return fromBags(PKCS12_SAFEBAG_get0_safes(bag), password, passSize, ks, keyPos, certPos);
    }
    return 1;
}

static int fromBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    int i = 0;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); ++i)
    {
        if (fromBag(sk_PKCS12_SAFEBAG_value(bags, i), password, passSize, ks, keyPos, certPos) == 0)
            return 0;
    }
    return 1;
}

static int fromSafes(const STACK_OF(PKCS7)* safes, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    PKCS7* pkcs7 = NULL;
    int bagNID = 0;
    int i = 0;

    for (i = 0; i < sk_PKCS7_num(safes); ++i)
    {
        pkcs7 = sk_PKCS7_value(safes, i);
        if (pkcs7 == NULL)
            continue;
        bagNID = OBJ_obj2nid(pkcs7->type);
        if (bagNID == NID_pkcs7_data)
            bags = PKCS12_unpack_p7data(pkcs7);
        else if (bagNID == NID_pkcs7_encrypted)
            bags = PKCS12_unpack_p7encdata(pkcs7, password, passSize);
        else
            continue;
        if (bags == NULL)
            return 0;

        if (fromBags(bags, password, passSize, ks, keyPos, certPos) == 0)
        {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            return 0;
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    return 1;
}

int parsePKCS12(const void* data, size_t dataSize, const char* password, size_t passSize, KeyStore** ks)
{
    const unsigned char* ptr = data;
    PKCS12* pkcs12 = d2i_PKCS12(NULL, &ptr, dataSize);
    STACK_OF(PKCS7)* safes = NULL;
    size_t numKeys = 0;
    size_t numCerts = 0;
    size_t keyPos = 0;
    size_t certPos = 0;

    if (pkcs12 == NULL)
        return 0;

    if (PKCS12_verify_mac(pkcs12, password, passSize) == 0)
    {
        PKCS12_free(pkcs12);
        return 0;
    }

    safes = PKCS12_unpack_authsafes(pkcs12);

    if (safes == NULL)
    {
        PKCS12_free(pkcs12);
        return 0;
    }

    if (countKeysCerts(safes, password, passSize, &numKeys, &numCerts) == 0 ||
        (numKeys == 0 && numCerts == 0))
    {
        sk_PKCS7_pop_free(safes, PKCS7_free);
        PKCS12_free(pkcs12);
        return 0;
    }

    *ks = KeyStoreNew(numKeys, numCerts);

    if (fromSafes(safes, password, passSize, *ks, &keyPos, &certPos) == 0)
    {
        KeyStoreFree(*ks);
        sk_PKCS7_pop_free(safes, PKCS7_free);
        PKCS12_free(pkcs12);
        return 0;
    }

    sk_PKCS7_pop_free(safes, PKCS7_free);
    PKCS12_free(pkcs12);

    return 1;
}

int readPKCS12(FILE* fp, const char* password, size_t passSize, KeyStore** ks)
{
    int res = 0;
    BIO* bio = BIO_new_fp(fp, 0);
    if (!bio)
        return 0;
    res = readPKCS12_bio(bio, password, passSize, ks);
    BIO_free(bio);
    return res;
}

int readPKCS12_bio(BIO* bio, const char* password, size_t passSize, KeyStore** ks)
{
    unsigned char buf[1024];
    BIO *mem = BIO_new(BIO_s_mem());
    size_t total = 0;
    size_t bytes = 0;
    size_t written = 0;
    char* ptr = NULL;
    int res = 0;
    for (;;)
    {
        if (!BIO_read_ex(bio, buf, sizeof(buf), &bytes))
        {
            if (total > 0)
                break;
            BIO_free(mem);
            return 0;
        }
        if (bytes == 0)
            break;
        if (!BIO_write_ex(mem, buf, bytes, &written))
        {
            BIO_free(mem);
            return 0;
        }
        total += bytes;
    }
    bytes = BIO_get_mem_data(mem, &ptr);
    if (bytes == 0 || ptr == NULL)
    {
        BIO_free(mem);
        return 0;
    }
    res = parsePKCS12(ptr, bytes, password, passSize, ks);
    BIO_free(mem);
    return res;
}
