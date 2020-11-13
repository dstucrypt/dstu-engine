#include "keylib.h"

#include "iit_asn1.h"

#include "params.h"
#include "gost/gost89.h"
#include "gost/gosthash.h"

#include <string.h>

static const char iitStoreOID[] = "1.3.6.1.4.1.19398.1.1.1.2";

static void hash(const void* data, size_t size, unsigned char* dest)
{
    gost_ctx cctx;
    gost_hash_ctx ctx;
    gost_subst_block sbox;

    unpack_sbox(default_sbox, &sbox);
    gost_init(&cctx, &sbox);
    memset(&ctx, 0, sizeof(ctx));
    ctx.cipher_ctx = &cctx;
    hash_block(&ctx, data, size);
    finish_hash(&ctx, dest);
}

static void pkdf(const char* password, size_t passSize, unsigned char* key)
{
    int i = 0;
    hash(password, passSize, key);
    for (i = 0; i < 9999; ++i)
        hash(key, 32, key);
}

static EVP_PKEY* pkeyFromAttributes(const void* data, size_t size)
{
    return NULL;
}

static int decryptKey6(const void* data, size_t size, const void* pad, size_t padSize, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
{
    gost_ctx ctx;
    gost_subst_block sbox;
    unsigned char key[32];
    const size_t sourceSize = size + padSize;
    const size_t resSize = sourceSize + 8;
    unsigned char* source = OPENSSL_malloc(sourceSize);
    unsigned char* res = OPENSSL_malloc(resSize);
    const unsigned char* ptr = res;
    EVP_PKEY* pkey1 = NULL;
    EVP_PKEY* pkey2 = NULL;

    unpack_sbox(default_sbox, &sbox);
    gost_init(&ctx, &sbox);
    pkdf(password, passSize, key);
    gost_key(&ctx, key);
    memcpy(source, data, size);
    if (padSize > 0)
        memcpy(source + size, pad, padSize);
    gost_dec(&ctx, source, res, sourceSize / 8);
    OPENSSL_clear_free(source, sourceSize);

    pkey1 = d2i_AutoPrivateKey(NULL, &ptr, resSize);
    if (pkey1 == NULL)
    {
        OPENSSL_clear_free(res, resSize);
        return 0;
    }

    pkey2 = pkeyFromAttributes(res, resSize);
    OPENSSL_clear_free(res, resSize);

    if (pkey2 == NULL)
    {
        *keys = OPENSSL_malloc(sizeof(EVP_PKEY*));
        (*keys)[0] = pkey1;
        *numKeys = 1;
    }
    else
    {
        *keys = OPENSSL_malloc(sizeof(EVP_PKEY*) * 2);
        (*keys)[0] = pkey1;
        (*keys)[1] = pkey2;
        *numKeys = 2;
    }

    return 1;
}

int parseKey6(const void* data, size_t size, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
{
    int res = 0;
    ASN1_OBJECT* correctType = NULL;
    const unsigned char* ptr = data;
    IITStore* store = d2i_IITStore(NULL, &ptr, size);
    if (store == NULL)
        return 0;
    // Sanity checks
    if (store->header == NULL || store->data == NULL ||
        store->header->type == NULL || store->header->params == NULL)
    {
        IITStore_free(store);
        return 0;
    }
    // Type check
    correctType = OBJ_txt2obj(iitStoreOID, 1);
    if (OBJ_cmp(store->header->type, correctType) != 0)
    {
        ASN1_OBJECT_free(correctType);
        IITStore_free(store);
        return 0;
    }
    ASN1_OBJECT_free(correctType);
    if (store->header->params->pad == NULL)
        res = decryptKey6(ASN1_STRING_get0_data(store->data), ASN1_STRING_length(store->data),
                          NULL, 0,
                          password, passSize,
                          keys, numKeys);
    else
        res = decryptKey6(ASN1_STRING_get0_data(store->data), ASN1_STRING_length(store->data),
                          ASN1_STRING_get0_data(store->header->params->pad), ASN1_STRING_length(store->header->params->pad),
                          password, passSize,
                          keys, numKeys);
    IITStore_free(store);
    return res;
}

int readKey6(FILE* fp, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
{
    int res = 0;
    BIO* bio = BIO_new_fp(fp, 0);
    if (!bio)
        return 0;
    res = readKey6_bio(bio, password, passSize, keys, numKeys);
    BIO_free(bio);
    return res;
}

int readKey6_bio(BIO* bio, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
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
    res = parseKey6(ptr, bytes, password, passSize, keys, numKeys);
    BIO_free(mem);
    return res;
}
