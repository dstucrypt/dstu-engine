#include "keystore_internal.h"
#include "keystore.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

struct KeyStore_st
{
    size_t keyNum;
    EVP_PKEY** keys;
    size_t certNum;
    X509** certs;
};

KeyStore* KeyStoreNew(size_t keyNum, size_t certNum)
{
    size_t i = 0;
    KeyStore* res = OPENSSL_malloc(sizeof(KeyStore));
    if (keyNum > 0)
    {
        res->keyNum = keyNum;
        res->keys = OPENSSL_malloc(keyNum * sizeof(EVP_PKEY*));
        for (i = 0; i < keyNum; ++i)
            res->keys[i] = NULL;
    }
    else
    {
        res->keyNum = 0;
        res->keys = NULL;
    }
    if (certNum > 0)
    {
        res->certNum = certNum;
        res->certs = OPENSSL_malloc(certNum * sizeof(X509*));
        for (i = 0; i < certNum; ++i)
            res->certs[i] = NULL;
    }
    else
    {
        res->certNum = 0;
        res->certs = NULL;
    }
    return res;
}

void KeyStoreAppend(KeyStore* to, KeyStore* from)
{
    size_t i = 0;
    if (from->keyNum > 0)
    {
        to->keys = OPENSSL_clear_realloc(to->keys, to->keyNum * sizeof(EVP_PKEY*), (to->keyNum + from->keyNum) * sizeof(EVP_PKEY*));
        for (i = 0; i < from->keyNum; ++i)
        {
            to->keys[to->keyNum + i] = from->keys[i];
            from->keys[i] = NULL;
        }
        to->keyNum += from->keyNum;
    }
    if (from->certNum > 0)
    {
        to->certs = OPENSSL_clear_realloc(to->certs, to->certNum * sizeof(X509*), (to->certNum + from->certNum) * sizeof(X509*));
        for (i = 0; i < from->certNum; ++i)
        {
            to->certs[to->certNum + i] = from->certs[i];
            from->certs[i] = NULL;
        }
        to->certNum += from->certNum;
    }
}

void KeyStoreFree(KeyStore* ks)
{
    size_t i = 0;
    if (ks->keys != NULL)
    {
        for (i = 0; i < ks->keyNum; ++i)
            EVP_PKEY_free(ks->keys[i]);
        OPENSSL_clear_free(ks->keys, ks->keyNum * sizeof(EVP_PKEY*));
    }
    if (ks->certs != NULL)
    {
        for (i = 0; i < ks->certNum; ++i)
            X509_free(ks->certs[i]);
        OPENSSL_clear_free(ks->certs, ks->certNum * sizeof(X509*));
    }
    OPENSSL_clear_free(ks, sizeof(KeyStore));
}

size_t KeyStoreKeyNum(const KeyStore* ks)
{
    return ks->keyNum;
}

size_t KeyStoreCertNum(const KeyStore* ks)
{
    return ks->certNum;
}

void KeyStoreSetKey(KeyStore* ks, size_t pos, EVP_PKEY* key)
{
    ks->keys[pos] = key;
}

void KeyStoreSetCert(KeyStore* ks, size_t pos, X509* cert)
{
    ks->certs[pos] = cert;
}

const EVP_PKEY* KeyStoreGetKey(const KeyStore* ks, size_t pos)
{
    if (pos < ks->keyNum)
        return ks->keys[pos];
    return NULL;
}

const X509* KeyStoreGetCert(const KeyStore* ks, size_t pos)
{
    if (pos < ks->certNum)
        return ks->certs[pos];
    return NULL;
}
