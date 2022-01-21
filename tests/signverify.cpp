#include "signverify.h"

#include "error.h"
#include "block.h"

#include <openssl/engine.h>
#include <openssl/evp.h>

#include <stdexcept>

using DSTUEngine::OPENSSLError;
using DSTUEngine::makeBlock;

namespace
{

std::vector<unsigned char> sign(ENGINE* engine, const EVP_MD* md, EVP_PKEY* priv, const void* data, size_t size)
{
    auto* mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr)
        throw std::runtime_error("sign: failed to create digest context. " + OPENSSLError());
    if (EVP_DigestSignInit(mdctx, nullptr, md, engine, priv) == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("sign: failed to initialize signature. " + OPENSSLError());
    }
    if (EVP_DigestSignUpdate(mdctx, data, size) == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("sign: failed to update signature. " + OPENSSLError());
    }
    size_t len = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &len) == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("sign: failed to get signature length. " + OPENSSLError());
    }
    if (len == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("sign: invalid signature length. " + std::to_string(len));
    }
    std::vector<unsigned char> res(len);
    if (EVP_DigestSignFinal(mdctx, res.data(), &len) == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("sign: failed to get signature length. " + OPENSSLError());
    }
    EVP_MD_CTX_destroy(mdctx);
    return res;
}

void verify(ENGINE* engine, const EVP_MD* md, EVP_PKEY* pub, const std::vector<unsigned char>& signature, const void* data, size_t size)
{
    auto* mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr)
        throw std::runtime_error("verify: failed to create digest context. " + OPENSSLError());
    if (EVP_DigestVerifyInit(mdctx, nullptr, md, engine, pub) == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("verify: failed to initialize verification. " + OPENSSLError());
    }
    if (EVP_DigestVerifyUpdate(mdctx, data, size) == 0)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("verify: failed to update verification. " + OPENSSLError());
    }
    if (EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size()) != 1)
    {
        EVP_MD_CTX_destroy(mdctx);
        throw std::runtime_error("verify: signature verification failed. " + OPENSSLError());
    }
    EVP_MD_CTX_destroy(mdctx);
}

}

void DSTUEngine::testVerify(ENGINE* engine, EVP_PKEY* pub, const std::string& signature, const void* data, size_t size)
{
    auto* md = ENGINE_get_digest(engine, NID_dstu34311);
    if (md == nullptr)
        throw std::runtime_error("testVerify: failed to get digest. " + OPENSSLError());
    verify(engine, md, pub, makeBlock(signature), data, size);
}

void DSTUEngine::testSignVerify(ENGINE* engine, EVP_PKEY* pub, EVP_PKEY* priv, const void* data, size_t size)
{
    auto* md = ENGINE_get_digest(engine, NID_dstu34311);
    if (md == nullptr)
        throw std::runtime_error("testSignVerify: failed to get digest. " + OPENSSLError());
    verify(engine, md, pub, sign(engine, md, priv, data, size), data, size);
}

void DSTUEngine::testSignVerify(ENGINE* engine, const KeyStore* ks, const void* data, size_t size)
{
    for (size_t i = 0; i < KeyStoreKeyNum(ks); ++i)
    {
        auto* key = const_cast<EVP_PKEY*>(KeyStoreGetKey(ks, i));
        try
        {
            testSignVerify(engine, key, key, data, size);
        }
        catch (const std::exception& ex)
        {
            throw std::runtime_error("key[" + std::to_string(i) + "] " + ex.what());
        }
    }
}
