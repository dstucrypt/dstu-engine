#include "jks.h"

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <string>
#include <array>
#include <stdexcept>

#include <cstring>
#include <cerrno>

namespace
{

std::string OPENSSLError() noexcept
{
    std::array<char, 256> buf{};
    ERR_error_string_n(ERR_get_error(), buf.data(), buf.size());
    return buf.data();
}

void testJKS(const std::string& file, const std::string& storagePass, const std::string& keyPass)
{
    auto* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("testJKS: failed to open '" + file + "'. " + strerror(errno));
    JKS* jks = nullptr;
    if (readJKS(fp, storagePass.c_str(), storagePass.length(), &jks) == 0)
        throw std::runtime_error("testJKS: failed to read key from '" + file + "'.");
    fclose(fp);
    if (jks == nullptr)
        throw std::runtime_error("testJKS: no keys from '" + file + "'.");
    const auto jksType = JKSType(jks);
    if (jksType != JKS_TYPE_JKS)
        throw std::runtime_error("testJKS: unexpected JKS type. Expected " + std::to_string(JKS_TYPE_JKS) + " (JKS), got " + std::to_string(jksType));
    const auto entryNum = JKSEntryNum(jks);
    if (entryNum != 1)
        throw std::runtime_error("testJKS: unexpected number of entries. Expected 1, got " + std::to_string(entryNum));
    for (size_t i = 0; i < entryNum; ++i)
    {
        auto entry = JKSEntryGet(jks, i);
        if (entry == nullptr)
            throw std::runtime_error("testJKS: empty JKS entry #" + std::to_string(i));
        const auto entryType = JKSEntryType(entry);
        if (entryType != JKS_ENTRY_PRIVATE_KEY)
            throw std::runtime_error("testJKS: unexpected JKS entry type. Expected " + std::to_string(JKS_ENTRY_PRIVATE_KEY) + " (private key), got " + std::to_string(entryType));
        auto pkeyNum = JKSEntryPKeyNum(entry);
        if (pkeyNum != 0)
            throw std::runtime_error("testJKS: unexpected number of private keys. Expected 0 (not decrypted), got " + std::to_string(pkeyNum));
        if (JKSEntryDecrypt(entry, keyPass.c_str(), keyPass.length()) == 0)
            throw std::runtime_error("testJKS: failed to decrypt private key entry.");
        pkeyNum = JKSEntryPKeyNum(entry);
        if (pkeyNum != 2)
            throw std::runtime_error("testJKS: unexpected number of private keys. Expected 2, got " + std::to_string(pkeyNum));
        const auto certNum = JKSEntryCertNum(entry);
        if (certNum != 3)
            throw std::runtime_error("testJKS: unexpected number of certificates. Expected 3, got " + std::to_string(certNum));
    }
    JKSFree(jks);
}

}

int main()
{
    ERR_load_crypto_strings(); OpenSSL_add_all_algorithms();

    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);

    if (CONF_modules_load_file("openssl.cnf", nullptr, 0) <= 0)
        throw std::runtime_error("main: failed to load config file. " + OPENSSLError());

    auto* engine = ENGINE_by_id("dstu");
    if (engine == nullptr)
        throw std::runtime_error("main: failed to load engine. " + OPENSSLError());
    if (ENGINE_init(engine) == 0)
        throw std::runtime_error("main: failed to initialize engine. " + OPENSSLError());

    ENGINE_set_default(engine, ENGINE_METHOD_ALL);

    testJKS("key.jks", "123456", "qwerty");

    ENGINE_finish(engine);
    ENGINE_free(engine);

    EVP_cleanup(); ERR_free_strings(); CRYPTO_cleanup_all_ex_data();

    return 0;
}
