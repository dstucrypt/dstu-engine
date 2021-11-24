#include "jks.h"
#include "keystore.h"

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
    KeyStore* ks = nullptr;
    if (readJKS(fp, storagePass.c_str(), storagePass.length(), keyPass.c_str(), keyPass.length(), &ks) == 0)
        throw std::runtime_error("testJKS: failed to read key from '" + file + "'.");
    fclose(fp);
    if (ks == nullptr)
        throw std::runtime_error("testJKS: no keys from '" + file + "'.");
    const auto keyNum = KeyStoreKeyNum(ks);
    if (keyNum != 2)
        throw std::runtime_error("testJKS: unexpected number of keys. Expected 2, got " + std::to_string(keyNum));
    const auto certNum = KeyStoreCertNum(ks);
    if (certNum != 3)
        throw std::runtime_error("testJKS: unexpected number of certs. Expected 3, got " + std::to_string(certNum));
    KeyStoreFree(ks);
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
