#include "key6.h"
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

void testKey6(const std::string& file, const std::string& password)
{
    auto* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("testKey6: failed to open '" + file + "'. " + strerror(errno));
    KeyStore* ks = nullptr;
    if (readKey6(fp, password.c_str(), password.length(), &ks) == 0)
        throw std::runtime_error("testKey6: failed to read key from '" + file + "'.");
    fclose(fp);
    if (ks == nullptr)
        throw std::runtime_error("testKey6: no keys from '" + file + "'.");
    auto keyNum = KeyStoreKeyNum(ks);
    if (keyNum != 2)
        throw std::runtime_error("testKey6: unexpected number of keys. Expected 2, got " + std::to_string(keyNum) + ".");
    const auto certNum = KeyStoreCertNum(ks);
    if (certNum != 0)
        throw std::runtime_error("testKey6: unexpected number of certs. Expected 0, got " + std::to_string(certNum));
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

    testKey6("Key-6.dat", "tect4");

    ENGINE_finish(engine);
    ENGINE_free(engine);

    EVP_cleanup(); ERR_free_strings(); CRYPTO_cleanup_all_ex_data();

    return 0;
}
