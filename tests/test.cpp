#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <string>
#include <array>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>

#include <cstring>
#include <cerrno>

namespace
{
namespace DSTU28417
{
constexpr std::array<unsigned char, 32> key{ 0,  1,  2,  3,  4,  5,  6,  7,
                                             8,  9, 10, 11, 12, 13, 14, 15,
                                            16, 17, 18, 19, 20, 21, 22, 23,
                                            24, 25, 26, 27, 28, 29, 30, 31};
constexpr std::array<unsigned char, 8> iv{7, 6, 5, 4, 3, 2, 1, 0};
}

std::string OPENSSLError() noexcept
{
    std::array<char, 256> buf{};
    ERR_error_string_n(ERR_get_error(), buf.data(), buf.size());
    return buf.data();
}

unsigned char fromHex(char a)
{
    if (a >= '0' && a <= '9')
        return a - '0';
    if (a >= 'a' && a <= 'f')
        return a - 'a' + 10;
    if (a >= 'A' && a <= 'F')
        return a - 'A' + 10;
    throw std::runtime_error("fromHex: invalid hex char: '" + std::string(1, a) + "'");
}

unsigned char fromHex(char a, char b)
{
    return fromHex(a) * 16 + fromHex(b);
}

std::vector<unsigned char> makeBlock(const std::string& hex)
{
    std::vector<unsigned char> res;
    for (size_t i = 0; i < hex.size();)
    {
        if (hex[i] == ' ')
        {
            ++i;
            continue;
        }
        res.push_back(fromHex(hex[i], hex[i + 1]));
        i += 2;
    }
    return res;
}

void checkBlock(const void* data, size_t size, const std::string& hexEtalon)
{
    size_t pos = 0;
    const auto* ptr = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < hexEtalon.size();)
    {
        if (i == hexEtalon.size() - 1)
            throw std::runtime_error("checkBlock: bad etalon, odd data at position #" + std::to_string(i));
        if (hexEtalon[i] == ' ')
        {
            ++i;
            continue;
        }
        if (pos >= size)
            throw std::runtime_error("checkBlock: etalon is bigger than the data. Data size: " + std::to_string(size));
        if (ptr[pos] != fromHex(hexEtalon[i], hexEtalon[i + 1]))
            throw std::runtime_error("checkBlock: bad data at position #" + std::to_string(pos));
        ++pos;
        i += 2;
    }
}

void checkBlock(const void* data, size_t size, const void* edata, size_t esize)
{
    if (size != esize)
        throw std::runtime_error("checkBlock: data size " + std::to_string(size) + " does not match etalon size " + std::to_string(esize));
    const auto* ptr = static_cast<const unsigned char*>(data);
    const auto* eptr = static_cast<const unsigned char*>(edata);
    for (size_t i = 0; i < size; ++i)
        if (ptr[i] != eptr[i])
            throw std::runtime_error("checkBlock: bad data at position #" + std::to_string(i));
}

void printBlock(const void* data, size_t size)
{
    const auto* ptr = static_cast<const uint8_t*>(data);
    bool first = true;
    for (size_t i = 0; i < size; ++i)
    {
        if (first)
            first = false;
        else
            std::cout << " ";
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (unsigned)ptr[i];
    }
    std::cout << std::dec << "\n";
}

EVP_PKEY* readPubKey(const std::string& file)
{
    FILE* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("readPubKey: failed to open file '" + file + "'. " + strerror(errno));
    auto res = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (res == nullptr)
        throw std::runtime_error("readPubKey: failed to read public key from '" + file + "'. " + OPENSSLError());
    return res;
}

EVP_PKEY* readPrivateKey(const std::string& file, const std::string& password)
{
    std::vector<unsigned char> pwd(password.begin(), password.end());
    FILE* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("readPrivateKey: failed to open file '" + file + "'. " + strerror(errno));
    auto res = PEM_read_PrivateKey(fp, nullptr, nullptr, pwd.data());
    fclose(fp);
    if (res == nullptr)
        throw std::runtime_error("readPrivateKey: failed to read private key from '" + file + "'. " + OPENSSLError());
    return res;
}

std::array<unsigned char, 32> makeHash(ENGINE* engine, const void* data, size_t size)
{
    const auto* mdt = ENGINE_get_digest(engine, NID_dstu34311);
    if (mdt == nullptr)
        throw std::runtime_error("makeHash: failed to get digest. " + OPENSSLError());

    std::array<unsigned char, 32> res;
    unsigned int s = 0;
    if (EVP_Digest(data, size, res.data(), &s, mdt, engine) == 0)
        throw std::runtime_error("makeHash: failed to calculate digest. " + OPENSSLError());
    if (s != 32)
        throw std::runtime_error("makeHash: unexpected digest size. Expected 32, got " + std::to_string(size));

    return res;
}

std::vector<unsigned char> encrypt(ENGINE* engine, const void* data, size_t size)
{
    const auto* cipher = ENGINE_get_cipher(engine, NID_dstu28147_cfb);
    if (cipher == nullptr)
        throw std::runtime_error("encrypt: failed to get cipher. " + OPENSSLError());

    auto* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("encrypt: failed to create cipher context. " + OPENSSLError());

    if (EVP_EncryptInit_ex(ctx, cipher, engine, DSTU28417::key.data(), DSTU28417::iv.data()) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encrypt: failed to initialize encryption. " + OPENSSLError());
    }

    std::vector<unsigned char> res(size + 8); // 8 - block size
    unsigned char* ptr = res.data();
    int size1 = 0;
    if (EVP_EncryptUpdate(ctx, ptr, &size1, static_cast<const unsigned char*>(data), size) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encrypt: failed to encrypt data. " + OPENSSLError());
    }

    int size2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ptr + size1, &size2) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encrypt: failed to finalize encryption. " + OPENSSLError());
    }
    EVP_CIPHER_CTX_free(ctx);

    res.resize(size1 + size2);
    return res;
}

std::vector<unsigned char> decrypt(ENGINE* engine, const void* data, size_t size)
{
    const auto* cipher = ENGINE_get_cipher(engine, NID_dstu28147_cfb);
    if (cipher == nullptr)
        throw std::runtime_error("decrypt: failed to get cipher. " + OPENSSLError());

    auto* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("decrypt: failed to create cipher context. " + OPENSSLError());

    if (EVP_DecryptInit_ex(ctx, cipher, engine, DSTU28417::key.data(), DSTU28417::iv.data()) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decrypt: failed to initialize encryption. " + OPENSSLError());
    }

    std::vector<unsigned char> res(size + 8); // 8 - block size
    unsigned char* ptr = res.data();
    int size1 = 0;
    if (EVP_DecryptUpdate(ctx, ptr, &size1, static_cast<const unsigned char*>(data), size) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decrypt: failed to encrypt data. " + OPENSSLError());
    }

    int size2 = 0;
    if (EVP_DecryptFinal_ex(ctx, ptr + size1, &size2) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decrypt: failed to finalize encryption. " + OPENSSLError());
    }
    EVP_CIPHER_CTX_free(ctx);

    res.resize(size1 + size2);
    return res;
}

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

void testHash(ENGINE* engine, const void* data, size_t size, const std::string& etalon)
{
    auto hash = makeHash(engine, data, size);
    try
    {
        checkBlock(hash.data(), hash.size(), etalon);
        std::cout << " * hashing - success.\n";
    }
    catch (const std::runtime_error& /*error*/)
    {
        std::cout << " * hashing - failure.\n";
        std::cout << "   Hash:     ";
        printBlock(hash.data(), hash.size());
        std::cout << "   Expected: " << etalon << std::endl;
        throw;
    }
}

void testEncrypt(ENGINE* engine, const void* data, size_t size, const std::string& etalon)
{
    auto cipher = encrypt(engine, data, size);
    try
    {
        checkBlock(cipher.data(), cipher.size(), etalon);
        std::cout << " * encryption - success.\n";
    }
    catch (const std::runtime_error& /*error*/)
    {
        std::cout << " * encryption - failure.\n";
        std::cout << "   Cipher:   ";
        printBlock(cipher.data(), cipher.size());
        std::cout << "   Expected: " << etalon << std::endl;
        throw;
    }
}

void testDecrypt(ENGINE* engine, const void* data, size_t size, const std::string& etalon)
{
    auto plain = decrypt(engine, data, size);
    try
    {
        checkBlock(plain.data(), plain.size(), etalon);
        std::cout << " * decryption - success.\n";
    }
    catch (const std::runtime_error& /*error*/)
    {
        std::cout << " * decryption - failure.\n";
        std::cout << "   Plain:    ";
        printBlock(plain.data(), plain.size());
        std::cout << "   Expected: " << etalon << std::endl;
        throw;
    }
}

void testSignVerify(ENGINE* engine, EVP_PKEY* pub, EVP_PKEY* priv, const void* data, size_t size)
{
    auto* md = ENGINE_get_digest(engine, NID_dstu34311);
    if (md == nullptr)
        throw std::runtime_error("testSignVerify: failed to get digest. " + OPENSSLError());
    verify(engine, md, pub, sign(engine, md, priv, data, size), data, size);
}

void testVerify(ENGINE* engine, EVP_PKEY* pub, const std::string& signature, const void* data, size_t size)
{
    auto* md = ENGINE_get_digest(engine, NID_dstu34311);
    if (md == nullptr)
        throw std::runtime_error("testVerify: failed to get digest. " + OPENSSLError());
    verify(engine, md, pub, makeBlock(signature), data, size);
}

void testVerifyCMS(ENGINE* engine, const std::string& file)
{
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    auto* cms = CMS_ContentInfo_new();
    if (cms == nullptr)
        throw std::runtime_error("testVerifyCMS: failed to read CMS from file '" + file + "'. " + OPENSSLError());
    auto* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("testVerifyCMS: failed to open file '" + file + "'. " + strerror(errno));
    auto* ci = PEM_read_CMS(fp, &cms, nullptr, nullptr);
    if (ci == nullptr)
        throw std::runtime_error("testVerifyCMS: failed to read CMS from file '" + file + "'. " + OPENSSLError());
    if (CMS_verify(ci, nullptr, nullptr, nullptr, nullptr, CMS_NO_SIGNER_CERT_VERIFY) != 1)
    {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("testVerifyCMS: CMS verification failed. " + OPENSSLError());
    }
    CMS_ContentInfo_free(cms);
}

void testHash(ENGINE* engine)
{
    std::cout << "*** Testing DSTU 34311 hash ***\n";
    testHash(engine, "123456", 6,  "96 48 e3 65 0b 97 0d 62 39 bc 76 cd 4c a5 94 4c 2c 9c 27 69 24 02 f4 d4 87 05 88 99 2b e3 7d 5d");
    testHash(engine, "abcdefghijklmnopqrstuvwxyz012345", 32,  "39 e1 ea e5 83 ce 45 bb fd 32 8d 92 20 e7 81 85 aa f9 db 32 4b df bc aa 83 b6 bf 99 65 7b 93 75");
    testHash(engine, "abcdefghijklmnopqrstuvwxyz0123456789", 36,  "0b ce c7 20 2d 92 5b c9 57 93 5a 09 f3 cf a1 35 4f b8 71 3c fc 36 34 55 7c 1d e5 0c 5e 8c 12 51");
    std::cout << "\n";
}

void testCipher(ENGINE* engine)
{
    std::cout << "*** Testing DSTU 28147 cipher in CFB mode ***\n";
    testEncrypt(engine, "123456", 6, "23 a8 38 29 32 ae");
    testDecrypt(engine, "\x23\xa8\x38\x29\x32\xae", 6, "31 32 33 34 35 36");
    testEncrypt(engine, "abcdefgh", 8, "73 f8 68 79 62 fe 53 c9");
    testDecrypt(engine, "\x73\xf8\x68\x79\x62\xfe\x53\xc9", 8, "61 62 63 64 65 66 67 68");
    testEncrypt(engine, "ZXCVBNM<>?ASDFGHJKL:\"|", 22, "48 c2 48 4b 45 d6 79 9d 0d a0 11 cd d2 2b 1b 28 81 ae a4 f4 12 4f");
    testDecrypt(engine, "\x48\xc2\x48\x4b\x45\xd6\x79\x9d\x0d\xa0\x11\xcd\xd2\x2b\x1b\x28\x81\xae\xa4\xf4\x12\x4f", 22, "5A 58 43 56 42 4E 4D 3C 3E 3F 41 53 44 46 47 48 4A 4B 4C 3A 22 7C");
    std::cout << "\n";
}

void testPKey(ENGINE* engine)
{
    auto pub1 = readPubKey("public1.pem");
    auto pk1 = readPrivateKey("private1.pem", "123456");
    auto pub2 = readPubKey("public2.pem");
    auto pk2 = readPrivateKey("private2.pem", "123456");
    std::cout << "*** Testing DSTU 4145 PKI ***\n";
    testSignVerify(engine, pub1, pk1, "123456", 6);
    testSignVerify(engine, pub2, pk2, "123456", 6);
    testVerify(engine, pub1, "04 40 6d 81 5a 1b 1d 5e 82 93 b7 ca aa 6f 77 38 aa ef 85 3f a9 a1 10 cf 11 29 44 ee 28 cb 0d 8c f5 69 30 10 2e e5 b7 bf 04 d7 ec e1 1a f0 0b 5a e2 4f ce d4 b3 e8 5e 22 07 2a ab de 91 ae 50 23 92 00", "123456", 6);
    testVerify(engine, pub2, "04 6c d8 45 c0 45 96 a4 71 1f d9 e8 34 d7 02 22 58 88 58 e5 19 68 66 8c a2 af c7 12 d6 77 88 fc fb 39 73 c9 28 ec 1f 78 c2 d0 ac 55 c0 63 df 14 7d d1 40 b2 db 0d 95 1a 31 93 ec 53 b7 3b 9a cc 88 3d 41 9d f4 d3 65 c2 81 2f 94 2b 1a 1c 2d a9 da 11 bc 22 99 38 25 a5 14 d6 57 37 00 93 05 dc bf c2 f0 1f 02 d0 ad 8e c9 c9 8f 19 cf 2d", "123456", 6);
    testVerifyCMS(engine, "cms.pem");
    EVP_PKEY_free(pub1);
    EVP_PKEY_free(pk1);
    EVP_PKEY_free(pub2);
    EVP_PKEY_free(pk2);
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

    testHash(engine);
    testCipher(engine);
    testPKey(engine);

    ENGINE_finish(engine);
    ENGINE_free(engine);

    EVP_cleanup(); ERR_free_strings(); CRYPTO_cleanup_all_ex_data();

    return 0;
}
