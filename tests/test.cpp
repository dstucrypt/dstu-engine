#include <openssl/evp.h>
#include <openssl/pem.h>
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

struct Seal
{
    Seal(size_t ivSize, size_t dataSize) : ekl(0), iv(ivSize), data(dataSize) {}
    size_t ekl;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> data;
};

Seal seal(ENGINE* engine, EVP_PKEY* pk, const void* data, size_t size)
{
    auto* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("seal: failed to create cipher context. " + OPENSSLError());

    auto* cipher = EVP_aes_256_cbc();

    Seal res(EVP_CIPHER_iv_length(cipher), EVP_PKEY_size(pk));

    std::vector<unsigned char> ek(res.ekl);
    unsigned char* ivPtr = res.iv.size() == 0 ? nullptr : res.iv.data();
    unsigned char* ekPtr = ek.data();
    int eks = ek.size();
    if (EVP_SealInit(ctx, EVP_aes_256_cbc(), &ekPtr, &eks, ivPtr, &pk, 1) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("seal: failed to initialize encryption. " + OPENSSLError());
    }
    res.ekl = eks;

    unsigned char* ptr = res.data.data();
    int size1 = 0;
    if (EVP_SealUpdate(ctx, ptr, &size1, static_cast<const unsigned char*>(data), size) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("seal: failed to encrypt data. " + OPENSSLError());
    }

    int size2 = 0;
    if (EVP_SealFinal(ctx, ptr + size1, &size2) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("seal: failed to finalize encryption. " + OPENSSLError());
    }
    EVP_CIPHER_CTX_free(ctx);

    res.data.resize(size1 + size2);
    return res;
}

std::vector<unsigned char> unseal(ENGINE* engine, EVP_PKEY* pk, const Seal& data)
{
    auto* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("unseal: failed to create cipher context. " + OPENSSLError());

    auto* cipher = EVP_aes_256_cbc();

    std::vector<unsigned char> ek(data.ekl);
    std::vector<unsigned char> iv(data.iv);
    unsigned char* ivPtr = iv.size() == 0 ? nullptr : iv.data();
    if (EVP_OpenInit(ctx, EVP_aes_256_cbc(), ek.data(), data.ekl, ivPtr, pk) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("unseal: failed to initialize encryption. " + OPENSSLError());
    }

    std::vector<unsigned char> res(EVP_PKEY_size(pk));
    unsigned char* ptr = res.data();
    int size1 = 0;
    if (EVP_OpenUpdate(ctx, ptr, &size1, data.data.data(), data.data.size()) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("unseal: failed to encrypt data. " + OPENSSLError());
    }

    int size2 = 0;
    if (EVP_OpenFinal(ctx, ptr + size1, &size2) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("unseal: failed to finalize encryption. " + OPENSSLError());
    }
    EVP_CIPHER_CTX_free(ctx);

    res.resize(size1 + size2);
    return res;
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

void testSeal(ENGINE* engine, EVP_PKEY* pub, EVP_PKEY* pk, const void* data, size_t size)
{
    auto cipher = seal(engine, pub, data, size);
    auto plain = unseal(engine, pk, cipher);
    try
    {
        checkBlock(plain.data(), plain.size(), data, size);
        std::cout << " * seal - success.\n";
    }
    catch (const std::runtime_error& /*error*/)
    {
        std::cout << " * seal - failure.\n";
        std::cout << "   Unsealed: ";
        printBlock(plain.data(), plain.size());
        std::cout << "   Expected: ";
        printBlock(data, size);
        throw;
    }
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
    testSeal(engine, pub1, pk1, "123456", 6);
    testSeal(engine, pub2, pk2, "123456", 6);
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
