#include "jks.h"

#include "keystore_internal.h"
#include "utils.h"

#include <iconv.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <arpa/inet.h> // ntohl
#include <string.h>
#include <stdint.h>
#include <errno.h>

static const char pbes1OID[] = "1.3.6.1.4.1.42.2.19.1";
static const char keyProtectorOID[] = "1.3.6.1.4.1.42.2.17.1.1";

#define JKS_ENTRY_PRIVATE_KEY 1
#define JKS_ENTRY_CERT 2

static const void* ptrAt(const void* base, size_t shift)
{
    return ((const unsigned char*)base) + shift;
}

static void copyAt(const void* base, size_t shift, void* dest, size_t size)
{
    memcpy(dest, ptrAt(base, shift), size);
}

static uint16_t read16(const void* base, size_t shift)
{
    uint16_t res = 0;
    copyAt(base, shift, &res, sizeof(res));
    return res;
}

static uint32_t read32(const void* base, size_t shift)
{
    uint32_t res = 0;
    copyAt(base, shift, &res, sizeof(res));
    return res;
}

static int toUTF16BE(const char* source, size_t size, void** dest, size_t* dsize)
{
    size_t resSize = size * 2;
    size_t bufSize = size;
    size_t ds = resSize;
    size_t ss = size;
    BIO *res = BIO_new(BIO_s_mem());
    char* buf = OPENSSL_malloc(resSize);
    char* d = buf;
    const char* s = source;
    iconv_t cd = iconv_open("utf-16be", "utf-8");
    size_t r = 0;
    if (cd == (iconv_t)-1)
    {
        OPENSSL_free(res);
        return 0;
    }
    while (ss > 0)
    {
        d = buf;
        ds = bufSize;
        r = iconv(cd, (char**)&s, &ss, &d, &ds);
        if (d != buf)
            BIO_write(res, buf, d - buf);
        if (r != (size_t)-1)
            break;
        if (errno != E2BIG)
        {
            iconv_close(cd);
            OPENSSL_free(buf);
            BIO_free(res);
            return 0;
        }
        bufSize *= 2;
        buf = OPENSSL_realloc(buf, bufSize);
    }
    for (;;)
    {
        d = buf;
        ds = bufSize;
        r = iconv(cd, NULL, NULL, &d, &ds);
        if (d != buf)
            BIO_write(res, buf, d - buf);
        if (r != (size_t)-1)
            break;
        if (errno != E2BIG)
        {
            iconv_close(cd);
            OPENSSL_free(buf);
            BIO_free(res);
            return 0;
        }
        bufSize *= 2;
        buf = OPENSSL_realloc(buf, bufSize);
    }
    OPENSSL_free(buf);
    iconv_close(cd);
    *dsize = BIO_get_mem_data(res, &d);
    if (d == NULL || *dsize == 0)
    {
        BIO_free(res);
        return 0;
    }
    *dest = OPENSSL_malloc(*dsize);
    memcpy(*dest, d, *dsize);
    BIO_free(res);
    return 1;
}

static int twoHash(const void* d1, size_t ds1, const void* d2, size_t ds2, void* digest)
{
    unsigned int ds = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 0 &&
             EVP_DigestUpdate(ctx, d1, ds1) != 0 &&
             EVP_DigestUpdate(ctx, d2, ds2) != 0 &&
             EVP_DigestFinal_ex(ctx, digest, &ds) != 0;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int whiteHash(const void* d1, size_t ds1, const void* d2, size_t ds2, void* digest)
{
    unsigned int ds = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 0 &&
             EVP_DigestUpdate(ctx, d1, ds1) != 0 &&
             EVP_DigestUpdate(ctx, "Mighty Aphrodite", 16) != 0 &&
             EVP_DigestUpdate(ctx, d2, ds2) != 0 &&
             EVP_DigestFinal_ex(ctx, digest, &ds) != 0;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static const void* parseCert(const void* data, KeyStore* ks, size_t* certPos)
{
    uint16_t typeLength = ntohs(read16(data, 0));
    uint32_t dataLength = ntohl(read32(data, sizeof(typeLength) + typeLength));
    const unsigned char* dataPtr = ptrAt(data, sizeof(typeLength) + typeLength + sizeof(dataLength));
    X509* x509 = NULL;

    x509 = d2i_X509(NULL, &dataPtr, dataLength);
    if (x509 == NULL)
        return NULL;

    KeyStore* tks = KeyStoreNew(0, 1);

    KeyStoreSetCert(tks, 0, x509);
    KeyStoreAppend(ks, tks);

    KeyStoreFree(tks);

    if (certPos != NULL)
        ++(*certPos);

    return ptrAt(data, sizeof(typeLength) + typeLength + sizeof(dataLength) + dataLength);
}

static int fromKeyProtector(const void* data, size_t size, const char* pwd16, size_t pwd16Length, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    const size_t saltLength = 20;
    const size_t digestLength = 20;
    const size_t encryptedLength = size - saltLength - digestLength;
    const size_t rounds = encryptedLength % digestLength > 0 ? 1 + encryptedLength / digestLength : encryptedLength / digestLength;
    const unsigned char* encrypted = ptrAt(data, saltLength);
    unsigned char* decrypted = NULL;
    const unsigned char* check = ptrAt(data, saltLength + encryptedLength);
    unsigned char digest[digestLength];
    size_t i = 0;
    size_t j = 0;
    size_t pos = 0;
    int r = 0;

    copyAt(data, 0, digest, saltLength);

    decrypted = OPENSSL_malloc(encryptedLength);
    for (i = 0; i < rounds; ++i)
    {
        if (!twoHash(pwd16, pwd16Length, digest, digestLength, digest))
        {
            OPENSSL_free(decrypted);
            return 0;
        }
        for (j = 0; j < digestLength; ++j)
        {
            decrypted[pos] = encrypted[pos] ^ digest[j];
            ++pos;
            if (pos == encryptedLength)
                break;
        }
    }

    if (!twoHash(pwd16, pwd16Length, decrypted, encryptedLength, digest))
    {
        OPENSSL_free(decrypted);
        return 0;
    }

    for (j = 0; j < digestLength; ++j)
        if (digest[j] != check[j])
        {
            OPENSSL_free(decrypted);
            return 0;
        }

    KeyStore* tks = NULL;

    r = keysFromPKCS8(decrypted, encryptedLength, &tks);

    if (r != 0)
    {
        KeyStoreAppend(ks, tks);
        if (keyPos != NULL)
            *keyPos += KeyStoreKeyNum(tks);
        if (certPos != NULL)
            *certPos += KeyStoreCertNum(tks);
    }

    KeyStoreFree(tks);

    OPENSSL_free(decrypted);
    return r;
}

static int fromPBES1(const void* data, size_t size, const void* pwd16, size_t pwd16Length, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    (void) data; //Unused
    (void) size; //Unused
    (void) pwd16; //Unused
    (void) pwd16Length; //Unused
    (void) ks; //Unused
    (void) keyPos; //Unused
    (void) certPos; //Unused
    return 0;
}

static int decryptKey(const void* data, size_t dataSize, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    void* pwd16 = NULL;
    size_t pwd16Length = 0;
    const unsigned char* dataPtr = data;
    X509_SIG* epkInfo = NULL;
    const X509_ALGOR* algo = NULL;
    const ASN1_OBJECT* aobj = NULL;
    ASN1_OBJECT* keyProtector = NULL;
    ASN1_OBJECT* pbes1 = NULL;
    const ASN1_OCTET_STRING* keyData = NULL;

    if (toUTF16BE(password, passSize, &pwd16, &pwd16Length) == 0)
        return 0;

    epkInfo = d2i_X509_SIG(NULL, &dataPtr, dataSize);
    if (epkInfo == NULL)
    {
        OPENSSL_free(pwd16);
        return 0;
    }

    X509_SIG_get0(epkInfo, &algo, &keyData);
    X509_ALGOR_get0(&aobj, NULL, NULL, algo);
    keyProtector = OBJ_txt2obj(keyProtectorOID, 1);
    pbes1 = OBJ_txt2obj(pbes1OID, 1);

    if (OBJ_cmp(aobj, keyProtector) == 0)
    {
        if (fromKeyProtector(ASN1_STRING_get0_data(keyData), ASN1_STRING_length(keyData), pwd16, pwd16Length, ks, keyPos, certPos) == 0)
        {
            ASN1_OBJECT_free(pbes1);
            ASN1_OBJECT_free(keyProtector);
            X509_SIG_free(epkInfo);
            OPENSSL_free(pwd16);
            return 0;
        }
    }
    else if (OBJ_cmp(aobj, pbes1) == 0)
    {
        if (fromPBES1(ASN1_STRING_get0_data(keyData), ASN1_STRING_length(keyData), pwd16, pwd16Length, ks, keyPos, certPos) == 0)
        {
            ASN1_OBJECT_free(pbes1);
            ASN1_OBJECT_free(keyProtector);
            X509_SIG_free(epkInfo);
            OPENSSL_free(pwd16);
            return 0;
        }
    }

    ASN1_OBJECT_free(pbes1);
    ASN1_OBJECT_free(keyProtector);
    OPENSSL_free(pwd16);
    X509_SIG_free(epkInfo);

    return 1;
}

static const void* parseKey(const void* data, const char* keyPass, size_t keyPassSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    uint16_t nameLength = ntohs(read16(data, 0));
    uint32_t dataLength = ntohl(read32(data, sizeof(nameLength) + nameLength + 8)); // 8 bytes - 64-bit timestamp
    uint32_t certNum = ntohl(read32(data, sizeof(nameLength) + nameLength + 8 + 4 + dataLength));
    const unsigned char* dataPtr = ptrAt(data, sizeof(nameLength) + nameLength + 8 + sizeof(dataLength));
    const unsigned char* certPtr = ptrAt(data, sizeof(nameLength) + nameLength + 8 + sizeof(dataLength) + dataLength + sizeof(certNum));
    size_t i = 0;

    if (decryptKey(dataPtr, dataLength, keyPass, keyPassSize, ks, keyPos, certPos) == 0)
        return NULL;

    for (i = 0; i < certNum; ++i)
    {
        certPtr = parseCert(certPtr, ks, certPos);
        if (certPtr == NULL)
            return NULL;
    }
    return certPtr;
}

static const void* parseEntry(const void* data, const char* keyPass, size_t keyPassSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    uint32_t tag = ntohl(read32(data, 0));
    switch (tag)
    {
        case JKS_ENTRY_PRIVATE_KEY:
            return parseKey(ptrAt(data, sizeof(tag)), keyPass, keyPassSize, ks, keyPos, certPos);
        case JKS_ENTRY_CERT:
            return parseCert(ptrAt(data, sizeof(tag)), ks, certPos);
    }
    return NULL;
}

int parseJKS(const void* data, size_t size, const char* storagePass, size_t storagePassSize, const char* keyPass, size_t keyPassSize, KeyStore** ks)
{
    const size_t digestLength = 20;
    uint32_t magic = read32(data, 0);
    uint32_t entries = ntohl(read32(data, sizeof(magic) + 4)); // 4 bytes - 32-bit version
    const unsigned char* entryPtr = ptrAt(data, sizeof(magic) + 4 + sizeof(entries));
    unsigned char digest[digestLength];
    size_t i = 0;
    size_t j = 0;
    void* pwd16 = NULL;
    size_t pwd16Length = 0;
    size_t keyPos = 0;
    size_t certPos = 0;

    (void) size; // Unused

    // Check MAGIC
    if (magic != 0xedfeedfe && // JKS
        magic != 0xcececece)   // JCEKS
        return 0;

    // Check version
    if (read32(data, sizeof(magic)) != 0x02000000) // 0x00000002 in BE
        return 0;
    if (toUTF16BE(storagePass, storagePassSize, &pwd16, &pwd16Length) == 0)
        return 0;

    *ks = KeyStoreNew(0, 0); // Start from zero

    for (i = 0; i < entries; ++i)
    {
        entryPtr = parseEntry(entryPtr, keyPass, keyPassSize, *ks, &keyPos, &certPos);
        if (entryPtr == NULL)
            break;
    }

    if (entryPtr == NULL)
    {
        KeyStoreFree(*ks);
        return 0;
    }

    if (whiteHash(pwd16, pwd16Length, data, entryPtr - (const unsigned char*)data, digest) == 0)
    {
        KeyStoreFree(*ks);
        OPENSSL_free(pwd16);
        return 0;
    }
    OPENSSL_free(pwd16);

    for (j = 0; j < digestLength; ++j)
        if (digest[j] != entryPtr[j])
        {
            KeyStoreFree(*ks);
            return 0;
        }

    return 1;
}

int readJKS(FILE* fp, const char* storagePass, size_t storagePassSize, const char* keyPass, size_t keyPassSize, KeyStore** ks)
{
    int res = 0;
    BIO* bio = BIO_new_fp(fp, 0);
    if (!bio)
        return 0;
    res = readJKS_bio(bio, storagePass, storagePassSize, keyPass, keyPassSize, ks);
    BIO_free(bio);
    return res;
}

int readJKS_bio(BIO* bio, const char* storagePass, size_t storagePassSize, const char* keyPass, size_t keyPassSize, KeyStore** ks)
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
    res = parseJKS(ptr, bytes, storagePass, storagePassSize, keyPass, keyPassSize, ks);
    BIO_free(mem);
    return res;
}
