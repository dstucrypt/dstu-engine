#include "jks.h"

#include "utils.h"

#include <iconv.h>

#include <arpa/inet.h> // ntohl
#include <string.h>
#include <errno.h>

static const char pbes1OID[] = "1.3.6.1.4.1.42.2.19.1";
static const char keyProtectorOID[] = "1.3.6.1.4.1.42.2.17.1.1";

struct jks_st
{
    size_t type;
    size_t entryNum;
    JKSEntry** entries;
};

typedef struct cert_st
{
    char* type;
    X509* cert;
} Cert;

struct jks_entry_st
{
    size_t type;

    // JKS_ENTRY_PRIVATE_KEY only
    char* name;
    size_t keyMaterialSize;
    void* keyMaterial;
    size_t pkeyNum;
    EVP_PKEY** pkeys;

    // JKS_ENTRY_PRIVATE_KEY & JKS_ENTRY_CERT
    size_t certNum;
    Cert** certs;
};

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
    int ds = 0;
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
    int ds = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 0 &&
             EVP_DigestUpdate(ctx, d1, ds1) != 0 &&
             EVP_DigestUpdate(ctx, "Mighty Aphrodite", 16) != 0 &&
             EVP_DigestUpdate(ctx, d2, ds2) != 0 &&
             EVP_DigestFinal_ex(ctx, digest, &ds) != 0;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static Cert* CertNew()
{
    Cert* res = OPENSSL_malloc(sizeof(Cert));
    res->type = NULL;
    res->cert = NULL;
}

static void CertFree(Cert* cert)
{
    if (cert == NULL)
        return;
    if (cert->type != NULL)
        OPENSSL_free(cert->type);
    if (cert->cert != NULL)
        X509_free(cert->cert);
    OPENSSL_free(cert);
}

static JKSEntry* JKSEntryNew(size_t type, size_t certNum)
{
    size_t i = 0;
    JKSEntry* res = OPENSSL_malloc(sizeof(JKSEntry));
    res->type = type;
    res->name = NULL;
    res->certNum = certNum;
    res->certs = OPENSSL_malloc(certNum * sizeof(Cert*));
    res->pkeyNum = 0;
    res->pkeys = NULL;
    res->keyMaterial = NULL;
    res->keyMaterialSize = 0;
    for (i = 0; i < certNum; ++i)
        res->certs[i] = NULL;
    return res;
}

static void JKSEntryFree(JKSEntry* entry)
{
    size_t i = 0;
    if (entry == NULL)
        return;
    if (entry->name != NULL)
        OPENSSL_free(entry->name);
    if (entry->pkeys != NULL)
    {
        for (i = 0; i < entry->pkeyNum; ++i)
            EVP_PKEY_free(entry->pkeys[i]);
        OPENSSL_free(entry->pkeys);
    }
    if (entry->certs != NULL)
    {
        for (i = 0; i < entry->certNum; ++i)
            CertFree(entry->certs[i]);
        OPENSSL_free(entry->certs);
    }
    if (entry->keyMaterial != NULL)
        OPENSSL_free(entry->keyMaterial);
    OPENSSL_free(entry);
}

static JKS* JKSNew(size_t type, size_t entryNum)
{
    JKS* res = OPENSSL_malloc(sizeof(JKS));
    size_t i = 0;
    res->type = type;
    res->entryNum = entryNum;
    res->entries = OPENSSL_malloc(entryNum * sizeof(JKSEntry*));
    for (i = 0; i < entryNum; ++i)
        res->entries[i] = NULL;
    return res;
}

static const void* parseCert(const void* data, JKSEntry* entry, size_t num)
{
    uint16_t typeLength = ntohs(read16(data, 0));
    uint32_t dataLength = ntohl(read32(data, sizeof(typeLength) + typeLength));
    const unsigned char* dataPtr = ptrAt(data, sizeof(typeLength) + typeLength + sizeof(dataLength));
    Cert* res = CertNew();
    char* type = NULL;
    X509* x509 = NULL;

    type = OPENSSL_malloc(typeLength + 1);
    copyAt(data, sizeof(typeLength), type, typeLength);
    type[typeLength] = '\0';

    x509 = d2i_X509(NULL, &dataPtr, dataLength);
    if (x509 == NULL)
    {
        OPENSSL_free(type);
        CertFree(res);
        return NULL;
    }

    res->type = type;
    res->cert = x509;
    entry->certs[num] = res;
    return ptrAt(data, sizeof(typeLength) + typeLength + sizeof(dataLength) + dataLength);
}

static int fromKeyProtector(const void* data, size_t size, const char* pwd16, size_t pwd16Length, EVP_PKEY*** keys, size_t* numKeys)
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

    r = keysFromPKCS8(decrypted, encryptedLength, keys, numKeys);

    OPENSSL_free(decrypted);
    return r;
}

static int fromPBES1(const void* data, size_t size, const void* pwd16, size_t pwd16Length, EVP_PKEY*** keys, size_t* numKeys)
{
    return 0;
}

static const void* parseKey(const void* data, JKSEntry** entry)
{
    uint16_t nameLength = ntohs(read16(data, 0));
    uint32_t dataLength = ntohl(read32(data, sizeof(nameLength) + nameLength + 8)); // 8 bytes - 64-bit timestamp
    uint32_t certNum = ntohl(read32(data, sizeof(nameLength) + nameLength + 8 + 4 + dataLength));
    const unsigned char* dataPtr = ptrAt(data, sizeof(nameLength) + nameLength + 8 + sizeof(dataLength));
    const unsigned char* certPtr = ptrAt(data, sizeof(nameLength) + nameLength + 8 + sizeof(dataLength) + dataLength + sizeof(certNum));
    size_t i = 0;

    *entry = JKSEntryNew(JKS_ENTRY_PRIVATE_KEY, certNum);

    (*entry)->name = OPENSSL_malloc(nameLength + 1);
    copyAt(data, sizeof(nameLength), (*entry)->name, nameLength);
    (*entry)->name[nameLength] = '\0';

    (*entry)->keyMaterialSize = dataLength;
    (*entry)->keyMaterial = OPENSSL_memdup(dataPtr, dataLength);

    for (i = 0; i < certNum; ++i)
    {
        certPtr = parseCert(certPtr, *entry, i);
        if (certPtr == NULL)
        {
            JKSEntryFree(*entry);
            return NULL;
        }
    }
    return certPtr;
}

static const void* parseEntry(const void* data, JKSEntry** entry)
{
    uint32_t tag = ntohl(read32(data, 0));
    switch (tag)
    {
        case JKS_ENTRY_PRIVATE_KEY:
            return parseKey(ptrAt(data, sizeof(tag)), entry);
        case JKS_ENTRY_CERT:
            *entry = JKSEntryNew(JKS_ENTRY_CERT, 1);
            return parseCert(ptrAt(data, sizeof(tag)), *entry, 0);
    }
    return NULL;
}

void JKSFree(JKS* jks)
{
    size_t i = 0;
    if (jks == NULL)
        return;
    if (jks->entries != NULL)
    {
        for (i = 0; i < jks->entryNum; ++i)
            JKSEntryFree(jks->entries[i]);
        OPENSSL_free(jks->entries);
    }
    OPENSSL_free(jks);
}

size_t JKSType(const JKS* jks)
{
    return jks->type;
}

size_t JKSEntryNum(const JKS* jks)
{
    return jks->entryNum;
}

JKSEntry* JKSEntryGet(const JKS* jks, size_t pos)
{
    if (pos < jks->entryNum)
        return jks->entries[pos];
    return NULL;
}

size_t JKSEntryType(const JKSEntry* entry)
{
    return entry->type;
}

int JKSEntryDecrypt(JKSEntry* entry, const char* password, size_t passSize)
{
    void* pwd16 = NULL;
    size_t pwd16Length = 0;
    const unsigned char* dataPtr = entry->keyMaterial;
    X509_SIG* epkInfo = NULL;
    const X509_ALGOR* algo = NULL;
    const ASN1_OBJECT* aobj = NULL;
    ASN1_OBJECT* keyProtector = NULL;
    ASN1_OBJECT* pbes1 = NULL;
    const ASN1_OCTET_STRING* keyData = NULL;
    size_t i = 0;

    if (entry->type != JKS_ENTRY_PRIVATE_KEY)
        return 1;

    if (toUTF16BE(password, passSize, &pwd16, &pwd16Length) == 0)
        return 0;

    epkInfo = d2i_X509_SIG(NULL, &dataPtr, entry->keyMaterialSize);
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
        if (fromKeyProtector(ASN1_STRING_get0_data(keyData), ASN1_STRING_length(keyData), pwd16, pwd16Length, &entry->pkeys, &entry->pkeyNum) == 0)
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
        if (fromPBES1(ASN1_STRING_get0_data(keyData), ASN1_STRING_length(keyData), pwd16, pwd16Length, &entry->pkeys, &entry->pkeyNum) == 0)
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

    if (entry->pkeys == NULL || entry->pkeyNum == 0)
        return 0;

    return 1;
}

const char* JKSEntryPKeyName(const JKSEntry* entry)
{
    return entry->name;
}

size_t JKSEntryPKeyNum(const JKSEntry* entry)
{
    return entry->pkeyNum;
}

const EVP_PKEY* JKSEntryPKey(const JKSEntry* entry, size_t pos)
{
    return entry->pkeys[pos];
}

size_t JKSEntryCertNum(const JKSEntry* entry)
{
    return entry->certNum;
}

const X509* JKSEntryCert(const JKSEntry* entry, size_t pos)
{
    if (pos < entry->certNum)
        return entry->certs[pos]->cert;
    return NULL;
}

const char* JKSEntryCertType(const JKSEntry* entry, size_t pos)
{
    if (pos > entry->certNum)
        return NULL;
    return entry->certs[pos]->type;
}

int parseJKS(const void* data, size_t size, const char* password, size_t passSize, JKS** keys)
{
    const size_t digestLength = 20;
    uint32_t magic = read32(data, 0);
    uint32_t entries = ntohl(read32(data, sizeof(magic) + 4)); // 4 bytes - 32-bit version
    const unsigned char* entryPtr = ptrAt(data, sizeof(magic) + 4 + sizeof(entries));
    unsigned char digest[digestLength];
    size_t type = 0;
    size_t i = 0;
    size_t j = 0;
    JKS* res = NULL;
    JKSEntry* entry = NULL;
    void* pwd16 = NULL;
    size_t pwd16Length = 0;
    // Check MAGIC
    switch (magic)
    {
        case 0xedfeedfe:
            type = JKS_TYPE_JKS;
            break;
        case 0xcececece:
            type = JKS_TYPE_JCEKS;
            break;
        default:
            return 0;
    }
    // Check version
    if (read32(data, sizeof(magic)) != 0x02000000) // 0x00000002 in BE
        return 0;
    if (toUTF16BE(password, passSize, &pwd16, &pwd16Length) == 0)
        return 0;
    res = JKSNew(type, entries);
    for (i = 0; i < entries; ++i)
    {
        entryPtr = parseEntry(entryPtr, &entry);
        if (entryPtr == NULL)
            break;
        res->entries[i] = entry;
    }
    if (i > 0)
    {
        *keys = JKSNew(type, i);
        for (j = 0; j < i; ++j)
        {
            (*keys)->entries[j] = res->entries[j];
            res->entries[j] = NULL;
        }
    }
    JKSFree(res);

    if (whiteHash(pwd16, pwd16Length, data, entryPtr - (const unsigned char*)data, digest) == 0)
    {
        OPENSSL_free(pwd16);
        return 0;
    }
    OPENSSL_free(pwd16);

    for (j = 0; j < digestLength; ++j)
        if (digest[j] != entryPtr[j])
            return 0;

    return i > 0 ? 1 : 0;
}

int readJKS(FILE* fp, const char* password, size_t passSize, JKS** keys)
{
    int res = 0;
    BIO* bio = BIO_new_fp(fp, 0);
    if (!bio)
        return 0;
    res = readJKS_bio(bio, password, passSize, keys);
    BIO_free(bio);
    return res;
}

int readJKS_bio(BIO* bio, const char* password, size_t passSize, JKS** keys)
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
    res = parseJKS(ptr, bytes, password, passSize, keys);
    BIO_free(mem);
    return res;
}
