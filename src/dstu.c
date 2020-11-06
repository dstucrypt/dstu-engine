#include "md.h"
#include "cipher.h"
#include "rbg.h"
#include "pmeth.h"
#include "ameth.h"
#include "err.h"

#include <openssl/engine.h>

#include <string.h>

static const char *engine_dstu_id = "dstu";
static const char *engine_dstu_name = "DSTU engine by Maksym Mamontov";


static int dstu_nids[] =
{
    NID_dstu4145le, NID_dstu4145be
};
static int digest_nids[] =
{
    NID_dstu34311
};
static int cipher_nids[] =
{
    NID_dstu28147_cfb
};

static const int DSTU_ENGINE_FLAGS =
    ENGINE_METHOD_PKEY_METHS | ENGINE_METHOD_PKEY_ASN1_METHS |
    ENGINE_METHOD_DIGESTS | ENGINE_METHOD_CIPHERS | ENGINE_METHOD_RAND;

static EVP_MD *dstu_md = NULL;
static EVP_CIPHER *dstu_cipher = NULL;
static EVP_PKEY_METHOD *dstu_pkey_methods[] = {NULL, NULL};
static EVP_PKEY_ASN1_METHOD *dstu_asn1_methods[] = {NULL, NULL};

static EVP_MD *dstu_md_get()
{
    if (dstu_md == NULL)
        dstu_md = dstu_digest_new();
    return dstu_md;
}

static EVP_CIPHER *dstu_cipher_get()
{
    if (dstu_cipher == NULL)
        dstu_cipher = dstu_cipher_new();
    return dstu_cipher;
}

static EVP_PKEY_METHOD *dstu_pkey_meth_get(int nid)
{
    int i = 0;
    for (i = 0; i < sizeof(dstu_nids) / sizeof(int); ++i)
    {
        if (nid == dstu_nids[i])
        {
            if (dstu_pkey_methods[i] == NULL)
                dstu_pkey_methods[i] = dstu_pkey_meth_new(nid);
            return dstu_pkey_methods[i];
        }
    }

    return NULL;
}

static EVP_PKEY_ASN1_METHOD *dstu_asn1_meth_get(int nid)
{
    int i = 0;
    for (i = 0; i < sizeof(dstu_nids) / sizeof(int); ++i)
    {
        if (nid == dstu_nids[i])
        {
            if (dstu_asn1_methods[i] == NULL)
                dstu_asn1_methods[i] = dstu_asn1_meth_new(nid);
            return dstu_asn1_methods[i];
        }
    }

    return NULL;
}

static int dstu_engine_init(ENGINE *e)
{
    printf("DSTU engine initialization.\n");
    return 1;
}

static int dstu_engine_finish(ENGINE *e)
{
    int i;
    printf("DSTU engine finalization.\n");
    for (i = 0; i < sizeof(dstu_asn1_methods) / sizeof(EVP_PKEY_ASN1_METHOD*); ++i)
        if (dstu_asn1_methods[i] != NULL)
            dstu_asn1_meth_free(dstu_asn1_methods[i]);
    for (i = 0; i < sizeof(dstu_pkey_methods) / sizeof(EVP_PKEY_METHOD*); ++i)
        if (dstu_pkey_methods[i] != NULL)
            dstu_pkey_meth_free(dstu_pkey_methods[i]);
    dstu_cipher_free(dstu_cipher);
    dstu_digest_free(dstu_md);

    ERR_unload_DSTU_strings();

    return 1;
}

static int dstu_digests(ENGINE *e, const EVP_MD **digest, const int **nids,
                        int nid)
{
    if (digest && nid)
    {
        if (NID_dstu34311 == nid)
        {
            *digest = dstu_md_get();
            return 1;
        }
        else
            return 0;
    }
    else
    {
        if (!nids)
            return -1;
        *nids = digest_nids;
        return 1;
    }
}

static int dstu_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                        int nid)
{
    if (cipher && nid)
    {
        if (NID_dstu28147_cfb == nid)
        {
            *cipher = dstu_cipher_get();
            return 1;
        }
        else
            return 0;
    }
    else
    {
        if (!nids)
            return -1;
        *nids = cipher_nids;
        return 1;
    }
}

static int dstu_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
                           int nid)
{
    if (!pmeth)
    {
        *nids = dstu_nids;
        return sizeof(dstu_nids) / sizeof(int);
    }

    *pmeth = dstu_pkey_meth_get(nid);
    if (*pmeth != NULL)
        return 1;

    return 0;
}

static int dstu_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                           const int **nids, int nid)
{
    if (!ameth)
    {
        *nids = dstu_nids;
        return sizeof(dstu_nids) / sizeof(int);
    }

    *ameth = dstu_asn1_meth_get(nid);
    if (*ameth != NULL)
        return 1;

    return 0;
}

static int dstu_bind(ENGINE *e, const char *id)
{
    if (id && strcmp(id, engine_dstu_id))
        return 0;

    if (!ENGINE_set_id(e, engine_dstu_id))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }
    if (!ENGINE_set_name(e, engine_dstu_name))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_init_function(e, dstu_engine_init))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }
    if (!ENGINE_set_finish_function(e, dstu_engine_finish))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_digests(e, dstu_digests))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_ciphers(e, dstu_ciphers))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_RAND(e, &dstu_rand_meth))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_pkey_meths(e, dstu_pkey_meths))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_pkey_asn1_meths(e, dstu_asn1_meths))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_set_flags(e, DSTU_ENGINE_FLAGS))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_register_digests(e))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_register_ciphers(e))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_register_pkey_meths(e))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!ENGINE_register_pkey_asn1_meths(e))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
        return 0;
    }

    if (!EVP_add_digest(dstu_md_get()))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_EVP_LIB);
        return 0;
    }

    if (!EVP_add_cipher(dstu_cipher_get()))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_EVP_LIB);
        return 0;
    }

    /* Adding our algorithms to support PBKDF2 */
    if (!EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, NID_hmacWithDstu34311, -1, NID_dstu34311, NULL))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_EVP_LIB);
        return 0;
    }

    ERR_load_DSTU_strings();

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(dstu_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
