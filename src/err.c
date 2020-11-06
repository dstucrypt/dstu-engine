/* err.c */
/* ====================================================================
 * Copyright (c) 1999-2013 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "err.h"
#include <openssl/err.h>
#include <stdio.h>

#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(0, func, 0)
#define ERR_REASON(reason) ERR_PACK(0, 0, reason)

static ERR_STRING_DATA DSTU_str_functs[] =
{
    {ERR_FUNC(DSTU_F_BIND_DSTU),              "BIND_DSTU"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PARAM_COPY),   "DSTU_ASN1_PARAM_COPY"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PARAM_DECODE), "DSTU_ASN1_PARAM_DECODE"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PARAM_ENCODE), "DSTU_ASN1_PARAM_ENCODE"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PARAM_PRINT),  "DSTU_ASN1_PARAM_PRINT"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PRIV_DECODE),  "DSTU_ASN1_PRIV_DECODE"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PRIV_ENCODE),  "DSTU_ASN1_PRIV_ENCODE"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PUB_DECODE),   "DSTU_ASN1_PUB_DECODE"},
    {ERR_FUNC(DSTU_F_DSTU_ASN1_PUB_ENCODE),   "DSTU_ASN1_PUB_ENCODE"},
    {ERR_FUNC(DSTU_F_DSTU_DO_SIGN),           "DSTU_DO_SIGN"},
    {ERR_FUNC(DSTU_F_DSTU_DO_VERIFY),         "DSTU_DO_VERIFY"},
    {ERR_FUNC(DSTU_F_DSTU_PKEY_CTRL),         "DSTU_PKEY_CTRL"},
    {ERR_FUNC(DSTU_F_DSTU_PKEY_INIT_BE),      "DSTU_PKEY_INIT_BE"},
    {ERR_FUNC(DSTU_F_DSTU_PKEY_INIT_LE),      "DSTU_PKEY_INIT_LE"},
    {ERR_FUNC(DSTU_F_DSTU_PKEY_KEYGEN),       "DSTU_PKEY_KEYGEN"},
    {ERR_FUNC(DSTU_F_DSTU_PKEY_SIGN),         "DSTU_PKEY_SIGN"},
    {ERR_FUNC(DSTU_F_DSTU_PKEY_VERIFY),       "DSTU_PKEY_VERIFY"},
    {0, NULL}
};

static ERR_STRING_DATA DSTU_str_reasons[] =
{
    {ERR_REASON(DSTU_R_AMETH_INIT_FAILED),            "ameth init failed"},
    {ERR_REASON(DSTU_R_ASN1_PARAMETER_ENCODE_FAILED), "asn1 parameter encode failed"},
    {ERR_REASON(DSTU_R_INCORRECT_FIELD_TYPE) ,        "incorrect field type"},
    {ERR_REASON(DSTU_R_INVALID_ASN1_PARAMETERS),      "invalid asn1 parameters"},
    {ERR_REASON(DSTU_R_INVALID_DIGEST_TYPE),          "invalid digest type"},
    {ERR_REASON(DSTU_R_NOT_DSTU_KEY),                 "not dstu key"},
    {ERR_REASON(DSTU_R_PMETH_INIT_FAILED),            "pmeth init failed"},
    {ERR_REASON(DSTU_R_POINT_COMPRESS_FAILED),        "point compress failed"},
    {ERR_REASON(DSTU_R_POINT_UNCOMPRESS_FAILED),      "point uncompress failed"},
    {0, NULL}
};

#endif

static ERR_STRING_DATA DSTU_lib_name[] =
{
    {0, "dstu"},
    {0, NULL}
};

static int DSTU_lib_error_code = 0;
static int DSTU_error_init = 1;

void ERR_load_DSTU_strings(void)
{
    if (DSTU_lib_error_code == 0)
        DSTU_lib_error_code = ERR_get_next_error_library();

    if (DSTU_error_init)
    {
        DSTU_error_init = 0;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(DSTU_lib_error_code, DSTU_str_functs);
        ERR_load_strings(DSTU_lib_error_code, DSTU_str_reasons);
#endif

        DSTU_lib_name->error = ERR_PACK(DSTU_lib_error_code, 0, 0);
        ERR_load_strings(0, DSTU_lib_name);
    }
}

void ERR_unload_DSTU_strings(void)
{
    if (DSTU_error_init == 0)
    {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(DSTU_lib_error_code, DSTU_str_functs);
        ERR_unload_strings(DSTU_lib_error_code, DSTU_str_reasons);
#endif

        ERR_unload_strings(0, DSTU_lib_name);
        DSTU_error_init = 1;
    }
}

void ERR_DSTU_error(int function, int reason, char *file, int line)
{
    if (DSTU_lib_error_code == 0)
        DSTU_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(DSTU_lib_error_code, function, reason, file, line);
}
