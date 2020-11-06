/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#ifndef HEADER_DSTU_ERR_H
#define HEADER_DSTU_ERR_H

#include <openssl/err.h>

#ifdef  __cplusplus
extern "C" {
#endif

void ERR_load_DSTU_strings(void);
void ERR_unload_DSTU_strings(void);
void ERR_DSTU_error(int function, int reason, char *file, int line);
#define DSTUerr(f, r) ERR_DSTU_error((f), (r), __FILE__, __LINE__)

/* Error codes for the DSTU functions. */

/* Function codes. */
#define DSTU_F_BIND_DSTU              100
#define DSTU_F_DSTU_ASN1_PARAM_COPY   102
#define DSTU_F_DSTU_ASN1_PARAM_DECODE 101
#define DSTU_F_DSTU_ASN1_PARAM_ENCODE 103
#define DSTU_F_DSTU_ASN1_PARAM_PRINT  104
#define DSTU_F_DSTU_ASN1_PRIV_DECODE  105
#define DSTU_F_DSTU_ASN1_PRIV_ENCODE  106
#define DSTU_F_DSTU_ASN1_PUB_DECODE   107
#define DSTU_F_DSTU_ASN1_PUB_ENCODE   108
#define DSTU_F_DSTU_DO_SIGN           109
#define DSTU_F_DSTU_DO_VERIFY         110
#define DSTU_F_DSTU_PKEY_CTRL         116
#define DSTU_F_DSTU_PKEY_INIT_BE      111
#define DSTU_F_DSTU_PKEY_INIT_LE      112
#define DSTU_F_DSTU_PKEY_KEYGEN       113
#define DSTU_F_DSTU_PKEY_SIGN         114
#define DSTU_F_DSTU_PKEY_VERIFY       115

/* Reason codes. */
#define DSTU_R_AMETH_INIT_FAILED            100
#define DSTU_R_ASN1_PARAMETER_ENCODE_FAILED 103
#define DSTU_R_INCORRECT_FIELD_TYPE         107
#define DSTU_R_INVALID_ASN1_PARAMETERS      102
#define DSTU_R_INVALID_DIGEST_TYPE          108
#define DSTU_R_NOT_DSTU_KEY                 104
#define DSTU_R_PMETH_INIT_FAILED            101
#define DSTU_R_POINT_COMPRESS_FAILED        105
#define DSTU_R_POINT_UNCOMPRESS_FAILED      106

#ifdef  __cplusplus
}
#endif
#endif
