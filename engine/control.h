#pragma once

/* This ctrl command to set custom sbox for MD and CIPHER */
/* p2 should point to char array of 64 bytes (packed format, see default_sbox), p1 should be set to size of the array (64) */
#define DSTU_SET_CUSTOM_SBOX (EVP_MD_CTRL_ALG_CTRL + 1)

#define DSTU_SET_CURVE (EVP_PKEY_ALG_CTRL + 2)
