![Build and test](https://github.com/madf/dstu-engine/workflows/Build%20and%20test/badge.svg) [![codecov](https://codecov.io/gh/madf/dstu-engine/branch/main/graph/badge.svg)](https://codecov.io/gh/madf/dstu-engine)

# DSTU OpenSSL engine

A dynamically loadable OpenSSL engine that implements DSTU random bit generator, hash, symmetric cipher and digital signature algorithms.

This project is based on `dstucrypt/openssl-dstu` repository which is a fork of an outdated version of OpenSSL. I put their changes into an external engine and made them compatible with OpenSSL-1.1.0 and later. GOST-related parts are taken from `gost-engine/engine` repository.

#### Standards:
 * DSTU GOST 34.311-95 - hash function.
 * DSTU GOST 28147:2009 - symmetric cipher, CFB mode.
 * DSTU 4145-2002 - elliptic curve digital signature algorithm (LE and BE keys) and random bit generator.

## Building instructions
```
mkdir build
cd build
cmake ..
make
```
#### Build options:
 * BUILD_TESTS - enable testing, default OFF.

## Requirements
 * OpenSSL 1.1.0 or later.

## Links
 * https://github.com/dstucrypt/openssl-dstu
 * https://github.com/gost-engine/engine
