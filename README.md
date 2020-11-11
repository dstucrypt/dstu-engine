![Build and test](https://github.com/madf/dstu-engine/workflows/Build%20and%20test/badge.svg) [![codecov](https://codecov.io/gh/madf/dstu-engine/branch/main/graph/badge.svg)](https://codecov.io/gh/madf/dstu-engine)

# DSTU OpenSSL engine

A dynamically loadable OpenSSL engine that implements DSTU random bit generator, hash, symmetric cipher and digital signature algorithms.

This project is based on `dstucrypt/openssl-dstu` repository which is a fork of an outdated version of OpenSSL. I put their changes into an external engine and made them compatible with OpenSSL-1.1.0 and later. GOST-related parts are taken from `gost-engine/engine` repository.

#### Standards:
 * DSTU GOST 34.311-95 - hash function.
 * DSTU GOST 28147:2009 - symmetric cipher, CFB mode.
 * DSTU 4145-2002 - elliptic curve digital signature algorithm (LE and BE keys) and random bit generator.

## Building and installation instructions
```
mkdir build
cd build
cmake ..
make
sudo make install
```
#### Build options:
 * BUILD_TESTS - enable testing, default OFF.
 * ENABLE_CODECOV - enable code coverage analysis, default OFF.

## Requirements
 * OpenSSL 1.1.0 or later.

## Usage examples
#### With `openssl` utility
Specify `-engine dstu`:
```
$ openssl cms -verify -engine dstu -in tests/cms.pem -inform PEM -noverify
DSTU engine initialization.
engine "dstu" set.
Verification successful
<?xmlversion="1.0" encoding="windows-1251"?><RQ V="1"><DAT FN="4538765845" TN="345612052809" ZN="" DI="238" V="1"><C T="11"></C><TS>YYYYMMDDHHMMSS</TS></DAT><MAC></MAC></RQ>DSTU engine finalization.
```
#### With API
Load 'dstu' engine with `ENGINE_by_id` and pass it to API functions:
```c++
// Essential for engine loading
OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);

// Get engine handle
auto* engine = ENGINE_by_id("dstu");

const auto* mdt = ENGINE_get_digest(engine, NID_dstu34311);
std::array<unsigned char, 32> res;
unsigned int s = 0;
EVP_Digest(data, size, res.data(), &s, mdt, engine);
// 'res' now contains the hash
```

## Links
 * https://github.com/dstucrypt/openssl-dstu
 * https://github.com/gost-engine/engine
