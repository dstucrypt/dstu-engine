![Build and test](https://github.com/madf/dstu-engine/workflows/Build%20and%20test/badge.svg) [![codecov](https://codecov.io/gh/madf/dstu-engine/branch/main/graph/badge.svg)](https://codecov.io/gh/madf/dstu-engine)

# DSTU OpenSSL engine and key reading library

A dynamically loadable OpenSSL engine that implements DSTU random bit generator, hash, symmetric cipher and digital signature algorithms.

This project is based on `dstucrypt/openssl-dstu` repository which is a fork of an outdated version of OpenSSL. I put their changes into an external engine and made them compatible with OpenSSL-1.1.0 and later. GOST-related parts are taken from `gost-engine/engine` repository.

`keylib` is a library for reading different key containers.

#### Standards:
 * DSTU GOST 34.311-95 - hash function.
 * DSTU GOST 28147:2009 - symmetric cipher, CFB mode.
 * DSTU 4145-2002 - elliptic curve digital signature algorithm (LE and BE keys) and random bit generator.

#### Key containers:
 * Key-6.dat - custom IIT key container with password protection.

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

## Documentation
[Library reference](https://madf.github.io/dstu-engine/)

## Usage examples
#### With `openssl` utility
Specify `-engine dstu`:
```
$ openssl cms -verify -engine dstu -in tests/cms.pem -inform PEM -noverify
engine "dstu" set.
Verification successful
<?xmlversion="1.0" encoding="windows-1251"?><RQ V="1"><DAT FN="4538765845" TN="345612052809" ZN="" DI="238" V="1"><C T="11"></C><TS>YYYYMMDDHHMMSS</TS></DAT><MAC></MAC></RQ>
```
#### With Docker
```
docker build -t dstu-engine .
dockerrun -td dstu-engine
docker exec  $(docker ps | grep dstu | cut -d' ' -f1)  openssl cms -verify -engine dstu -in dstu-engine/tests/cms.pem -inform PEM -noverify
```
#### With API
Load 'dstu' engine with `ENGINE_by_id` and pass it to API functions:
```c++
// Essential for engine loading
OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);

// Get engine handle
auto* engine = ENGINE_by_id("dstu");
ENGINE_init(engine);

const auto* mdt = ENGINE_get_digest(engine, NID_dstu34311);
std::array<unsigned char, 32> res;
unsigned int s = 0;
EVP_Digest(data, size, res.data(), &s, mdt, engine);
// 'res' now contains the hash
```

#### Keylib API
```c++
// Essential for engine loading
OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);

// Get engine handle
auto* engine = ENGINE_by_id("dstu");
ENGINE_init(engine);

ENGINE_set_default(engine, ENGINE_METHOD_ALL);

auto* fp = fopen(file.c_str(), "r");

// Key-6.dat may contain 1 or 2 keys
EVP_PKEY** keys = nullptr;
size_t numKeys = 0;
readKey6(fp, password.c_str(), password.length(), &keys, &numKeys);

// Delete all keys after use
for (size_t i = 0; i < numKeys; ++i)
    EVP_PKEY_free(keys[i]);
OPENSSL_free(keys);

fclose(fp);
```

## Links
 * https://github.com/dstucrypt/openssl-dstu
 * https://github.com/gost-engine/engine
