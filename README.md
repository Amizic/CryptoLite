# CryptoLite

A small, clean **Windows C++17 wrapper around OpenSSL** with exactly three
classes:

| Class                    | Purpose                          | Underlying OpenSSL primitive     |
|--------------------------|----------------------------------|----------------------------------|
| `CryptoLite::Aes256`      | Symmetric encryption             | AES-256-GCM (authenticated)      |
| `CryptoLite::Rsa4096`     | Asymmetric public-key encryption | RSA-4096 with OAEP-SHA256        |
| `CryptoLite::PostQuantum` | Post-quantum hybrid encryption   | ML-KEM-768 (Kyber) + AES-256-GCM |

Every class has the same shape of API: generate keys, save/load keys
(asymmetric only), encrypt, decrypt, and automatic memory cleanup on
destruction.

> **Requirements**
> - Windows with a C++17 compiler (MinGW-w64 GCC or MSVC).
> - **OpenSSL 3.5.0 or newer** (the `PostQuantum` class uses ML-KEM, added in
>   OpenSSL 3.5).
> - CMake 3.16 or newer.

---

## CryptoLite vs Crypto

This workspace ships two related libraries. Both implement the same
algorithms (AES-256-GCM, RSA-4096, ML-KEM-768) with aligned return codes and
naming. They differ in one design decision — key ownership:

* **CryptoLite (this one)** — each object **owns its key** (stored
  inside, non-copyable, mutex-protected) and can save/load it to PEM files.
  Self-contained: create one object per client and the key travels with it.
* **Crypto** — a **stateless, lock-free engine**: keys are passed in
  as byte vectors per call and live in *your* data structures. Built for
  high-throughput servers managing many clients and threads.

Pick **Lite** for simple, self-contained objects that carry their own keys;
pick **Crypto** when your application owns the key lifecycle and
wants zero locking overhead.

---

## Return codes

Every function that performs work returns an `int`. **`0` means success**; any
negative value is an error. `hasKey()`, `hasPublicKey()`, `hasPrivateKey()` and
`getKey()` are the only exceptions (they are queries, not operations).

The codes are aligned with Crypto's `kOk` / `kErr*` return codes, so the
same number means the same thing in both libraries:

| Code | Constant                | Meaning                                                          | Used by |
|------|-------------------------|------------------------------------------------------------------|---------|
| `0`  | `kOk`                   | Success                                                          | all |
| `-1` | `kErrInvalidArgument`   | Bad input / no key available (wrong key size, oversized or malformed input, missing key) | all |
| `-2` | `kErrOpenSsl`           | Underlying OpenSSL call failed                                   | all |
| `-3` | `kErrAuth`              | Authentication/integrity failure (GCM tag mismatch, wrong key, corrupted data) | `Aes256`, `PostQuantum` |
| `-4` | `kErrUnavailable`       | Algorithm not available in this OpenSSL build (e.g. no ML-KEM)   | `PostQuantum` |
| `-5` | `kErrInternal`          | Unexpected internal failure                                      | `Rsa4096`, `PostQuantum` |
| `-6` | `kErrFile`              | File I/O error (cannot open/read/write a key file) — CryptoLite-only extension | `Rsa4096`, `PostQuantum` |

> **Breaking change:** earlier versions used a different numbering
> (`kErrNoKey=-1`, `kErrBadArg=-2`, `kErrCrypto=-3`, `kErrAuth=-4`,
> `kErrFile=-5`, `kErrMemory=-6`). The mapping is:
> `kErrNoKey` / `kErrBadArg` → `kErrInvalidArgument` (-1),
> `kErrCrypto` / `kErrMemory` → `kErrOpenSsl` (-2),
> `kErrAuth` → `kErrAuth` (-3), `kErrFile` → `kErrFile` (-6).

The same numeric values are exposed as `static constexpr int` members on each
class (e.g. `Aes256::kErrAuth`), so you can write readable checks:

```cpp
int rc = aes.decrypt(cipher, plain);
if (rc == CryptoLite::Aes256::kErrAuth) { /* wrong key or tampered data */ }
```

---

## Thread safety

All three classes are fully thread-safe: every method locks internally, and a
single instance may be shared freely between threads — including concurrent
key changes.

* `Aes256::encrypt()` / `decrypt()` copy the 32-byte key under the lock and
  run the crypto on that snapshot.
* `Rsa4096` and `PostQuantum` take an up-referenced `EVP_PKEY` snapshot under
  the lock, so the key stays valid even while `generateKeyPair()` / `load*()`
  replaces the instance's key.
* `getKey()` returns a copy for the same reason.

A call therefore either sees the old key or the new one, never a torn state.
The only remaining rule is the usual one: do not destroy an object while
another thread is still using it.

---

## Project layout

```
CryptoLite/
├── CMakeLists.txt          # build script (static + shared)
├── README.md
├── include/                # the three headers (.hpp)
│   ├── Aes256.hpp
│   ├── Rsa4096.hpp
│   └── PostQuantum.hpp
├── src/                    # the three implementations (.cpp)
│   ├── Aes256.cpp
│   ├── Rsa4096.cpp
│   └── PostQuantum.cpp
├── scripts/
│   └── build.ps1           # one-command build (+ -Test runs ctest)
└── tests/
    └── test_main.cpp       # unit tests (CTest)
```

---

## Class reference

All classes live in the `CryptoLite` namespace. They are **non-copyable and
non-movable** because each one exclusively owns its key material, and they are
**thread-safe**: all methods lock internally (see "Thread safety" above).

### `CryptoLite::Aes256` — AES-256-GCM

The 256-bit key lives **only in memory** and is never written to disk.

**Public constants**

| Constant   | Value | Meaning                       |
|------------|-------|-------------------------------|
| `kKeySize` | 32    | key length in bytes (256 bit) |
| `kIvSize`  | 12    | IV length in bytes            |
| `kTagSize` | 16    | GCM tag length in bytes       |

**Member variables** (private, owned by the object)

| Variable | Type                        | Meaning                       |
|----------|-----------------------------|-------------------------------|
| `mutex_`  | `mutable std::mutex`       | guards `key_` and `hasKey_`   |
| `key_`   | `std::vector<unsigned char>`| the 32-byte AES key (memory)  |
| `hasKey_`| `bool`                      | whether a key has been set    |

**Functions**

| Function | Returns | Description |
|----------|---------|-------------|
| `generateKey()` | `int` | Generate a fresh random 256-bit key (`0` on success). |
| `setKey(key)` | `int` | Set the key from a 32-byte vector (`-1` if not 32 bytes). |
| `hasKey()` | `bool` | `true` once a key is available. |
| `getKey()` | `vector` | Copy of the key bytes (by value, thread-safe snapshot). |
| `encrypt(in, out)` | `int` | Encrypt `in` into `out`. |
| `decrypt(in, out)` | `int` | Decrypt `in` into `out`. |
| `encrypt(in, aad, out)` | `int` | Encrypt, binding `aad` (headers/metadata) into the tag. |
| `decrypt(in, aad, out)` | `int` | Decrypt with the same `aad` that was bound at encryption. |

**Ciphertext layout** (binary): `[ 12-byte IV ][ ciphertext ][ 16-byte tag ]`

### `CryptoLite::Rsa4096` — RSA-4096 (OAEP-SHA256)

Encrypt with the public key, decrypt with the private key. Keys are stored in
standard **PEM** format. A 4096-bit key encrypts at most **446 bytes** per call.

**Public constants**

| Constant        | Value | Meaning                    |
|-----------------|-------|----------------------------|
| `kBits`         | 4096  | RSA modulus size           |
| `kModulusSize`  | 512   | ciphertext size in bytes   |
| `kMaxPlaintext` | 446   | max plaintext bytes (OAEP) |

**Member variables** (private, owned by the object)

| Variable      | Type       | Meaning                          |
|---------------|------------|----------------------------------|
| `mutex_`      | `mutable std::mutex` | guards `pkey_` and `hasPrivate_` |
| `pkey_`       | `EVP_PKEY*`| the OpenSSL key handle           |
| `hasPrivate_` | `bool`     | whether a private key is present |

**Functions**

| Function | Returns | Description |
|----------|---------|-------------|
| `generateKeyPair()` | `int` | Generate a new 4096-bit key pair. |
| `savePublicKey(path)` / `loadPublicKey(path)` | `int` | Save/load the public key (PEM). |
| `savePrivateKey(path)` / `loadPrivateKey(path)` | `int` | Save/load the private key (PEM, unencrypted). |
| `hasPublicKey()` / `hasPrivateKey()` | `bool` | Key presence checks. |
| `encrypt(in, out)` | `int` | Encrypt with the public key. |
| `decrypt(in, out)` | `int` | Decrypt with the private key. |

### `CryptoLite::PostQuantum` — ML-KEM-768 (Kyber) + AES-256-GCM

`encrypt()` runs an ML-KEM-768 key encapsulation to establish a shared secret,
then uses that secret as an AES-256-GCM key to encrypt the message.
`decrypt()` reverses the process.

**Public constants**

| Constant     | Value         | Meaning                  |
|--------------|---------------|--------------------------|
| `kAlgorithm` | `"ML-KEM-768"`| ML-KEM parameter set    |

**Member variables** (private, owned by the object)

| Variable      | Type        | Meaning                          |
|---------------|-------------|----------------------------------|
| `mutex_`      | `mutable std::mutex` | guards `pkey_` and `hasPrivate_` |
| `pkey_`       | `EVP_PKEY*` | the OpenSSL key handle           |
| `hasPrivate_` | `bool`      | whether a private key is present |

**Functions** — same shape as `Rsa4096`: `generateKeyPair()` (returns `-4` when
this OpenSSL build has no ML-KEM support), `savePublicKey()`/`loadPublicKey()`,
`savePrivateKey()`/`loadPrivateKey()`, `hasPublicKey()`/`hasPrivateKey()`,
`encrypt()`, `decrypt()`.

**Ciphertext layout** (binary):

```
[ 4-byte little-endian KEM ciphertext length ][ KEM ciphertext ]
[ AES-256-GCM ciphertext: 12-byte IV ][ data ][ 16-byte tag ]
```

---

## Building (Windows)

### 1. Get OpenSSL 3.5+

Install OpenSSL with development headers and libraries. Examples:

- **MSYS2 / MinGW-w64 (ucrt):** `pacman -S mingw-w64-ucrt-x86_64-openssl`
- **vcpkg:** `vcpkg install openssl:x64-windows`
- **Shining Light / Win64 OpenSSL:** download from <https://slproweb.com/products/Win32OpenSSL.html>

If OpenSSL is in a non-standard location, point CMake at it with
`-DOPENSSL_ROOT_DIR=C:/path/to/openssl`.

### 2. Build a **static** library

```bat
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Produces `libCryptoLite.a` (MinGW) or `CryptoLite.lib` (MSVC).

### 3. Build a **shared** library (DLL)

```bat
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
cmake --build build
```

Produces `libCryptoLite.dll` plus its import library. The `__declspec`
import/export is handled automatically by the `CRYPTO_LITE_API` macro in each
header.

### 4. Build and run the tests

```bat
cmake --build build
build\CryptoLite_tests.exe
ctest --test-dir build --output-on-failure
```

The suite covers round trips, every error code with its exact value, file I/O
failures, and multithreaded stress tests that hammer one shared instance.
When run directly in a terminal (or double-clicked), the test binary pauses at
the end so the window stays open while you read the results; CTest and
redirected runs skip the pause automatically, and setting
`CRYPTO_LITE_NO_PAUSE=1` forces it off.

A one-command helper builds with the in-workspace toolchain and can run the
tests right after:

```bat
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Linkage static -Test
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Linkage shared -Test
```

The build in this workspace links OpenSSL **statically**, so no OpenSSL DLL is
needed at runtime. The build copies the MinGW runtime DLLs next to the test
executable automatically.

---

## Using CryptoLite in your own project

```cpp
#include "Aes256.hpp"
#include <vector>

int main() {
    CryptoLite::Aes256 aes;
    if (aes.generateKey() != 0) return 1;

    std::vector<unsigned char> plain = {'h','i'};
    std::vector<unsigned char> cipher, recovered;

    if (aes.encrypt(plain, cipher) != 0) return 1;
    if (aes.decrypt(cipher, recovered) != 0) return 1;

    return recovered == plain ? 0 : 1;
}
```

Link statically:

```bat
g++ main.cpp -I path\to\CryptoLite\include -L path\to\lib -lCryptoLite -lcrypto
```

Link against the DLL the same way, then ensure `libCryptoLite.dll` **and** the
OpenSSL DLL are on `PATH` at runtime.

With CMake:

```cmake
find_package(OpenSSL 3.5 REQUIRED)
add_subdirectory(path/to/CryptoLite)
target_link_libraries(my_app PRIVATE CryptoLite::CryptoLite)
```

---

## Security notes

- **AES** uses AES-256-**GCM** (confidentiality + integrity); tampered data is
  rejected with `-3`. The IV (nonce) is generated randomly inside `encrypt()`
  for every message and prepended to the ciphertext, so it can never be
  reused by accident. With random 96-bit IVs the collision risk becomes
  meaningful only after ~2³² messages under one key — rotate keys at extreme
  volume. AAD overloads (`encrypt(in, aad, out)` / `decrypt(in, aad, out)`)
  bind headers/metadata into the tag.
- **RSA** uses **OAEP** with SHA-256/MGF1-SHA256 (not the weaker PKCS#1 v1.5).
- **Post-quantum** uses **ML-KEM-768** (FIPS 203 / NIST category 3) plus
  AES-256-GCM. The 32-byte shared secret is used directly as the AES key.
- The AES key is kept **in memory only**; it is never written to disk. RSA/PQ
  public keys are meant to be shared (hence PEM files); their private keys are
  saved unencrypted for simplicity, so protect those files.
- All classes **cleanse key material from memory** on destruction and when keys
  are replaced (`OPENSSL_cleanse`), and free their OpenSSL handles.
- With this workspace's OpenSSL 3.5.9 (built `no-shared`), OpenSSL is linked
  statically into the library and test executable, so no `libcrypto-3-x64.dll`
  is needed at runtime — only the MinGW runtime DLLs shipped next to the
  executable.

## License

Provided as-is for educational and general use. OpenSSL is licensed under the
Apache License 2.0.
