# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

C library for generating one-time passwords:

- **TOTP** ([RFC-6238](https://www.rfc-editor.org/rfc/rfc6238)) and **HOTP** ([RFC-4226](https://www.rfc-editor.org/rfc/rfc4226)) with SHA-1, SHA-256 and SHA-512
- **Steam Guard** codes
- **YAOTP** (Yandex.Key) codes
- **Base32** codec ([RFC-4648](https://www.rfc-editor.org/rfc/rfc4648))
- **`otpauth://` URI** parser/builder, including Yandex's `otpauth://yaotp/` variant
- Optional **time-window validation** helpers

**Quick index:** [Build](#build-and-install) · [Using libcotp](#using-libcotp-in-your-project) · [Public API](#public-api) · [Ownership](#ownership-and-lifetime) · [Error Model](#error-model) · [Context API](#context-api) · [Validation](#validation-helpers-optional) · [otpauth:// URIs](#otpauth-uris) · [YAOTP](#yaotp-yandexkey) · [Base32](#base32-encoding--decoding) · [Utilities](#utilities) · [Version Macros](#version-macros) · [Operational Notes](#operational-notes)

## Requirements

- GCC or Clang, CMake ≥ 3.16
- One crypto backend:
  - libgcrypt ≥ 1.8.0 (default)
  - OpenSSL ≥ 3.0.0
  - MbedTLS 2.x, 3.x or 4.x
- [Criterion](https://github.com/Snaipe/Criterion) (only for tests)

## Build and Install

```sh
git clone https://github.com/paolostivanin/libcotp.git
cd libcotp
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

This installs `cotp.h`, the library, a pkg-config file (`cotp.pc`) and a CMake
package config (`COTPConfig.cmake`).

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `-DHMAC_WRAPPER=<gcrypt, openssl, mbedtls>` | gcrypt | Select crypto backend |
| `-DBUILD_SHARED_LIBS=OFF` | ON | Build static instead of shared |
| `-DCOTP_ENABLE_VALIDATION=ON` | OFF | Build the [validation helper APIs](#validation-helpers-optional) |
| `-DBUILD_TESTS=ON` | OFF | Build tests (requires Criterion) |
| `-DCOTP_BUILD_FUZZERS=ON` | OFF | Build libFuzzer harnesses (requires Clang) |

### Tests

```sh
cmake -DBUILD_TESTS=ON -DCOTP_ENABLE_VALIDATION=ON ..
make
ctest --output-on-failure
```

The validation tests are only built when `COTP_ENABLE_VALIDATION` is on.

### Fuzzing

Five libFuzzer harnesses live in `fuzz/` (`fuzz_base32_decode`,
`fuzz_base32_encode`, `fuzz_get_totp_at`, `fuzz_otpauth_uri`, `fuzz_yaotp_uri`).
The library and harnesses are built with ASan and UBSan:

```sh
CC=clang cmake -DCOTP_BUILD_FUZZERS=ON ..
make
./fuzz/fuzz_otpauth_uri -max_total_time=60
```

### Tested Platforms

The code is C11 and is tested on Linux (Debian stable and Ubuntu 24.04) with GCC
and Clang, for all three crypto backends. CI also runs the test suite under
ASan+UBSan for every backend, smoke-runs each fuzzer, and builds and tests the
gcrypt backend on 32-bit Debian. The codec and OTP paths are endianness- and
word-size-independent (`uint64_t`/`uint8_t` arithmetic). On 32-bit/ILP32
platforms the public API still accepts `long` timestamps/counters, so timestamps
beyond 2038 are not representable there.

MSVC is not a supported build: CMake guards some GCC-only flags, but the
sources rely on POSIX/GCC features. The volatile-write fallback in
`cotp_secure_memzero` is portable, and `whmac.h` provides an `ssize_t`
compatibility typedef, but availability of a Windows build should not be
assumed without testing.

---

## Using libcotp in Your Project

All declarations live in a single header:

```c
#include <cotp.h>
```

CMake:

```cmake
find_package(COTP 4.2 CONFIG REQUIRED)
target_link_libraries(myapp PRIVATE COTP::cotp)
```

pkg-config:

```sh
cc myapp.c $(pkg-config --cflags --libs cotp)
```

`cotp.pc` lists the crypto backend under `Requires.private`/`Libs.private`, so
static consumers should use `pkg-config --static`.

If libcotp was built with `-DCOTP_ENABLE_VALIDATION=ON`, the `COTP::cotp` target
propagates the `COTP_ENABLE_VALIDATION` define automatically. `cotp.pc` does
**not**: pkg-config consumers must add `-DCOTP_ENABLE_VALIDATION` to their own
`CFLAGS` to see the validation prototypes.

---

## Public API

### TOTP and HOTP

```c
char *get_totp(const char *base32_secret,
               int digits,
               int period,
               int algo,
               cotp_error_t *err);

char *get_totp_at(const char *base32_secret,
                  long timestamp,
                  int digits,
                  int period,
                  int algo,
                  cotp_error_t *err);

char *get_hotp(const char *base32_secret,
               long counter,
               int digits,
               int algo,
               cotp_error_t *err);

int64_t otp_to_int(const char *otp,
                   cotp_error_t *err);
```

Example:

```c
cotp_error_t err;
char *code = get_totp("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", 6, 30, COTP_SHA1, &err);
if (!code) {
    fprintf(stderr, "get_totp: %s\n", cotp_strerror(err));
    return 1;
}
/* … use code … */
free(code);
```

### Steam Guard

```c
char *get_steam_totp(const char *base32_secret,
                     int period,
                     cotp_error_t *err);

char *get_steam_totp_at(const char *base32_secret,
                        long timestamp,
                        int period,
                        cotp_error_t *err);
```

Steam codes are five characters from the alphabet `23456789BCDFGHJKMNPQRTVWXY`,
always computed with HMAC-SHA1. Steam uses a 30-second period. See
[Operational Notes](#operational-notes) for converting Steam's Base64 seed into
the Base32 secret these functions expect.

### YAOTP

`get_yaotp`, `get_yaotp_at` and `cotp_yaotp_secret_pin_length` are documented in
[YAOTP (Yandex.Key)](#yaotp-yandexkey).

### Parameter Constraints

- `base32_secret`: Base32 encoded (may contain spaces). `NULL` is invalid.
- `digits`: 4–10 inclusive (`MIN_DIGITS`/`MAX_DIGITS`)
- `period`: 1–120 seconds inclusive
- `algo`: `COTP_SHA1`, `COTP_SHA256`, `COTP_SHA512`
- `counter`: non-negative
- `timestamp`: non-negative UNIX epoch seconds (`INVALID_COUNTER` otherwise)

Secrets are normalized (spaces removed, lowercase → uppercase).

Public functions returning a heap pointer or status code are annotated with
`__attribute__((warn_unused_result))` (GCC/Clang) so ignoring the return
triggers a compile warning.

---

## Ownership and Lifetime

- On success, OTP functions return `char *`. Caller must `free()`.
- On error, they return `NULL` and set `err` if non-NULL.
- If `err == NULL`, functions still behave correctly using an internal error variable.
- `otp_to_int()` never allocates:
  - returns `-1` on invalid input
  - returns integer on success
  - strips leading zeroes and sets `MISSING_LEADING_ZERO` when applicable
    (any leading `0`, including an all-zero code such as `"0000"`)

---

## Error Model

```c
const char *cotp_strerror(cotp_error_t err);
```

| Error | Meaning |
|-------|---------|
| `NO_ERROR` | Success. From `validate_totp_in_window` / `cotp_ctx_validate_totp`, this means the call ran cleanly but **no offset matched**. |
| `VALID` | Validation matched. Set **only** by `validate_totp_in_window` and `cotp_ctx_validate_totp`. Other functions never use it. |
| `WHMAC_ERROR` | Backend crypto error |
| `WCRYPT_VERSION_MISMATCH` | Crypto backend unusable. Emitted by the **gcrypt** backend when libgcrypt is older than 1.8.0, and by the **MbedTLS 4.x** backend when `psa_crypto_init()` fails. The OpenSSL and MbedTLS 2.x/3.x backends skip the runtime check. |
| `INVALID_B32_INPUT` | Secret not valid Base32 |
| `INVALID_ALGO` | Unsupported algorithm |
| `INVALID_PERIOD` | Period not in allowed range |
| `INVALID_DIGITS` | Digits not in allowed range |
| `INVALID_COUNTER` | Negative counter or timestamp |
| `INVALID_USER_INPUT` | NULL or malformed user input |
| `MISSING_LEADING_ZERO` | Leading zeroes stripped |
| `MEMORY_ALLOCATION_ERROR` | Allocation failure |
| `EMPTY_STRING` | Input was empty |
| `INVALID_YAOTP_SECRET_LENGTH` | YAOTP secret too short (decoded length < 26 bytes) |
| `INVALID_YAOTP_SECRET_CRC` | YAOTP secret's CRC-13 checksum did not verify |
| `INVALID_YAOTP_PIN` | YAOTP PIN NULL, wrong length, or contains non-digits; also returned when the embedded pin-length nibble decodes to a PIN length outside 4–16 (nibble values 0–2 mean 1–3 and are rejected) |

Return rules:

- `get_totp`, `get_totp_at`, `get_steam_totp`, `get_steam_totp_at`, `get_hotp`, `get_yaotp`, `get_yaotp_at` → `NULL` on failure
- `otp_to_int`, `cotp_yaotp_secret_pin_length` → `-1` on failure
- `cotp_strerror(err)` returns a static, non-NULL, NUL-terminated description for any
  `cotp_error_t` value. Unknown values return `"unknown error"`. Do **not** `free()` the result.

---

## Context API

A context bundles `digits`, `period`, and `algo` so you don't repeat them on
every call. Contexts are immutable after creation and safe to share across
threads.

```c
cotp_ctx *cotp_ctx_create(int digits, int period, int sha_algo);
void      cotp_ctx_free(cotp_ctx *ctx);

char     *cotp_ctx_totp(cotp_ctx *ctx, const char *base32_secret, cotp_error_t *err);
char     *cotp_ctx_totp_at(cotp_ctx *ctx, const char *base32_secret, long timestamp, cotp_error_t *err);
char     *cotp_ctx_hotp(cotp_ctx *ctx, const char *base32_secret, long counter, cotp_error_t *err);

/* Steam variants ignore ctx->digits and ctx->algo (Steam fixes both); only ctx->period is used. */
char     *cotp_ctx_steam_totp(cotp_ctx *ctx, const char *base32_secret, cotp_error_t *err);
char     *cotp_ctx_steam_totp_at(cotp_ctx *ctx, const char *base32_secret, long timestamp, cotp_error_t *err);

/* YAOTP variants ignore ctx->{digits,period,algo} entirely (all hardcoded by the algorithm). */
char     *cotp_ctx_yaotp(cotp_ctx *ctx, const char *base32_secret, const char *pin, cotp_error_t *err);
char     *cotp_ctx_yaotp_at(cotp_ctx *ctx, const char *base32_secret, const char *pin, long timestamp, cotp_error_t *err);

#ifdef COTP_ENABLE_VALIDATION
int       cotp_ctx_validate_totp(cotp_ctx *ctx, const char *user_code, const char *base32_secret,
                                 long timestamp, int window, int *matched_delta, cotp_error_t *err);
#endif
```

`cotp_ctx_create` returns `NULL` if `digits`, `period` or `sha_algo` is out of
range, or on allocation failure. A `NULL` ctx passed to the other functions returns `NULL` (or `0` for the
validate variant) and sets `err` to `INVALID_USER_INPUT`. `cotp_ctx_free(NULL)`
is a no-op.

Example — generate three codes from the same configuration:

```c
cotp_ctx *ctx = cotp_ctx_create(6, 30, COTP_SHA1);
if (!ctx) { /* invalid digits/period/algo */ }

cotp_error_t err;
for (int i = 0; i < 3; i++) {
    char *code = cotp_ctx_totp(ctx, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", &err);
    /* … use code … */
    free(code);
    sleep(30);
}
cotp_ctx_free(ctx);
```

---

## Validation Helpers (optional)

Built only with `-DCOTP_ENABLE_VALIDATION=ON` (see
[Using libcotp](#using-libcotp-in-your-project) for how consumers get the
prototypes):

```c
int validate_totp_in_window(const char *user_code,
                            const char *base32_secret,
                            long timestamp,
                            int digits,
                            int period,
                            int sha_algo,
                            int window,
                            int *matched_delta,
                            cotp_error_t *err);
```

Returns:

- `1` on match within `[-window, +window]` periods (sets `VALID`, and `*matched_delta` to the matching offset)
- `0` otherwise

`window` is symmetric and clamped to a maximum of `1024`; values above that
return `INVALID_USER_INPUT`, and `INT_MIN` is rejected explicitly (it cannot be
negated safely). A negative base timestamp returns `INVALID_COUNTER`. The
internal time arithmetic is overflow-safe; deltas whose timestamp would overflow
`long`, and pre-epoch timestamps (`t < 0`, rejected by the generators), are
silently skipped. The compare uses constant-time byte comparison.

Example — accept a code generated one period in the past with `window=1`:

```c
cotp_error_t err;
char *code = get_totp_at("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", 1700000000,
                         6, 30, COTP_SHA1, &err);

int matched_delta = 0;
int ok = validate_totp_in_window(code, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                                 1700000030, /* one period later */
                                 6, 30, COTP_SHA1,
                                 1, &matched_delta, &err);
// ok == 1, matched_delta == -1, err == VALID
free(code);
```

---

## otpauth:// URIs

Parser and builder for the de-facto Google Authenticator URI format used by
most TOTP/HOTP apps and QR-code provisioning flows.

```c
typedef enum {
    COTP_OTPAUTH_TOTP = 0,
    COTP_OTPAUTH_HOTP = 1
} cotp_otpauth_type;

typedef struct {
    cotp_otpauth_type type;
    char *issuer;     /* may be NULL */
    char *account;    /* may be NULL */
    char *secret;     /* base32, required */
    int   algo;       /* COTP_SHA1 / COTP_SHA256 / COTP_SHA512 (default SHA1) */
    int   digits;     /* 4-10 (default 6) */
    int   period;     /* 1-120, TOTP only (default 30) */
    long  counter;    /* >= 0, HOTP only (required for HOTP) */
} cotp_otpauth_uri;

cotp_otpauth_uri *cotp_otpauth_uri_parse(const char *uri, cotp_error_t *err);
char             *cotp_otpauth_uri_build(const cotp_otpauth_uri *u, cotp_error_t *err);
void              cotp_otpauth_uri_free(cotp_otpauth_uri *u);
```

Behavior:

- Format: `otpauth://TYPE/[ISSUER:]ACCOUNT?secret=…&algorithm=…&digits=…&period=…|counter=…&issuer=…`
- `TYPE` is `totp` or `hotp` (case-insensitive); anything else, including `yaotp`,
  is rejected with `INVALID_USER_INPUT`. Use [`cotp_yaotp_uri_parse`](#yaotp-otpauth-uris) for Yandex URIs.
- Label fields are percent-decoded; missing query parameters use the defaults shown above.
- For HOTP, the `counter` query parameter is required. Missing → `INVALID_COUNTER`.
- If both label-issuer (`Foo:bar`) and `&issuer=` are present, the **label-issuer wins**.
  A label with an empty issuer (`:bar`) does not count as a label-issuer.
- Unknown query keys are silently ignored; query segments without `=` are skipped.
- Numeric values (`digits`, `period`, `counter`) are parsed with `strtol` semantics, so a
  leading `+` or surrounding whitespace is accepted (e.g. `digits=+6`). Range validation is
  applied afterwards. Requiring digit-only input would be a compatibility change.
- Percent-escapes must be complete: a `%` not followed by two hex digits is rejected as
  malformed input. A secret consisting only of ASCII spaces is rejected.
- `_parse` returns a heap struct; release it with `cotp_otpauth_uri_free`. The free function
  securely zeroes `secret` before releasing.
- `_build` validates fields against the same bounds as `get_hotp` / `get_totp_at` and returns a
  newly allocated, NUL-terminated string the caller must `free()`.

Example:

```c
cotp_error_t err;
cotp_otpauth_uri *u = cotp_otpauth_uri_parse(
    "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", &err);
if (!u) { /* handle err */ }
char *code = get_totp(u->secret, u->digits, u->period, u->algo, &err);
/* … */
free(code);
cotp_otpauth_uri_free(u);
```

---

## YAOTP (Yandex.Key)

Proprietary OTP scheme used by Yandex 2FA. Produces eight lowercase letters
(`a`–`z`) every 30 seconds. Algorithm ported from
[KeeYaOtp](https://github.com/norblik/KeeYaOtp) (the canonical reference);
matches Yandex servers including the SHA-256 leading-zero quirk.

```c
#define COTP_YAOTP_PERIOD         30
#define COTP_YAOTP_DIGITS         8
#define COTP_YAOTP_MIN_PIN_LENGTH 4
#define COTP_YAOTP_MAX_PIN_LENGTH 16

char *get_yaotp(const char *base32_secret,
                const char *pin,
                cotp_error_t *err);

char *get_yaotp_at(const char *base32_secret,
                   const char *pin,
                   long timestamp,
                   cotp_error_t *err);

int   cotp_yaotp_secret_pin_length(const char *base32_secret,
                                   cotp_error_t *err);
```

Behavior:

- The `base32_secret` is a Yandex-format blob: base32 of `[16-byte key][8-byte userId][pinLength nibble + 12-bit CRC-13]`.
  Decoded length must be ≥ 26 bytes. The CRC-13 checksum (polynomial `0x18F3`) is verified before
  any code is computed; a flipped bit returns `INVALID_YAOTP_SECRET_CRC`.
- The PIN must be ASCII digits, length 4–16, matching the value encoded in the secret. Mismatch
  returns `INVALID_YAOTP_PIN`. Call `cotp_yaotp_secret_pin_length` first if your UI needs to
  size the PIN-entry field.
- All output parameters are fixed by the algorithm: 30-second period, SHA-256, 8 letters, `a`–`z`
  alphabet. `digits`, `period`, and `algo` from a `cotp_ctx` are **ignored** by the ctx wrappers.
- Return values: 9-byte heap string on success (caller `free()`s); `NULL` on error with `*err` set.
- The library does not retain or copy the PIN, but it cannot scrub a `const char *` it doesn't own.
  Wipe the PIN buffer yourself with `cotp_secure_memzero` after use.

Example:

```c
const char *secret = "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI";
char pin[] = "7586";

cotp_error_t err;
int expected_len = cotp_yaotp_secret_pin_length(secret, &err);
/* expected_len == 4 */

char *code = get_yaotp_at(secret, pin, 1581064020 /* 2020-02-07T08:27:00Z */, &err);
/* code == "oactmacq"; use get_yaotp() for the current time */

free(code);
cotp_secure_memzero(pin, sizeof pin - 1);
```

### YAOTP `otpauth://` URIs

Yandex apps issue QR codes of the form
`otpauth://yaotp/<account>?secret=…&pin_length=N[&issuer=…][&track_id=…][&uid=…]`.
A separate struct (`cotp_yaotp_uri`) parses and builds these without overloading the standard
`cotp_otpauth_uri` with Yandex-specific opaque fields.

```c
typedef struct {
    char *secret;     /* base32, required */
    char *account;    /* may be NULL (Yandex's "name" field maps here) */
    char *issuer;     /* may be NULL */
    char *track_id;   /* opaque pass-through, may be NULL */
    char *uid;        /* opaque pass-through, may be NULL */
    int   pin_length; /* 4–16, required */
} cotp_yaotp_uri;

cotp_yaotp_uri *cotp_yaotp_uri_parse(const char *uri, cotp_error_t *err);
char           *cotp_yaotp_uri_build(const cotp_yaotp_uri *u, cotp_error_t *err);
void            cotp_yaotp_uri_free(cotp_yaotp_uri *u);
```

`_parse` requires both `secret` and `pin_length`. Unknown query keys are silently
ignored and segments without `=` are skipped. `pin_length` uses the same lenient
`strtol` numeric parsing as `cotp_otpauth_uri_parse`. Secrets made only of ASCII
spaces are rejected. `track_id` and `uid` are capped at 128 decoded bytes to prevent
URI-bomb allocations, and `_build` enforces the same cap so it cannot emit a URI that
`_parse` would refuse. `_free` securely zeroes `secret` before releasing.

---

## Base32 Encoding / Decoding

```c
char *base32_encode(const uint8_t *data,
                    size_t len,
                    cotp_error_t *err);

uint8_t *base32_decode(const char *user_data,
                       size_t data_len,
                       cotp_error_t *err);

bool is_string_valid_b32(const char *user_data);
```

Behavior:

- `NULL` on error (sets `err`); the caller must `free()` a non-NULL result
- empty input → empty non-NULL string + `EMPTY_STRING`
- spaces allowed
- invalid base32 → `INVALID_B32_INPUT`
- `is_string_valid_b32` does not allocate; it ignores ASCII spaces

Example — round-trip a binary buffer:

```c
const uint8_t raw[] = { 0xDE, 0xAD, 0xBE, 0xEF };

cotp_error_t err;
char *encoded = base32_encode(raw, sizeof raw, &err);          // "32W353Y="
uint8_t *decoded = base32_decode(encoded, strlen(encoded), &err);
// memcmp(raw, decoded, sizeof raw) == 0
free(encoded);
free(decoded);
```

Lenient-mode caveats — the decoder targets the OTP-secret use case, not strict
RFC 4648 conformance. Callers handling general-purpose Base32 should be aware:

- Non-zero pad bits in the final group are accepted, not rejected (RFC 4648 §3.5
  strict-mode behavior is not implemented).
- Embedded NUL bytes silently truncate the input (`strlen` semantics).
- Only ASCII space (0x20) is stripped — tabs, newlines, and CRs cause `INVALID_B32_INPUT`.
- A single base32 character (e.g. `"J"`) is accepted and decodes to a zero-length buffer.

---

## Utilities

Helpers exposed for callers that handle their own secret material. Both are
thread-safe and have no internal state.

```c
void cotp_secure_memzero(void *ptr, size_t len);
int  cotp_timing_safe_memcmp(const void *a, const void *b, size_t len);
```

- `cotp_secure_memzero` — wipes `len` bytes at `ptr` in a way the compiler must
  not elide (uses `memset_s` / `explicit_bzero` / volatile fallback). Safe with
  `ptr == NULL` or `len == 0`. Use it to scrub the Base32 secret strings you
  pass into `get_totp` / `get_hotp` once you no longer need them.
- `cotp_timing_safe_memcmp` — constant-time byte comparison. Returns `0` on
  equal, non-zero otherwise. Length is treated as public information.

Example — scrub a secret after use:

```c
char secret[] = "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
cotp_error_t err;
char *code = get_totp(secret, 6, 30, COTP_SHA1, &err);
/* … */
free(code);
cotp_secure_memzero(secret, sizeof secret - 1);
```

---

## Version Macros

```c
#define COTP_VERSION_MAJOR  4
#define COTP_VERSION_MINOR  2
#define COTP_VERSION_PATCH  2
#define COTP_VERSION_STRING "4.2.2"
#define COTP_VERSION_NUMBER /* MAJOR*10000 + MINOR*100 + PATCH */
```

Use `COTP_VERSION_NUMBER` (available since 4.1.0) for compile-time conditionals:

```c
#if COTP_VERSION_NUMBER >= 40200
    /* APIs added in 4.2.0 (YAOTP) are available */
#endif
```

The build asserts that `COTP_VERSION_STRING` matches the CMake project version,
so the two cannot drift.

---

## Operational Notes

- **System clock**: `get_totp()` reads `time(NULL)` once at call time; ensure
  the host clock is synchronized (NTP). A skew larger than the verifier's
  validation window will cause every code to be rejected.
- **Validation window**: allow a small window (±1–2 periods) on the verifier
  side to absorb minor clock drift.
- **HOTP counter persistence**: HOTP requires the caller to persist the counter
  across runs and increment it for every code consumed. Lose the counter and
  the device falls out of sync with the verifier.
- **Steam TOTP secrets**: Steam stores the seed as a Base64 string on the
  device. Callers must Base64-decode it to raw bytes and Base32-encode those
  bytes (e.g. with `base32_encode`) before passing the result to
  `get_steam_totp` / `get_steam_totp_at`. This library does not perform the
  Base64 step.
- **Minimum secret length**: RFC 6238 §5.1 recommends ≥160-bit shared secrets
  for SHA1 (20 raw bytes / 32 Base32 characters). The library accepts shorter
  secrets — pass them at your own cryptographic risk.
- **Thread safety**: bare functions hold no global state and are safe to call
  concurrently from multiple threads. `cotp_ctx` is immutable after creation
  and may be shared. The gcrypt backend performs a one-shot library
  initialization on the first call; subsequent calls are inert. The MbedTLS 4.x
  backend calls the idempotent `psa_crypto_init()` before each computation.
- **Secrets in memory**: use `cotp_secure_memzero` (see [Utilities](#utilities))
  to wipe secret strings the caller owns before freeing them. The library
  already scrubs its internal copies.

---

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report a
vulnerability privately.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
