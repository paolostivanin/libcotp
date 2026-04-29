# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

C library that generates TOTP and HOTP according to [RFC-6238](https://www.rfc-editor.org/rfc/rfc6238)
and [RFC-4226](https://www.rfc-editor.org/rfc/rfc4226), with Base32 codec
([RFC-4648](https://www.rfc-editor.org/rfc/rfc4648)) and `otpauth://` URI parser/builder.

**Quick index:** [Public API](#public-api) · [Error Model](#error-model) · [Validation](#validation-helpers-optional) · [Context API](#context-api) · [otpauth:// URIs](#otpauth-uris) · [Base32](#base32-encoding--decoding) · [Utilities](#utilities) · [Operational Notes](#operational-notes)

## Requirements

- GCC or Clang and CMake
- One crypto backend:
  - libgcrypt ≥ 1.8.0
  - OpenSSL ≥ 3.0.0
  - MbedTLS 2.x or 3.x

## Build and Install

```sh
git clone https://github.com/paolostivanin/libcotp.git
cd libcotp
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
sudo make install
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `-DBUILD_TESTS=ON` | OFF | Build tests (requires Criterion) |
| `-DBUILD_SHARED_LIBS=OFF` | ON | Build static instead of shared |
| `-DHMAC_WRAPPER=<gcrypt, openssl, mbedtls>` | gcrypt | Select crypto backend |
| `-DCOTP_ENABLE_VALIDATION=ON` | OFF | Enable validation helper APIs |
| `-DCOTP_BUILD_FUZZERS=ON` | OFF | Build libFuzzer harnesses (requires Clang) |

---

## Public API

```c
char *get_totp(const char *base32_secret,
               int digits,
               int period,
               int algo,
               cotp_error_t *err);

char *get_steam_totp(const char *base32_secret,
                     int period,
                     cotp_error_t *err);

char *get_steam_totp_at(const char *base32_secret,
                        long timestamp,
                        int period,
                        cotp_error_t *err);

char *get_hotp(const char *base32_secret,
               long counter,
               int digits,
               int algo,
               cotp_error_t *err);

char *get_totp_at(const char *base32_secret,
                  long timestamp,
                  int digits,
                  int period,
                  int algo,
                  cotp_error_t *err);

int64_t otp_to_int(const char *otp,
                   cotp_error_t *err);

const char *cotp_strerror(cotp_error_t err);
```

Public functions returning a heap pointer or status code are annotated with
`__attribute__((warn_unused_result))` (GCC/Clang) so ignoring the return
triggers a compile warning.

### Parameter Constraints

- `base32_secret`: Base32 encoded (may contain spaces). `NULL` is invalid.
- `digits`: 4–10 inclusive
- `period`: 1–120 seconds inclusive
- `algo`: `COTP_SHA1`, `COTP_SHA256`, `COTP_SHA512`
- `counter`: non-negative
- `timestamp`: UNIX epoch seconds

Secrets are normalized (spaces removed, lowercase → uppercase).

---

## Ownership and Lifetime

- On success, OTP functions return `char *`. Caller must `free()`.
- On error, they return `NULL` and set `err` if non-NULL.
- If `err == NULL`, functions still behave correctly using an internal error variable.
- `otp_to_int()` never allocates:
  - returns `-1` on invalid input
  - returns integer on success
  - strips leading zeroes and sets `MISSING_LEADING_ZERO` when applicable

Example:

```c
cotp_error_t err;
char *code = get_totp("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", 6, 30, COTP_SHA1, &err);
if (!code) {
    // handle error
}
free(code);
```

---

## Error Model

| Error | Meaning |
|-------|---------|
| `NO_ERROR` | Success. From `validate_totp_in_window` / `cotp_ctx_validate_totp`, this means the call ran cleanly but **no offset matched**. |
| `VALID` | Validation matched. Set **only** by `validate_totp_in_window` and `cotp_ctx_validate_totp`. Other functions never use it. |
| `WHMAC_ERROR` | Backend crypto error |
| `WCRYPT_VERSION_MISMATCH` | Crypto backend version too old. Currently emitted by the **gcrypt** backend only; the OpenSSL and MbedTLS backends skip the runtime check. |
| `INVALID_B32_INPUT` | Secret not valid Base32 |
| `INVALID_ALGO` | Unsupported algorithm |
| `INVALID_PERIOD` | Period not in allowed range |
| `INVALID_DIGITS` | Digits not in allowed range |
| `INVALID_COUNTER` | `counter < 0` |
| `INVALID_USER_INPUT` | NULL or malformed user input |
| `MISSING_LEADING_ZERO` | Leading zeroes stripped |
| `MEMORY_ALLOCATION_ERROR` | Allocation failure |
| `EMPTY_STRING` | Input was empty |

Return rules:

- `get_totp`, `get_totp_at`, `get_steam_totp`, `get_steam_totp_at`, `get_hotp` → `NULL` on failure
- `otp_to_int` → `-1` on failure
- `cotp_strerror(err)` returns a static, non-NULL, NUL-terminated description for any
  `cotp_error_t` value. Unknown values return `"unknown error"`. Do **not** `free()` the result.

---

## Validation Helpers (optional)

Enabled with `-DCOTP_ENABLE_VALIDATION=ON`:

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

- `1` on match within `[-window, +window]` periods (sets `VALID`)
- `0` otherwise

`window` is symmetric and clamped to a maximum of `1024`; values above that
return `INVALID_USER_INPUT`. The internal time arithmetic is overflow-safe;
deltas whose timestamp would overflow `long` are silently skipped. The compare
uses constant-time byte comparison.

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

#ifdef COTP_ENABLE_VALIDATION
int       cotp_ctx_validate_totp(cotp_ctx *ctx, const char *user_code, const char *base32_secret,
                                 long timestamp, int window, int *matched_delta, cotp_error_t *err);
#endif
```

`NULL` ctx returns `NULL` (or `0` for the validate variant) and sets `err` to
`INVALID_USER_INPUT`. `cotp_ctx_free(NULL)` is a no-op.

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
- Label fields are percent-decoded; missing query parameters use the defaults shown above.
- For HOTP, the `counter` query parameter is required. Missing → `INVALID_COUNTER`.
- If both label-issuer (`Foo:bar`) and `&issuer=` are present, the **label-issuer wins**.
- Unknown query keys are silently ignored.
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

## Version Macros

```c
#define COTP_VERSION_MAJOR  4
#define COTP_VERSION_MINOR  1
#define COTP_VERSION_PATCH  0
#define COTP_VERSION_STRING "4.1.0"
#define COTP_VERSION_NUMBER /* MAJOR*10000 + MINOR*100 + PATCH */
```

Use `COTP_VERSION_NUMBER` for compile-time conditionals:

```c
#if COTP_VERSION_NUMBER >= 40100
    /* APIs added in 4.1.0 are available */
#endif
```

The build asserts that `COTP_VERSION_STRING` matches the CMake project version,
so the two cannot drift.

---

## Base32 Encoding / Decoding

```c
char *base32_encode(const unsigned char *data,
                    size_t len,
                    cotp_error_t *err);

unsigned char *base32_decode(const char *user_data,
                             size_t data_len,
                             cotp_error_t *err);

bool is_string_valid_b32(const char *user_data);
```

Behavior:

- `NULL` on error (sets `err`)
- empty input → empty non-NULL string + `EMPTY_STRING`
- spaces allowed
- invalid base32 → `INVALID_B32_INPUT`

Example — round-trip a binary buffer:

```c
const unsigned char raw[] = { 0xDE, 0xAD, 0xBE, 0xEF };

cotp_error_t err;
char *encoded = base32_encode(raw, sizeof raw, &err);          // "326L57Y="
unsigned char *decoded = base32_decode(encoded, strlen(encoded), &err);
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
  bytes before passing the result to `get_steam_totp` / `get_steam_totp_at`.
  This library does not perform that conversion.
- **Minimum secret length**: RFC 6238 §5.1 recommends ≥160-bit shared secrets
  for SHA1 (20 raw bytes / 32 Base32 characters). The library accepts shorter
  secrets — pass them at your own cryptographic risk.
- **Thread safety**: bare functions hold no global state and are safe to call
  concurrently from multiple threads. `cotp_ctx` is immutable after creation
  and may be shared. The gcrypt backend performs a one-shot library
  initialization on the first call; subsequent calls are inert.
- **Secrets in memory**: use `cotp_secure_memzero` (see [Utilities](#utilities))
  to wipe secret strings the caller owns before freeing them. The library
  already scrubs its internal copies.
