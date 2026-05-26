#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include "cotp.h"
#include "whmac.h"
#include "whash.h"
#include "utils/secure_zero.h"

// Minimum decoded secret length: 16 (key) + 8 (userId) + 2 (pinLength nibble + 12-bit CRC) = 26.
#define YAOTP_SECRET_MIN_BYTES 26
#define YAOTP_KEY_BYTES        16
#define YAOTP_SHA256_BYTES     32
#define YAOTP_BASE26_MOD       208827064576ULL  // 26^8

// Derive the decoded length of a base32 string the same way otp.c does:
// floor(non-pad chars * 5 / 8). Spaces and '=' don't count toward output bytes.
static size_t
yaotp_b32_decoded_len (const char *s)
{
    if (!s) return 0;
    size_t chars = 0;
    for (const char *p = s; *p; ++p) {
        if (*p != '=' && *p != ' ') ++chars;
    }
    return (chars * 5) / 8;
}

// Count leading zero bits in a 16-bit value (matches KeeYaOtp's NumberOfLeadingZeros).
static int
yaotp_clz16 (uint16_t value)
{
    if (value == 0) return 16;
    int n = 0;
    if ((value & 0xFF00u) == 0) { n += 8;  value <<= 8; }
    if ((value & 0xF000u) == 0) { n += 4;  value <<= 4; }
    if ((value & 0xC000u) == 0) { n += 2;  value <<= 2; }
    if ((value & 0x8000u) == 0) { n += 1; }
    return n;
}

// Port of KeeYaOtp/Core/Secret.cs:ChecksumIsValid. Polynomial 0x18F3 (13 bits).
// Stored 12-bit checksum lives in the low 4 bits of byte[len-2] + all 8 bits of byte[len-1].
// All other bits are fed MSB-first into a 13-bit accumulator; when the accumulator hits 13 bits,
// it is XORed with the polynomial. The effective bit-width is then re-derived via leading-zero count.
static int
yaotp_crc_valid (const unsigned char *input, size_t len)
{
    if (len < 4) return 0;
    const uint16_t poly = 0x18F3u;
    uint16_t checksum_orig = (uint16_t)(((input[len - 2] & 0x0F) << 8) | input[len - 1]);

    uint16_t accum = 0;
    int accum_bits = 0;

    int total_bits = (int)(len * 8) - 12;
    size_t idx = 0;
    int bits_avail = 8;

    while (total_bits > 0) {
        int required = 13 - accum_bits;
        if (total_bits < required) required = total_bits;
        while (required > 0) {
            unsigned char cur = (unsigned char)(input[idx] & ((1 << bits_avail) - 1));
            int to_read = required > bits_avail ? bits_avail : required;
            cur = (unsigned char)(cur >> (bits_avail - to_read));
            accum = (uint16_t)(((uint32_t)accum << to_read) | cur);

            total_bits -= to_read;
            required   -= to_read;
            bits_avail -= to_read;
            accum_bits += to_read;
            if (bits_avail == 0) {
                idx++;
                bits_avail = 8;
            }
        }

        if (accum_bits == 13) accum ^= poly;
        accum_bits = 16 - yaotp_clz16 (accum);
    }

    return accum == checksum_orig;
}

// Decode and validate the Yandex-format secret. On success fills out_key (16 bytes) and *out_pin_len.
// Always wipes the decoded buffer before returning.
static int
yaotp_parse_secret (const char    *base32_secret,
                    unsigned char  out_key[YAOTP_KEY_BYTES],
                    int           *out_pin_len,
                    cotp_error_t  *err)
{
    if (!is_string_valid_b32 (base32_secret)) { *err = INVALID_B32_INPUT; return -1; }

    size_t decoded_len_expected = yaotp_b32_decoded_len (base32_secret);
    if (decoded_len_expected < YAOTP_SECRET_MIN_BYTES) {
        *err = INVALID_YAOTP_SECRET_LENGTH;
        return -1;
    }

    cotp_error_t b32_err = NO_ERROR;
    unsigned char *decoded = base32_decode (base32_secret, strlen (base32_secret), &b32_err);
    if (decoded == NULL || b32_err != NO_ERROR) {
        free (decoded);
        *err = b32_err != NO_ERROR ? b32_err : INVALID_B32_INPUT;
        return -1;
    }

    if (!yaotp_crc_valid (decoded, decoded_len_expected)) {
        cotp_secure_memzero (decoded, decoded_len_expected);
        free (decoded);
        *err = INVALID_YAOTP_SECRET_CRC;
        return -1;
    }

    if (decoded_len_expected < YAOTP_SECRET_MIN_BYTES) {
        cotp_secure_memzero (decoded, decoded_len_expected);
        free (decoded);
        *err = INVALID_YAOTP_SECRET_LENGTH;
        return -1;
    }

    memcpy (out_key, decoded + (decoded_len_expected - YAOTP_SECRET_MIN_BYTES), YAOTP_KEY_BYTES);
    *out_pin_len = (int)((decoded[decoded_len_expected - 2] >> 4) + 1);

    cotp_secure_memzero (decoded, decoded_len_expected);
    free (decoded);

    if (*out_pin_len < COTP_YAOTP_MIN_PIN_LENGTH || *out_pin_len > COTP_YAOTP_MAX_PIN_LENGTH) {
        cotp_secure_memzero (out_key, YAOTP_KEY_BYTES);
        *err = INVALID_YAOTP_SECRET_LENGTH;
        return -1;
    }

    return 0;
}

static int
yaotp_validate_pin (const char *pin, int expected_len, cotp_error_t *err)
{
    if (pin == NULL) { *err = INVALID_YAOTP_PIN; return -1; }
    size_t len = strlen (pin);
    if ((int)len != expected_len) { *err = INVALID_YAOTP_PIN; return -1; }
    for (size_t i = 0; i < len; i++) {
        if (!isdigit ((unsigned char)pin[i])) { *err = INVALID_YAOTP_PIN; return -1; }
    }
    return 0;
}

int
cotp_yaotp_secret_pin_length (const char   *base32_secret,
                              cotp_error_t *err_code)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err_code ? err_code : &local_err;

    if (base32_secret == NULL) { *errp = INVALID_USER_INPUT; return -1; }

    unsigned char key[YAOTP_KEY_BYTES];
    int pin_len = 0;
    if (yaotp_parse_secret (base32_secret, key, &pin_len, errp) != 0) {
        return -1;
    }
    cotp_secure_memzero (key, sizeof (key));

    *errp = NO_ERROR;
    return pin_len;
}

char *
get_yaotp_at (const char   *base32_secret,
              const char   *pin,
              long          timestamp,
              cotp_error_t *err_code)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err_code ? err_code : &local_err;

    if (base32_secret == NULL || pin == NULL) {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }

    if (whmac_check () == -1) {
        *errp = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    unsigned char key[YAOTP_KEY_BYTES];
    int pin_len = 0;
    if (yaotp_parse_secret (base32_secret, key, &pin_len, errp) != 0) {
        return NULL;
    }

    if (yaotp_validate_pin (pin, pin_len, errp) != 0) {
        cotp_secure_memzero (key, sizeof (key));
        return NULL;
    }

    // keyHash = SHA-256(pin || key). Concat into one buffer; wipe after hashing.
    size_t pin_bytes = (size_t)pin_len;
    size_t cat_len = pin_bytes + YAOTP_KEY_BYTES;
    unsigned char *cat = malloc (cat_len);
    if (cat == NULL) {
        cotp_secure_memzero (key, sizeof (key));
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    memcpy (cat, pin, pin_bytes);
    memcpy (cat + pin_bytes, key, YAOTP_KEY_BYTES);
    cotp_secure_memzero (key, sizeof (key));

    unsigned char key_hash[YAOTP_SHA256_BYTES];
    int hash_rc = whash_sha256 (cat, cat_len, key_hash);
    cotp_secure_memzero (cat, cat_len);
    free (cat);
    if (hash_rc != 0) {
        cotp_secure_memzero (key_hash, sizeof (key_hash));
        *errp = WHMAC_ERROR;
        return NULL;
    }

    // Leading-zero quirk: if key_hash[0] == 0x00, treat key_hash as starting at byte 1, length 31.
    // pyYaOTP omits this; KeeYaOtp does it; Yandex servers require it.
    size_t hash_offset = (key_hash[0] == 0x00) ? 1u : 0u;
    size_t hash_len    = YAOTP_SHA256_BYTES - hash_offset;

    // counter = floor(unix_time / 30), big-endian 8 bytes.
    int64_t counter = (int64_t)timestamp / COTP_YAOTP_PERIOD;
    unsigned char counter_be[8];
    for (int i = 0; i < 8; i++) {
        counter_be[i] = (unsigned char)((uint64_t)counter >> (56 - 8 * i));
    }

    whmac_handle_t *hd = whmac_gethandle (COTP_SHA256);
    if (hd == NULL) {
        cotp_secure_memzero (key_hash, sizeof (key_hash));
        *errp = WHMAC_ERROR;
        return NULL;
    }

    if (whmac_setkey (hd, key_hash + hash_offset, hash_len) != 0 ||
        whmac_update (hd, counter_be, sizeof (counter_be)) != 0) {
        whmac_freehandle (hd);
        cotp_secure_memzero (key_hash, sizeof (key_hash));
        *errp = WHMAC_ERROR;
        return NULL;
    }

    unsigned char mac[YAOTP_SHA256_BYTES];
    ssize_t flen = whmac_finalize (hd, mac, sizeof (mac));
    whmac_freehandle (hd);
    cotp_secure_memzero (key_hash, sizeof (key_hash));
    if (flen != (ssize_t)YAOTP_SHA256_BYTES) {
        cotp_secure_memzero (mac, sizeof (mac));
        *errp = WHMAC_ERROR;
        return NULL;
    }

    // 64-bit dynamic truncation (NOT RFC 4226's 32-bit truncation):
    // offset = mac[31] & 0x0F; value = be64(mac[offset..offset+8]) & 0x7FFF_FFFF_FFFF_FFFF.
    unsigned int offset = mac[YAOTP_SHA256_BYTES - 1] & 0x0Fu;
    if (offset + 8u > YAOTP_SHA256_BYTES) {
        cotp_secure_memzero (mac, sizeof (mac));
        *errp = WHMAC_ERROR;
        return NULL;
    }
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; i++) {
        value = (value << 8) | mac[offset + i];
    }
    value &= 0x7FFFFFFFFFFFFFFFULL;
    cotp_secure_memzero (mac, sizeof (mac));

    value %= YAOTP_BASE26_MOD;

    // Encode 8 base-26 chars (a..z) MSB-first.
    char *out = malloc (COTP_YAOTP_DIGITS + 1);
    if (out == NULL) {
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    for (int i = COTP_YAOTP_DIGITS - 1; i >= 0; i--) {
        out[i] = (char)('a' + (value % 26));
        value /= 26;
    }
    out[COTP_YAOTP_DIGITS] = '\0';

    *errp = NO_ERROR;
    return out;
}

char *
get_yaotp (const char   *base32_secret,
           const char   *pin,
           cotp_error_t *err_code)
{
    return get_yaotp_at (base32_secret, pin, (long)time (NULL), err_code);
}
