#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* We simulate the vulnerable pattern and test the invariant:
 * Buffer reads must never exceed the declared length.
 *
 * The invariant: before performing memcpy(out_key, decoded + (decoded_len_expected - 26), 26),
 * the function MUST verify that:
 *   1. decoded_len_expected >= 26
 *   2. actual buffer size >= decoded_len_expected
 *   3. The offset (decoded_len_expected - 26) + 26 <= actual_buffer_size
 */

#define YAOTP_KEY_BYTES 26

/* Safe extraction function that enforces the invariant */
static int safe_extract_key(const uint8_t *decoded, size_t actual_len,
                             size_t decoded_len_expected, uint8_t *out_key)
{
    /* Invariant checks */
    if (decoded == NULL || out_key == NULL) {
        return -1;
    }
    /* decoded_len_expected must be at least YAOTP_KEY_BYTES */
    if (decoded_len_expected < YAOTP_KEY_BYTES) {
        return -1;
    }
    /* actual buffer must be at least decoded_len_expected */
    if (actual_len < decoded_len_expected) {
        return -1;
    }
    /* The read region must be within bounds */
    size_t offset = decoded_len_expected - YAOTP_KEY_BYTES;
    if (offset + YAOTP_KEY_BYTES > actual_len) {
        return -1;
    }
    memcpy(out_key, decoded + offset, YAOTP_KEY_BYTES);
    return 0;
}

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    /* Invariant: Buffer reads must never exceed the declared length.
     * Any attempt to read beyond the actual buffer size must be rejected. */

    /* Each payload entry: { base64-like string, actual_buf_size, claimed_decoded_len_expected } */
    struct {
        const char *description;
        size_t actual_buf_size;
        size_t claimed_decoded_len_expected;
        int should_succeed;
    } payloads[] = {
        /* Normal valid case */
        { "valid: exact size", 26, 26, 1 },
        { "valid: larger buffer", 64, 64, 1 },
        { "valid: buffer bigger than claimed", 100, 64, 1 },

        /* Attack: claimed size larger than actual buffer (2x oversized) */
        { "attack: claimed 2x actual", 26, 52, 0 },
        { "attack: claimed 2x actual (64 vs 32)", 32, 64, 0 },

        /* Attack: claimed size 10x larger than actual buffer */
        { "attack: claimed 10x actual", 26, 260, 0 },
        { "attack: claimed 10x actual (10 vs 100)", 10, 100, 0 },

        /* Attack: decoded_len_expected less than YAOTP_KEY_BYTES */
        { "attack: claimed less than key bytes", 26, 25, 0 },
        { "attack: claimed zero", 26, 0, 0 },
        { "attack: claimed 1", 100, 1, 0 },

        /* Attack: empty buffer with large claimed size */
        { "attack: empty buffer large claim", 0, 1000, 0 },
        { "attack: empty buffer claim=26", 0, 26, 0 },

        /* Attack: off-by-one */
        { "attack: off-by-one (actual=25, claimed=26)", 25, 26, 0 },
        { "attack: off-by-one (actual=51, claimed=52)", 51, 52, 0 },

        /* Attack: integer overflow-like large values */
        { "attack: SIZE_MAX claimed", 26, SIZE_MAX, 0 },
        { "attack: SIZE_MAX - 1 claimed", 26, SIZE_MAX - 1, 0 },
        { "attack: very large claimed", 26, 0xFFFFFF, 0 },

        /* Attack: actual smaller than key bytes */
        { "attack: actual < key bytes", 10, 10, 0 },
        { "attack: actual=0 claimed=0", 0, 0, 0 },

        /* Edge: exact boundary conditions */
        { "edge: actual=26 claimed=26", 26, 26, 1 },
        { "edge: actual=27 claimed=27", 27, 27, 1 },
        { "edge: actual=27 claimed=26", 27, 26, 1 },
    };

    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        uint8_t out_key[YAOTP_KEY_BYTES];
        memset(out_key, 0, sizeof(out_key));

        /* Allocate actual buffer of the specified size */
        uint8_t *decoded = NULL;
        if (payloads[i].actual_buf_size > 0) {
            decoded = (uint8_t *)malloc(payloads[i].actual_buf_size);
            ck_assert_msg(decoded != NULL, "malloc failed for test case %d", i);
            /* Fill with known pattern */
            memset(decoded, 0xAB, payloads[i].actual_buf_size);
        }

        int result = safe_extract_key(decoded, payloads[i].actual_buf_size,
                                      payloads[i].claimed_decoded_len_expected,
                                      out_key);

        if (payloads[i].should_succeed) {
            ck_assert_msg(result == 0,
                "Test case %d ('%s'): expected success but got failure",
                i, payloads[i].description);
        } else {
            ck_assert_msg(result != 0,
                "Test case %d ('%s'): expected rejection of out-of-bounds read but got success. "
                "actual_buf=%zu, claimed=%zu — this indicates a buffer overread vulnerability!",
                i, payloads[i].description,
                payloads[i].actual_buf_size,
                payloads[i].claimed_decoded_len_expected);
        }

        if (decoded != NULL) {
            free(decoded);
        }
    }
}
END_TEST

/* Additional test: verify that the offset calculation itself cannot overflow */
START_TEST(test_offset_calculation_no_overflow)
{
    /* Invariant: offset = decoded_len_expected - YAOTP_KEY_BYTES must not wrap around */
    size_t dangerous_values[] = {
        0,
        1,
        YAOTP_KEY_BYTES - 1,
        SIZE_MAX,
        SIZE_MAX - YAOTP_KEY_BYTES + 1,
        SIZE_MAX - YAOTP_KEY_BYTES,
        (size_t)(-1),
        (size_t)(-26),
    };
    int num_vals = sizeof(dangerous_values) / sizeof(dangerous_values[0]);

    for (int i = 0; i < num_vals; i++) {
        uint8_t buf[64];
        uint8_t out_key[YAOTP_KEY_BYTES];
        memset(buf, 0xCC, sizeof(buf));
        memset(out_key, 0, sizeof(out_key));

        size_t claimed = dangerous_values[i];

        /* The safe function must reject all these as they would cause
         * out-of-bounds access on a 64-byte buffer */
        int result = safe_extract_key(buf, sizeof(buf), claimed, out_key);

        /* For values < YAOTP_KEY_BYTES or > sizeof(buf), must reject */
        if (claimed < YAOTP_KEY_BYTES || claimed > sizeof(buf)) {
            ck_assert_msg(result != 0,
                "Offset overflow/underflow not caught for claimed=%zu — "
                "buffer overread vulnerability detected!", claimed);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    tcase_add_test(tc_core, test_offset_calculation_no_overflow);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}