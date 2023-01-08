#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cotp.h"

#define BITS_PER_BYTE               8
#define BITS_PER_B32_BLOCK          5

// 64 MB should be more than enough
#define MAX_ENCODE_INPUT_LEN        (64*1024*1024)
// if 64 MB of data is encoded than it should be also possible to decode it. That's why a bigger input is allowed for decoding
#define MAX_DECODE_BASE32_INPUT_LEN ((MAX_ENCODE_INPUT_LEN * 8 + 4) / 5)

static int is_valid_b32_input   (const char    *user_data);

static int get_char_index       (uint8_t        c);

static cotp_error_t check_input (const uint8_t *user_data,
                                 size_t         data_len,
                                 int            max_len);

static int strip_char           (char          *str,
                                 char           strip);

static const uint8_t b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";


// The encoding process represents 40-bit groups of input bits as output strings of 8 encoded characters. The input data must be null terminated.
char *
base32_encode (const uint8_t *user_data,
               size_t         data_len,
               cotp_error_t  *err_code)
{
    cotp_error_t error = check_input (user_data, data_len, MAX_ENCODE_INPUT_LEN);
    if (error == EMPTY_STRING) {
        return strdup ("");
    }
    if (error != NO_ERROR) {
        *err_code = error;
        return NULL;
    }

    size_t user_data_chars = 0, total_bits = 0;
    int num_of_equals = 0;
    for (int i = 0; i < data_len; i++) {
        // As it's not known whether data_len is with or without the +1 for the null byte, a manual check is required.
        // Check for null byte only at the end of the user given length, otherwise issue#23 may occur
        if (user_data[i] == '\0' && i == data_len-1) {
            break;
        } else {
            total_bits += 8;
            user_data_chars += 1;
        }
    }
    switch (total_bits % 40) {
        case 8:  num_of_equals = 6; break;
        case 16: num_of_equals = 4; break;
        case 24: num_of_equals = 3; break;
        case 32: num_of_equals = 1; break;
    }

    size_t output_length = (user_data_chars * 8 + 4) / 5;
    char *encoded_data = calloc (output_length + num_of_equals + 1, 1);
    if (encoded_data == NULL) {
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    for (int i = 0, j = 0; i < user_data_chars;) {
        uint64_t first_octet = i < user_data_chars ? user_data[i++] : 0;
        uint64_t second_octet = i < user_data_chars ? user_data[i++] : 0;
        uint64_t third_octet = i < user_data_chars ? user_data[i++] : 0;
        uint64_t fourth_octet = i < user_data_chars ? user_data[i++] : 0;
        uint64_t fifth_octet = i < user_data_chars ? user_data[i++] : 0;
        uint64_t quintuple =
                ((first_octet >> 3) << 35) +
                ((((first_octet & 0x7) << 2) | (second_octet >> 6)) << 30) +
                (((second_octet & 0x3F) >> 1) << 25) +
                ((((second_octet & 0x01) << 4) | (third_octet >> 4)) << 20) +
                ((((third_octet & 0xF) << 1) | (fourth_octet >> 7)) << 15) +
                (((fourth_octet & 0x7F) >> 2) << 10) +
                ((((fourth_octet & 0x3) << 3) | (fifth_octet >> 5)) << 5) +
                (fifth_octet & 0x1F);

        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 35) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 30) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 25) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 20) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 15) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 10) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 5) & 0x1F];
        encoded_data[j++] = (char)b32_alphabet[(quintuple >> 0) & 0x1F];
    }

    for (int i = 0; i < num_of_equals; i++) {
        encoded_data[output_length + i] = '=';
    }
    encoded_data[output_length + num_of_equals] = '\0';

    *err_code = NO_ERROR;

    return encoded_data;
}


uint8_t *
base32_decode (const char   *user_data_untrimmed,
               size_t        data_len,
               cotp_error_t *err_code)
{
    cotp_error_t error = check_input ((uint8_t *)user_data_untrimmed, data_len, MAX_DECODE_BASE32_INPUT_LEN);
    if (error == EMPTY_STRING) {
        return (uint8_t *)strdup ("");
    }
    if (error != NO_ERROR) {
        *err_code = error;
        return NULL;
    }

    char *user_data = strdup (user_data_untrimmed);
    if (user_data == NULL) {
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    data_len -= strip_char(user_data, ' ');

    if (!is_valid_b32_input(user_data)) {
        free (user_data);
        *err_code = INVALID_B32_INPUT;
        return NULL;
    }

    size_t user_data_chars = 0;
    for (int i = 0; i < data_len; i++) {
        // As it's not known whether data_len is with or without the +1 for the null byte, a manual check is required.
        if (user_data[i] != '=' && user_data[i] != '\0') {
            user_data_chars += 1;
        }
    }

    size_t output_length = (size_t)((user_data_chars + 1.6 + 1) / 1.6);  // round up
    uint8_t *decoded_data = calloc(output_length + 1, 1);
    if (decoded_data == NULL) {
        free (user_data);
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    uint8_t mask, current_byte = 0;
    int bits_left = 8;
    for (int i = 0, j = 0; i < user_data_chars; i++) {
        int char_index = get_char_index ((uint8_t)user_data[i]);
        if (bits_left > BITS_PER_B32_BLOCK) {
            mask = (uint8_t)char_index << (bits_left - BITS_PER_B32_BLOCK);
            current_byte = (uint8_t) (current_byte | mask);
            bits_left -= BITS_PER_B32_BLOCK;
        } else {
            mask = (uint8_t)char_index >> (BITS_PER_B32_BLOCK - bits_left);
            current_byte = (uint8_t) (current_byte | mask);
            decoded_data[j++] = current_byte;
            current_byte = (uint8_t) (char_index << (BITS_PER_BYTE - BITS_PER_B32_BLOCK + bits_left));
            bits_left += BITS_PER_BYTE - BITS_PER_B32_BLOCK;
        }
    }
    decoded_data[output_length] = '\0';

    free (user_data);

    *err_code = NO_ERROR;

    return decoded_data;
}


static int
is_valid_b32_input (const char *user_data)
{
    // Create a lookup table for ASCII characters
    uint8_t table[128];
    memset (table, 0, sizeof (table));
    for (size_t i = 0; i < sizeof (b32_alphabet); i++) {
        table[b32_alphabet[i]] = 1;
    }
    table['='] = 1;

    const char *p;
    for (p = user_data; *p; p++) {
        if (!table[*(uint8_t *)p]) {
            return 0;
        }
    }
    return 1;
}


static int
get_char_index (uint8_t c)
{
    for (int i = 0; i < sizeof (b32_alphabet); i++) {
        if (b32_alphabet[i] == c) {
            return i;
        }
    }
    return -1;
}


static int
strip_char (char *str,
            char  strip)
{
    int found = 0;

    // Create a lookup table for ASCII characters
    uint8_t table[128];
    memset (table, 0, sizeof (table));
    table[(int)strip] = 1;

    // Iterate through the string using pointers
    char *p, *q;
    for (q = p = str; *p; p++) {
        if (!table[*(uint8_t *)p]) {
            *q++ = *p;
        } else {
            found++;
        }
    }
    *q = '\0';
    return found;
}


static cotp_error_t
check_input (const uint8_t *user_data,
             size_t               data_len,
             int                  max_len)
{
    if (!user_data || (data_len == 0 && user_data[0] != '\0') || (data_len > (size_t)max_len)) {
        return INVALID_USER_INPUT;
    }

    if (user_data[0] == '\0') {
        return EMPTY_STRING;
    }

    return NO_ERROR;
}