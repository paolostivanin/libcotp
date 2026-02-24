#include <stdlib.h>
#include <string.h>
#include "../cotp.h"

#define BITS_PER_BYTE               8
#define BITS_PER_B32_BLOCK          5

// 64 MB should be more than enough
#define MAX_ENCODE_INPUT_LEN        (64*1024*1024)

// if 64 MB of data is encoded than it should be also possible to decode it. That's why a bigger input is allowed for decoding
#define MAX_DECODE_BASE32_INPUT_LEN ((MAX_ENCODE_INPUT_LEN * 8 + 4) / 5)

static const uint8_t b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// O(1) lookup table for base32 character → index (0-31), -1 for invalid
static const int8_t b32_char_index[256] = {
    ['A'] =  0, ['B'] =  1, ['C'] =  2, ['D'] =  3, ['E'] =  4,
    ['F'] =  5, ['G'] =  6, ['H'] =  7, ['I'] =  8, ['J'] =  9,
    ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14,
    ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
    ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24,
    ['Z'] = 25, ['2'] = 26, ['3'] = 27, ['4'] = 28, ['5'] = 29,
    ['6'] = 30, ['7'] = 31,
};

// Static const validity table for base32 characters (A-Z, a-z, 2-7, =)
static const uint8_t b32_valid[128] = {
    ['A'] = 1, ['B'] = 1, ['C'] = 1, ['D'] = 1, ['E'] = 1,
    ['F'] = 1, ['G'] = 1, ['H'] = 1, ['I'] = 1, ['J'] = 1,
    ['K'] = 1, ['L'] = 1, ['M'] = 1, ['N'] = 1, ['O'] = 1,
    ['P'] = 1, ['Q'] = 1, ['R'] = 1, ['S'] = 1, ['T'] = 1,
    ['U'] = 1, ['V'] = 1, ['W'] = 1, ['X'] = 1, ['Y'] = 1,
    ['Z'] = 1,
    ['a'] = 1, ['b'] = 1, ['c'] = 1, ['d'] = 1, ['e'] = 1,
    ['f'] = 1, ['g'] = 1, ['h'] = 1, ['i'] = 1, ['j'] = 1,
    ['k'] = 1, ['l'] = 1, ['m'] = 1, ['n'] = 1, ['o'] = 1,
    ['p'] = 1, ['q'] = 1, ['r'] = 1, ['s'] = 1, ['t'] = 1,
    ['u'] = 1, ['v'] = 1, ['w'] = 1, ['x'] = 1, ['y'] = 1,
    ['z'] = 1,
    ['2'] = 1, ['3'] = 1, ['4'] = 1, ['5'] = 1,
    ['6'] = 1, ['7'] = 1, ['='] = 1,
};

static int           get_char_index (uint8_t        c);

static bool          valid_b32_str (const char *str);

static bool          has_space      (const char *str);

static cotp_error_t  check_input    (const uint8_t *user_data,
                                     size_t         data_len,
                                     int32_t        max_len);

static int           strip_char     (char          *str);


// The encoding process represents 40-bit groups of input bits as output strings of 8 encoded characters. The input data must be null terminated.
char *
base32_encode (const uint8_t *user_data,
               size_t         data_len,
               cotp_error_t  *err_code)
{
    cotp_error_t error = check_input (user_data, data_len, MAX_ENCODE_INPUT_LEN);
    if (error == EMPTY_STRING) {
        *err_code = error;
        return strdup ("");
    }
    if (error != NO_ERROR) {
        *err_code = error;
        return NULL;
    }

    size_t user_data_chars = 0, total_bits = 0;
    int num_of_equals = 0;
    int null_terminated = false;
    if (user_data[data_len - 1] == '\0' && memchr(user_data, '\0', data_len - 1) == NULL) {
        // the user might give the input with the null byte, we need to check for that
        null_terminated = true;
    }
    for (int i = 0; i < data_len; i++) {
        if (null_terminated == true && user_data[i] == '\0' && i == data_len-1) {
            break;
        }
        total_bits += 8;
        user_data_chars += 1;
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

    for (int i = 0, j = 0; i < user_data_chars; i += 5) {
        uint64_t quintuple = 0;

        for (int k = 0; k < 5; k++) {
            quintuple = (quintuple << 8) | (i + k < user_data_chars ? user_data[i + k] : 0);
        }

        for (int shift = 35; shift >= 0; shift -= 5) {
            encoded_data[j++] = (char)b32_alphabet[(quintuple >> shift) & 0x1F];
        }
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
        *err_code = error;
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
    data_len -= strip_char (user_data);

    if (!is_string_valid_b32 (user_data)) {
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

    // Compute exact maximum output length as floor(chars * 5 / 8)
    size_t output_length = (user_data_chars * 5) / 8;
    uint8_t *decoded_data = calloc(output_length + 1, 1);
    if (decoded_data == NULL) {
        free (user_data);
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    uint8_t mask, current_byte = 0;
    int bits_left = 8;
    size_t j = 0;
    for (int i = 0; i < (int)user_data_chars; i++) {
        int char_index = get_char_index ((uint8_t)user_data[i]);
        if (bits_left > BITS_PER_B32_BLOCK) {
            mask = (uint8_t)char_index << (bits_left - BITS_PER_B32_BLOCK);
            current_byte |= mask;
            bits_left -= BITS_PER_B32_BLOCK;
        } else {
            mask = (uint8_t)char_index >> (BITS_PER_B32_BLOCK - bits_left);
            current_byte |= mask;
            if (j < output_length) {
                decoded_data[j++] = current_byte;
            }
            current_byte = (uint8_t)(char_index << (BITS_PER_BYTE - BITS_PER_B32_BLOCK + bits_left));
            bits_left += BITS_PER_BYTE - BITS_PER_B32_BLOCK;
        }
    }
    decoded_data[j] = '\0';

    free (user_data);

    *err_code = NO_ERROR;

    return decoded_data;
}


bool
is_string_valid_b32 (const char *user_data)
{
    if (user_data == NULL) {
        return false;
    }

    if (has_space (user_data)) {
        char *trimmed = strdup (user_data);
        if (trimmed == NULL) {
            return false;
        }
        strip_char (trimmed);
        bool valid = valid_b32_str (trimmed);
        free(trimmed);
        return valid;
    }

    return valid_b32_str (user_data);
}


static bool
valid_b32_str (const char *str)
{
    if (str == NULL) {
        return false;
    }

    while (*str) {
        uint8_t c = (uint8_t)*str;
        if (c >= 128 || !b32_valid[c]) {
            return false;
        }
        str++;
    }

    return true;
}


static bool
has_space (const char *str)
{
    while (*str) {
        if (*str == ' ') {
            return true;
        }
        str++;
    }
    return false;
}


static int
get_char_index (uint8_t c)
{
    if (c >= 'a' && c <= 'z') {
        c = c - 'a' + 'A';
    }
    if (c >= 'A' && c <= 'Z') {
        return b32_char_index[c];
    }
    if (c >= '2' && c <= '7') {
        return b32_char_index[c];
    }
    return -1;
}


static int
strip_char (char *str)
{
    const char strip = ' ';
    uint8_t table[256] = {0};
    table[(uint8_t)strip] = 1;

    int found = 0;
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
             size_t         data_len,
             int32_t        max_len)
{
    if (!user_data || data_len > max_len) {
        return INVALID_USER_INPUT;
    }

    if (data_len == 0) {
        return EMPTY_STRING;
    }

    return NO_ERROR;
}
