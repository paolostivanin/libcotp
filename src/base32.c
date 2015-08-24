/* Base32 implementation
 *
 * Copyright 2010 Google Inc.
 * Author: Markus Gutschke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <stdint.h>

int
base32_decode ( const uint8_t *encoded,
                uint8_t *result, int buf_size)
{
    int buffer = 0;
    int bits_left = 0;
    int count = 0;
    for (const uint8_t *ptr = encoded; count < buf_size && *ptr; ++ptr)
    {
        uint8_t ch = *ptr;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-')
            continue;

        buffer <<= 5;

        // Deal with commonly mistyped characters
        if (ch == '0')
            ch = 'O';
        else if (ch == '1')
            ch = 'L';
        else if (ch == '8')
            ch = 'B';

        // Look up one base32 digit
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
            ch = (ch & 0x1F) - 1;
        else if (ch >= '2' && ch <= '7')
            ch -= '2' - 26;
        else
            return -1;

        buffer |= ch;
        bits_left += 5;
        if (bits_left >= 8)
        {
            result[count++] = buffer >> (bits_left - 8);
            bits_left -= 8;
        }
    }
    if (count < buf_size)
        result[count] = '\000';

    return count;
}

int
base32_encode ( const uint8_t *data, int data_length,
                uint8_t *result, int buf_size)
{
    if (data_length < 0 || data_length > (1 << 28))
        return -1;

    int count = 0;
    if (data_length > 0)
    {
        int buffer = data[0];
        int next = 1;
        int bits_left = 8;
        while (count < buf_size && (bits_left > 0 || next < data_length))
        {
            if (bits_left < 5)
            {
                if (next < data_length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bits_left += 8;
                }
                else
                {
                    int pad = 5 - bits_left;
                    buffer <<= pad;
                    bits_left += pad;
                }
            }
            int index = 0x1F & (buffer >> (bits_left - 5));
            bits_left -= 5;
            result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
        }
    }
    if (count < buf_size)
        result[count] = '\000';

    return count;
}
