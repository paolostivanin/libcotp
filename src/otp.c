#include <stdio.h>
#include <time.h>
#include <string.h>
#include <gcrypt.h>
#include <math.h>
#include <stdint.h>

#define BITS_PER_BASE32_CHAR 5

/* ToDo:
 * - 2 funcs, 1 google auth based and 1 normal otp
 * - decide between 6 or 8 digits
 */

int base32_decode (const uint8_t *, uint8_t *, int);
int base32_encode (const uint8_t *, int, uint8_t *, int);

int DIGITS_POWER[] = {1,10,100,1000,10000,100000,1000000,10000000,100000000};

int Truncate (unsigned char *hmac, int N)
{
    int O = (hmac[19] & 0x0f);
    int bin_code = ((hmac[O] & 0x7f) << 24) | ((hmac[O+1] & 0xff) << 16) | ((hmac[O+2] & 0xff) << 8) | ((hmac[O+3] & 0xff));
    int token = bin_code % DIGITS_POWER[N];
    return token;
}

unsigned char *HMAC (const char *K, long C)
{
	/* Estimated number of bytes needed to represent the decoded secret. Because
	 * of white-space and separators, this is an upper bound of the real number,
	 * which we later get as a return-value from base32_decode()
     */
    int secret_len = (strlen (K) + 7)/8*BITS_PER_BASE32_CHAR;

    /* Sanity check, that our secret will fixed into a reasonably-sized static
	 * array.
     */
	if (secret_len < 0 || secret_len > 100)
		return NULL;

    uint8_t secret[secret_len];

    /* Decode secret from Base32 to a binary representation, and check that we
	 * have at least one byte's worth of secret data.
     */
    if ((secret_len = base32_decode ((const uint8_t *) K, secret, secret_len)) < 1)
        return NULL;

    unsigned char C_reverse_byte_order[8];
    int j, i;
    for (j=0, i=7; j<8 && i>=0; j++, i--)
        C_reverse_byte_order[i] = ((unsigned char *)&C)[j];

    gcry_md_hd_t hd;
    gcry_md_open (&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey (hd, secret, secret_len);
    gcry_md_write (hd, C_reverse_byte_order, sizeof (C_reverse_byte_order));
    gcry_md_final (hd);
    unsigned char *hmac =  gcry_md_read (hd, GCRY_MD_SHA1);
    return hmac;
}


int HOTP (const char *K, long C, int N)
{
    unsigned char *hmac = HMAC(K, C);
    int token = Truncate (hmac, N);
    return token;
}


int TOTP (const char *K, int N)
{
    long TC = ((long) time (NULL))/30;
    return HOTP(K, TC, N);
}

int main (void)
{
    int i;
    int tk = TOTP("", 6); // write secret token. Get it from argv or from encrypted file? 6 or 8 digits?
    int digits = floor (log10 (abs (tk))) + 1;
    if (digits < 6)
    {
        for (i=0; i<(6-digits); i++)
            printf("0");
    }
    printf ("%d\n", tk);
    return 0;
}
