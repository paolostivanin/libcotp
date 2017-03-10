#include <stdio.h>
#include <time.h>
#include <string.h>
#include <gcrypt.h>
#include <stdint.h>

#define TOTP_NOT_VALID 0
#define TOTP_VALID 1

#define BITS_PER_BASE32_CHAR 5

static int base32_decode (const uint8_t *, uint8_t *, int);
static int base32_encode (const uint8_t *, int, uint8_t *, int);

static int DIGITS_POWER[] = {1,10,100,1000,10000,100000,1000000,10000000,100000000};


static int
truncate (unsigned char *hmac, int N)
{
    int offset = (hmac[19] & 0x0f);
    int bin_code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) | ((hmac[offset+2] & 0xff) << 8) | ((hmac[offset+3] & 0xff));
    int token = bin_code % DIGITS_POWER[N];
    return token;
}


static unsigned char
*compute_hmac (const char *K, long C)
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
        C_reverse_byte_order[i] = ((unsigned char *) &C)[j];

    gcry_md_hd_t hd;
    gcry_md_open (&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey (hd, secret, secret_len);
    gcry_md_write (hd, C_reverse_byte_order, sizeof (C_reverse_byte_order));
    gcry_md_final (hd);
    unsigned char *hmac =  gcry_md_read (hd, GCRY_MD_SHA1);
    return hmac;
}


static char
*finalize (int N, int tk)
{
	char *token = NULL;
    token = malloc (N+1);
    if (token == NULL) {
        printf ("[E] Error during memory allocation\n");
        return NULL;
    } else {
        if (N == 6)
            snprintf (token, 7, "%.6d", tk);
        else
            snprintf (token, 9, "%.8d", tk);
    }
    return token;
}


static int
check_otp_len (int N)
{
	if ((N != 6) && (N != 8)) {
        printf ("[E]: You must choose between 6 or 8 digits\n");
        return -1;
    } else {
        return 0;
    }
}


char
*get_hotp (const char *K, long C, int N)
{
    if (check_otp_len (N) == -1)
    	return NULL;

    unsigned char *hmac = compute_hmac (K, C);
    int tk = truncate (hmac, N);
    char *token = finalize (N, tk);
    return token;
}


char
*get_totp (const char *K, int N)
{
    if (check_otp_len (N) == -1)
    	return NULL;

    long TC = ((long) time (NULL))/30;
    char *token = get_hotp (K, TC, N);
    return token;
}


int
totp_verify (const char *K, int N, const char *user_totp)
{
    int token_status;
    char *current_totp = get_totp (K, N);
    if (strcmp (current_totp, user_totp) != 0) {
        token_status = TOTP_NOT_VALID;
    } else {
        token_status = TOTP_VALID;
    }
    free (current_totp);
    return token_status;
}