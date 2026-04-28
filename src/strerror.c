#include "cotp.h"

const char *
cotp_strerror (cotp_error_t err)
{
    switch (err) {
        case NO_ERROR:                 return "no error";
        case VALID:                    return "OTP validated";
        case WCRYPT_VERSION_MISMATCH:  return "crypto backend version mismatch";
        case INVALID_B32_INPUT:        return "invalid base32 input";
        case INVALID_ALGO:             return "invalid algorithm";
        case INVALID_DIGITS:           return "invalid digits (must be 4-10)";
        case INVALID_PERIOD:           return "invalid period (must be 1-120)";
        case MEMORY_ALLOCATION_ERROR:  return "memory allocation failed";
        case INVALID_USER_INPUT:       return "invalid user input";
        case EMPTY_STRING:             return "empty string";
        case MISSING_LEADING_ZERO:     return "leading zero dropped during conversion";
        case INVALID_COUNTER:          return "invalid counter (must be >= 0)";
        case WHMAC_ERROR:              return "HMAC computation error";
    }
    return "unknown error";
}
