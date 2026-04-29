#pragma once
// Compatibility shim: cotp_secure_memzero / cotp_timing_safe_memcmp are now
// declared in the public header. Internal sources include this for legacy
// reasons; new code should include <cotp.h> directly.
#include "../cotp.h"
