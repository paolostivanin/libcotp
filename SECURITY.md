# Security Policy

## Supported Versions

The following list describes whether a version is eligible or not for security updates.

| Version | Supported | EOL         |
|---------|----------|-------------|
| 4.2.x   | :white_check_mark: | - |
| 4.1.x   | :white_check_mark: | 31-Oct-2026 |
| 4.0.x   | :x:      | 30-Jun-2026 |
| 3.1.x   | :x:      | 01-May-2026 |
| 3.0.x   | :x:      | 30-Sep-2025 |
| 2.0.x   | :x:      | 31-Dec-2023 |
| 1.2.x   | :x:      | 30-Jun-2023 |
| 1.1.x   | :x:      | 31-Dec-2021 |
| 1.0.x   | :x:      | 31-Dec-2021 |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it **privately** via [e-mail](mailto:paolostivanin@users.noreply.github.com).  
The process is as follows:
- Send me an e-mail describing the security issue.
- Within **24 hours**, I will acknowledge your report and provide initial feedback (for example, whether it is indeed a vulnerability and its potential severity).
- Within **7 days**, I will work on a fix and release an update.
- Once the update is available, I will publish a [security advisory](https://github.com/paolostivanin/libcotp/security/advisories).  

## Recent Hardening

- 2026-09-23: Hardened input validation and error handling: overflow-checked window arithmetic, rejection of negative timestamps and `INT_MIN` windows, strict percent-escape/base32 validation, blank-secret rejection and secure erasure of replaced secrets in otpauth/yaotp URIs, and rejection of out-of-range YAOTP pin-length nibbles. Fixed a leak of the OpenSSL MAC context on re-key and missing NULL-handle guards in the HMAC backends.
- 2025-10-03: Strengthened base32 decoding to use exact integer sizing and tightened writes to avoid potential over-allocation and to prevent out-of-bounds writes.
