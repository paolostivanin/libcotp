# libcotp — Proposed Improvements and Feature Roadmap (updated)

## 1) What features would we add?

- URI and provisioning helpers
  - otpauth:// URI parser/serializer (HOTP/TOTP, labels, issuer, algorithm, digits, counter, period, secret validation) behind an optional build flag to keep core small.
  - QR payload generation (string only; no image dependency) to integrate with external QR libraries.

- Time drift and time utilities
  - Optional time‑step alignment utilities (next/prev step boundaries, remaining seconds) for UI integrations.

- Secret management utilities
  - Cryptographically secure secret generation utility (base32 output, selectable size, RFC‑friendly alphabet; option to return raw bytes).
  - Optional PBKDF (e.g., HKDF/PKCS#5) helper for deriving seeds from passphrases when required by integrators (kept in a separate module to avoid scope creep).

- Backend flexibility
  - Runtime selection between gcrypt/openssl/mbedtls when multiple are compiled in; keep compile‑time selection as default.
  - Expose a lightweight plug‑in interface for new HMAC backends while preserving the current wrapper API.

- Platform support and integration
  - Windows (MSVC) build support and CI; ensure secure zero primitives map correctly (e.g., SecureZeroMemory/explicit_bzero shim).
  - Optional thread‑safe context API enabling reentrancy and easier use from multithreaded apps.

- Utility conversions
  - Companion formatter ensuring fixed‑width, zero‑padded strings without UB.
  - Base32 enhancements: optional case‑strict mode, optional padding enforcement, fast path for already‑normalized input.

- Examples and tooling
  - Minimal example programs (not installed) showing HOTP/TOTP generation, URI parsing, and validation with drift window.

## Prioritization (suggested)

1. Tests and fuzzing around base32 and OTP math (property‑based + fuzzing).
2. Documentation cookbook with common tasks and examples.
3. Build/portability polish (backend diagnostics; Windows CI prep).
4. URI parser/serializer behind option flags; time‑step utilities.
5. Runtime backend selection and plug‑in interface.

Contributions welcome — please open an issue to discuss scope before large changes to keep the library focused and portable.