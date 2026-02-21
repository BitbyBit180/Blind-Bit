# Threat Model and Leakage

## Adversaries
- Honest-but-curious server that sees ciphertext, tokens, metadata, and query timing.
- External attacker with possible DB/log dump.
- Brute-force attacker targeting password/OTP endpoints.

## Assets
- Plaintext file/record contents.
- Search query intent.
- User key material and session state.

## Guarantees
- Plaintext confidentiality via AES-GCM encryption.
- Query token confidentiality via keyed HMAC tokens.
- Sensitive actions gated by authenticated + 2FA-verified session.
- Password and OTP failures are throttled with temporary lockouts.

## Residual Leakage (SSE)
- Access pattern leakage (matching IDs per query).
- Search pattern leakage (repeated token use can correlate repeated queries).
- Size leakage (ciphertext roughly reflects plaintext size).
- Timing leakage (complex queries can be slower).

## Mitigations Implemented
- Per-query decoy lookups (`SEARCH_OBFUSCATION_ENABLED`, `SEARCH_OBFUSCATION_DECOYS`).
- Result padding available in legacy server layer.
- Strict security headers, CSRF/session hardening, and secure cookie settings.

## Not Yet Solved
- Full ORAM-level access pattern hiding.
- Backward privacy guarantees post-deletion.
- Hardware-backed key custody.
