# BlindBit SSE - Product Requirements Document (PRD)

## 1. Document Overview
- Product: BlindBit SSE
- Type: Privacy-first encrypted storage and searchable encryption web app
- Primary audience: Judges, contributors, and future maintainers
- Status: Implementation-aligned draft for hackathon delivery

## 2. Executive Summary
BlindBit SSE is a zero-knowledge style encrypted data platform where users can upload data, search encrypted indexes, and retrieve content without exposing plaintext to the server storage layer. The product combines authenticated encryption (AES-GCM), keyed tokenization (HMAC), and strong account security controls (password, 2FA, lockouts, trusted device flow, recovery codes).

This PRD defines:
- Product scope and user value
- Functional and non-functional requirements
- Security model and leakage tradeoffs
- UX expectations for core workflows and educational playground
- Delivery, testing, and acceptance criteria

## 3. Problem Statement
Traditional cloud storage/search products require server-side plaintext processing. This creates privacy risk for sensitive user content and query intent. BlindBit SSE addresses this by:
- Encrypting user data before storage
- Searching through secure tokens instead of plaintext terms
- Restricting key/session usage to authenticated and 2FA-verified users

## 4. Vision, Goals, and Non-Goals
### 4.1 Vision
Provide practical searchable encryption with understandable UX and explicit security tradeoffs.

### 4.2 Product Goals
- Confidentiality: server stores encrypted blobs and opaque tokens only
- Integrity: tampering is detectable via AES-GCM authentication
- Secure access: sensitive operations require authenticated + 2FA-verified session
- Usability: crypto complexity hidden behind clear UI
- Learnability: playground teaches encryption and search internals interactively

### 4.3 Non-Goals (Current Version)
- ORAM-level access pattern hiding
- Full backward privacy guarantees after deletion
- Hardware-backed key custody (HSM/TEE)
- Enterprise IAM/SAML/SCIM integrations

## 5. User Personas and Primary Jobs
### 5.1 Standard User
- Register account and configure 2FA
- Upload files/records securely
- Search encrypted data using multiple query modes
- Download and delete owned data

### 5.2 Security Reviewer / Judge
- Validate threat model and leakage transparency
- Validate defensive controls and tests
- Evaluate UX clarity and educational value

### 5.3 Admin (Platform Operations)
- Monitor app health and basic operational state
- Cannot decrypt user content by design

## 6. Scope
### 6.1 In Scope
- Authentication with mandatory 2FA setup
- Trusted-device login experience (2FA challenge reduction)
- Recovery code flow for lost authenticator
- Encrypted file/record storage and retrieval
- SSE search with exact, prefix/contains, fuzzy, phrase/regex-capable paths
- Query parsing for +/- terms and AND/OR behavior
- Security headers, lockouts, rate limiting, and safe errors
- Interactive mission-based encryption playground

### 6.2 Out of Scope
- Cross-tenant collaborative sharing with per-document ACLs
- Multi-region active-active deployments
- Advanced compliance packs (HIPAA/GDPR legal automation)

## 7. Functional Requirements
## 7.1 Authentication and Account Security
1. Registration
- User provides username, optional email, password
- Password policy enforced by app validators and UI checks

Acceptance criteria:
- Registration rejects weak/invalid password input
- Duplicate usernames blocked

2. 2FA setup and verification
- TOTP secret provisioned via QR and manual key
- User verifies one TOTP code to enable 2FA

Acceptance criteria:
- 2FA flag remains disabled until successful verification
- 2FA setup attempts lock out after repeated failures

3. Login with adaptive 2FA
- Password check first
- If 2FA enabled, require TOTP unless trusted-device proof is valid
- Remember-device option stores signed, time-limited trusted marker

Acceptance criteria:
- New/untrusted device requires TOTP or recovery code
- Trusted remembered device can skip repeated TOTP prompts during validity period

4. Recovery flow for lost authenticator
- One-time recovery codes generated and stored hashed
- Recovery code can replace TOTP once and is consumed
- Recovery login forces re-enrollment of authenticator and refreshes recovery codes

Acceptance criteria:
- Used recovery code cannot be reused
- Recovery codes shown once after generation and not retrievable in plaintext later

5. Defensive controls
- Per-IP and per-account lockouts for password and OTP failures
- Rate limiting on login POST
- Security headers enabled globally
- Error responses avoid stack trace leakage

Acceptance criteria:
- Lockout messages shown when thresholds exceeded
- Sensitive headers present in responses

## 7.2 Key Management and Session Behavior
1. Session key derivation
- Master key derived at login from password + TOTP secret + user salt
- Derived key material stored only in server session (not DB)

2. Session gating
- Sensitive endpoints require authenticated user and 2FA-verified session marker

Acceptance criteria:
- Upload, search, download, delete endpoints fail with 403/redirect when session key marker missing

## 7.3 Encrypted Data Management
1. Upload
- Accept supported file types (TXT/PDF)
- Extract text, preprocess keywords, encrypt payload, build index entries

2. Download
- Decrypt owned encrypted blob using session key material

3. Delete
- Remove encrypted objects and related index rows

Acceptance criteria:
- User isolation enforced for all operations
- Decryption/download fails safely if key session invalid

## 7.4 Search (SSE)
1. Query parsing and logic
- Supports +term, -term parsing
- Supports default AND/OR logic where applicable

2. Search modes
- Exact
- Substring/prefix-style matching
- Fuzzy candidate expansion
- Phrase/regex-capable flow with verification

3. Ranking
- Relevance ranking via stored scores (TF-IDF-like signal)

4. Leakage mitigation options
- Optional decoy lookups to reduce direct query-pattern observability

Acceptance criteria:
- Invalid mode/logic rejected with safe errors
- Parser behavior covered by regression tests
- Candidate filtering respects include/exclude semantics

## 7.5 Playground / Visualizer UX
1. Educational flow
- Show input -> key previews -> encrypted output (IV/ciphertext/tag) -> token list

2. Interactive search simulation
- Query against generated keywords by mode
- Highlight matches and show counts

3. Mission mode
- Goal-driven tasks with score/rank/progress
- Action log to guide comprehension

Acceptance criteria:
- Users can complete guided missions without external explanation
- Visualizer API failures are handled with readable UI errors

## 8. Non-Functional Requirements
## 8.1 Security
- Use vetted libraries for crypto and auth
- No plaintext secrets in logs
- Session/cookie protections enabled

Targets:
- 0 known plaintext leaks in API responses/logs during test runs
- 100% sensitive endpoints require auth + valid key session

## 8.2 Performance
Targets (hackathon baseline):
- Search P50 under 200 ms on small/medium demo corpus
- Upload/index latency acceptable for <= 10 MB demo files

## 8.3 Reliability
- Graceful handling of malformed input and crypto failures
- No unhandled exceptions in happy-path and known invalid-path tests

## 8.4 Maintainability
- Regression tests for auth, lockouts, parser, and endpoint gates
- Clear docs for threat model and sequence flows

## 9. Security and Privacy Model
## 9.1 Assets
- Plaintext file/record contents
- Query intent
- Session key material
- 2FA and recovery factors

## 9.2 Threat Actors
- Honest-but-curious server operator
- External attacker with DB/log access
- Credential-stuffing/brute-force attacker

## 9.3 Guarantees
- Confidentiality of stored blobs via AES-GCM
- Token confidentiality via keyed hashing
- User isolation by ownership checks and authenticated sessions
- Integrity verification through authenticated encryption

## 9.4 Explicit SSE Leakage
- Access pattern leakage
- Search pattern linkage on repeated terms
- Size leakage from ciphertext lengths
- Timing leakage from query complexity

## 9.5 Mitigations Implemented
- Lockouts/rate limits
- Header hardening
- Optional decoy lookups
- Recovery and re-enrollment flow for 2FA loss scenarios

## 10. Data and Storage Requirements
- User profile stores encrypted TOTP secret and metadata
- Encrypted blobs stored as binary payloads
- Token indexes store opaque token values and scoring metadata
- Recovery codes stored as password-style hashes only
- Local/dev DB artifacts must not be committed to source control

## 11. UX Requirements and Product Behavior
1. Auth UX
- Progressive two-step login flow: Step 1 (Username/Password), Step 2 (2FA/Recovery Code if enabled).
- Clear prompts for when/why 2FA is required on the dedicated second-step page.
- Remember-device option with explicit duration, accessible during the 2FA challenge.
- Recovery code option visible on the 2FA challenge page.

2. Recovery UX
- After recovery login, user must rebind authenticator app before normal use
- Fresh recovery codes shown once and must be saved offline

3. Search UX
- Explain mode behavior simply in UI
- Return readable errors for invalid queries/modes

4. Playground UX
- Mission-first structure to reduce confusion
- Immediate visual feedback for each interaction

## 12. Observability and Metrics
Track at minimum:
- Login success/failure counts and lockout events
- OTP and recovery-code usage events
- Search mode usage and latency
- Upload/index duration
- Playground mission completion rate (optional analytics)

## 13. QA and Acceptance Test Plan
Minimum regression suite must cover:
- Registration password policy
- Login lockout behavior
- 2FA requirement for untrusted device
- Trusted-device login bypass correctness
- Recovery code consume-once behavior
- Forced re-enrollment path after recovery
- Sensitive endpoint 2FA/session gate behavior
- Search parser validation for mode/logic and +/- terms

Release gate:
- App test suite green for accounts + drive modules
- No known critical security defects

## 14. Deployment and Environment Expectations
- Dev: SQLite acceptable
- Production: PostgreSQL recommended
- Environment variables for security/runtime toggles must be documented
- HTTPS required in production for secure cookies and credential safety

## 15. Risks and Mitigations
1. Risk: User loses authenticator and recovery codes
- Mitigation: clear unrecoverable-data warning and backup guidance

2. Risk: SSE leakage misunderstood by users/judges
- Mitigation: explicit threat/leakage docs and demo explanation

3. Risk: UX complexity reduces demo clarity
- Mitigation: mission-based playground and guided copy

## 16. Roadmap (Post-Hackathon)
- Security settings page to rotate/reissue recovery codes
- Expanded trusted-device management (list and revoke devices)
- Better search obfuscation and batching
- Optional access-pattern mitigation experiments
- Benchmark automation and dashboard packaging

## 17. Deliverables Checklist Mapping
- PRD: this document
- Threat model: docs/THREAT_MODEL.md
- Sequence diagrams: docs/SEQUENCE_DIAGRAMS.md
- Test evidence: accounts and drive regression runs
- Demo assets: screenshots/video for auth, upload, search, and playground mission flow
