# Secured String Matching using Symmetric Searchable Encryption (SSE)

A Python implementation of a client-server **Symmetric Searchable Encryption (SSE)** system using **AES** for data encryption and secure token generation via keyed hash functions (**HMAC-SHA256**) that supports **secure keyword search on encrypted PDF and TXT files**.

## Architecture

```
Client (key holder)                    Server (honest-but-curious)
┌──────────────────────┐               ┌──────────────────────┐
│  key_manager.py      │               │  database.py         │
│  encrypt.py          │  tokens/IDs   │  app.py              │
│  search.py       ◄──────────────────►│                      │
│  decrypt.py          │               │  SQLite DB           │
│                      │               │  storage/*.enc       │
│  client_keys.json    │               │  sse_security.log    │
└──────────────────────┘               └──────────────────────┘
```

**Threat model**: The server faithfully executes the protocol but may attempt to learn information from the encrypted data and query tokens it stores. All cryptographic keys remain exclusively on the client.

## Features

| Feature | Description |
|---|---|
| AES-256-GCM | Authenticated encryption for files with random IV |
| HMAC-SHA256 tokens | Deterministic search tokens without exposing keywords |
| HKDF key derivation | Three independent sub-keys from one master key |
| Forward privacy | Counter-based token randomization prevents old tokens matching new uploads |
| Multi-keyword search | AND (intersection) and OR (union) modes |
| Result-size padding | Dummy file IDs reduce frequency leakage |
| Security logging | Timestamps only — no plaintext keywords logged |

## Project Structure

```
project/
├── client/
│   ├── __init__.py
│   ├── key_manager.py     # Key generation & HKDF derivation
│   ├── encrypt.py         # AES-GCM encryption & index construction
│   ├── search.py          # Search token generation & result filtering
│   └── decrypt.py         # AES-GCM decryption & tag verification
├── server/
│   ├── __init__.py
│   ├── database.py        # SQLite schema & CRUD operations
│   └── app.py             # Upload / Search / Delete logic
├── storage/               # Encrypted .enc files (created at runtime)
├── main.py                # Interactive CLI entry point
├── test_sse.py            # Automated end-to-end test
├── requirements.txt
└── README.md
```

## Setup & Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd BlindBit

# 2. Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download NLTK stopwords (done automatically on first run)
python -c "import nltk; nltk.download('stopwords')"
```

## Usage

### Interactive CLI

```bash
python main.py
```

Menu options:
1. **Upload file** — provide a path to a PDF or TXT file
2. **Search keywords** — enter keywords and choose AND/OR mode
3. **Delete file** — remove an uploaded file and its index
4. **List files** — view all uploaded files
5. **Performance report** — see encryption, indexing, and search timings
6. **Exit**

### Automated Test

```bash
python test_sse.py
```

Runs a full lifecycle test: key generation → upload → search → decrypt → delete.

## Hackathon Runbook

### 1) Security/Quality checks

```powershell
python manage.py check
python manage.py test accounts drive
```

### 2) KPI benchmarking

```powershell
python benchmarks/benchmark_sse.py --sizes 1000 10000 100000 --queries 200 --out benchmarks/benchmark_report.json
```

### 3) One-command quick run (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_hackathon_check.ps1
```

### 4) Submission artifacts

- `PRD.md`
- `docs/THREAT_MODEL.md`
- `docs/SEQUENCE_DIAGRAMS.md`
- `docs/HACKATHON_CHECKLIST.md`
- `benchmarks/benchmark_report.json`

## Cryptographic Design

### Key Hierarchy

```
master_key  (256-bit, os.urandom)
    │
    ├── HKDF("sse-file-encryption-key")  ──►  file_encryption_key   (AES-256-GCM)
    ├── HKDF("sse-hmac-key")             ──►  hmac_key              (HMAC-SHA256 tokens)
    └── HKDF("sse-token-randomization")  ──►  token_randomization_key (forward privacy)
```

### Encrypted Index

```
base_token        = HMAC-SHA256(hmac_key, keyword)
randomized_token  = HMAC-SHA256(token_rand_key, base_token || counter)
```

The counter increments on each file upload, so the same keyword produces different tokens at different counter values. During search, the client generates tokens for **all** counter values to cover every uploaded file.

### File Encryption

```
Ciphertext layout:  IV (12 bytes) || Auth Tag (16 bytes) || Ciphertext
```

## Security Analysis

### Protections

| Threat | Mitigation |
|---|---|
| Server reads file content | AES-256-GCM encryption; key never leaves client |
| Server learns search keywords | Only HMAC tokens transmitted; pre-image resistance |
| Ciphertext tampering | GCM authentication tag verified on decryption |
| Key compromise from one sub-key | HKDF domain separation ensures sub-key independence |
| Result-size leakage | Padding with dummy IDs up to minimum K |
| Old tokens match new files | Counter-based forward privacy |

### Known Limitations

1. **Access-pattern leakage**: The server learns *which* encrypted tokens are queried and which file IDs are returned. This is inherent to SSE schemes.
2. **Volume leakage**: The size of encrypted files reveals approximate plaintext size.
3. **Query frequency**: Repeated identical searches produce the same tokens. A frequency analysis could correlate queries over time.
4. **Single-client model**: This prototype does not support multi-user access control.
5. **Counter scalability**: Search time grows linearly with the counter value because the client must generate tokens for all counter values.

### Future Improvements

- Implement **backward privacy** (hide from server that a deleted file matched a query).
- Use **oblivious RAM (ORAM)** to hide access patterns.
- Add **TLS transport** for client-server communication.
- Support **multi-user** scenarios with proxy re-encryption.
- Integrate a **proper key store** (e.g., hardware security module).
- Optimize search with **Bloom filters** or **tree-based** index structures.

## Dependencies

| Package | Purpose |
|---|---|
| `pdfminer.six` | PDF text extraction |
| `cryptography` | AES-GCM, HKDF, HMAC |
| `nltk` | English stopword removal |

## License

MIT License
