"""
SSE Bridge — Connects Django views to the existing SSE engine.
Handles per-user key derivation (password + TOTP secret → master key)
and DEK wrap/unwrap operations (key-wrapping layer).
"""
import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from client.encrypt import (
    extract_text, preprocess, preprocess_ordered, encrypt_file,
    build_encrypted_index, generate_ngrams, generate_base_token,
    generate_randomized_token, MIN_NGRAM, compute_tf,
    update_document_frequencies, compute_tfidf,
)
from client.search import search as sse_search, generate_search_tokens
from client.decrypt import decrypt_file as sse_decrypt_file
from client.records import (
    encrypt_record, decrypt_record, build_record_index,
    flatten_json, extract_searchable_text, find_fuzzy_keywords,
)
from client.regex_engine import (
    regex_to_search_fragments, verify_regex_match,
    extract_literal_fragments, get_pattern_description,
)


def derive_master_key(password: str, totp_secret: str, salt: bytes) -> bytes:
    """Derive a 256-bit master key from password + TOTP secret + user salt.
    
    This cryptographically ties the 2FA to data access:
    - Password alone → can't derive key
    - TOTP secret alone → can't derive key
    - Both required for any data operation
    """
    combined = f"{password}:{totp_secret}".encode('utf-8')
    # salt is now passed in (per-user)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"blindbit-master-key",
    )
    return hkdf.derive(combined)


def derive_keys(master_key: bytes) -> dict:
    """Derive purpose-specific keys from master key (same as existing)."""
    def _derive(info: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(master_key)
    
    return {
        "file_encryption_key": _derive(b"file-enc"),
        "hmac_key": _derive(b"hmac"),
        "token_randomization_key": _derive(b"token-rand"),
    }


# ---------------------------------------------------------------------------
# DEK key-wrapping helpers
# ---------------------------------------------------------------------------

def wrap_dek_with_master_key(master_key: bytes, dek: bytes) -> tuple:
    """AES-GCM encrypt the DEK with the master key.

    Returns a 3-tuple: (iv: bytes, ciphertext: bytes, auth_tag: bytes).
    The IV is 12 random bytes, the auth tag is 16 bytes (GCM default).
    The master key MUST be exactly 32 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = os.urandom(12)
    aesgcm = AESGCM(master_key)
    # AESGCM.encrypt returns ciphertext || auth_tag
    ct_tag = aesgcm.encrypt(iv, dek, None)
    # Split ciphertext from the 16-byte GCM tag
    ciphertext = ct_tag[:-16]
    auth_tag = ct_tag[-16:]
    return iv, ciphertext, auth_tag


def unwrap_dek_with_master_key(master_key: bytes, iv: bytes,
                               ciphertext: bytes, auth_tag: bytes) -> bytes:
    """AES-GCM decrypt the DEK.

    Raises ValueError on authentication failure (wrong master key / tampered data).
    The master key MUST be exactly 32 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    aesgcm = AESGCM(master_key)
    try:
        # Re-combine ciphertext + auth_tag as expected by the library
        return aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    except (InvalidTag, Exception) as exc:
        raise ValueError("DEK unwrap failed: authentication error") from exc


def get_user_keys(password: str, totp_secret: str, salt: bytes) -> dict:
    """Full key derivation pipeline: password + TOTP → 3 purpose keys."""
    mk = derive_master_key(password, totp_secret, salt)
    return derive_keys(mk)


def encrypt_file_data(filepath: str, file_enc_key: bytes) -> tuple:
    """Encrypt a file and return (file_id, encrypted_bytes, encrypt_time)."""
    file_id, enc_path, enc_time = encrypt_file(filepath, file_enc_key)
    with open(enc_path, 'rb') as f:
        enc_data = f.read()
    # Clean up temp file
    try:
        os.remove(enc_path)
    except OSError:
        pass
    return file_id, enc_data, enc_time


def decrypt_file_data(enc_data: bytes, file_id: str, file_enc_key: bytes) -> bytes:
    """Decrypt file data from bytes."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    IV_LENGTH = 12
    TAG_LENGTH = 16
    
    # Client stores as: IV (12) || Tag (16) || Ciphertext (N)
    iv = enc_data[:IV_LENGTH]
    tag = enc_data[IV_LENGTH:IV_LENGTH+TAG_LENGTH]
    ciphertext = enc_data[IV_LENGTH+TAG_LENGTH:]
    
    # AESGCM.decrypt expects: Ciphertext || Tag
    combined_ct = ciphertext + tag
    
    aesgcm = AESGCM(file_enc_key)
    return aesgcm.decrypt(iv, combined_ct, None)


def build_index(keywords: list, file_id: str, hmac_key: bytes,
                token_randomization_key: bytes, counter: int,
                raw_text: str = "") -> tuple:
    """Build encrypted index entries for a file."""
    return build_encrypted_index(
        keywords, file_id, hmac_key, token_randomization_key,
        counter, raw_text=raw_text
    )


def generate_tokens_for_search(query: str, hmac_key: bytes,
                                token_randomization_key: bytes,
                                counter: int, search_mode: str = "exact") -> tuple:
    """Generate search tokens for a query."""
    return generate_search_tokens(
        query, hmac_key, token_randomization_key, counter, search_mode
    )


def visualize_encryption(text: str, hmac_key: bytes, token_randomization_key: bytes, file_enc_key: bytes) -> dict:
    """Generate detailed visualization data for the playground."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import hmac as hmac_mod
    
    # 1. Preprocessing
    keywords = preprocess(text)
    
    # 2. HMAC Tokenization (Step-by-step)
    hmac_tokens = []
    # Limit to first few unique keywords for clarity
    seen_kw = set()
    display_keywords = []
    for kw in keywords:
        if kw in seen_kw or len(seen_kw) >= 8: continue
        seen_kw.add(kw)
        display_keywords.append(kw)

    for kw in display_keywords:
        # Base token (deterministic)
        bt = generate_base_token(hmac_key, kw)
        # Randomized token (simulation for visualizer)
        rt = generate_randomized_token(token_randomization_key, bt, 1) # using counter=1 for demo
        
        hmac_tokens.append({
            "keyword": kw,
            "base_token_hex": bt.hex(),
            "randomization_proof": f"HMAC({bt.hex()[:8]}..., counter=1)",
            "final_token_hex": rt,
            "short_token": rt[:16] + "..."
        })
    
    # 3. N-grams (Sample)
    ngram_samples = []
    if display_keywords:
        sample_kw = display_keywords[0]
        ngs = sorted(list(generate_ngrams(sample_kw)))
        for ng in ngs[:5]: # just show a few
            bt = generate_base_token(hmac_key, f"__ng__{ng}")
            ngram_samples.append({
                "source": sample_kw,
                "ngram": ng,
                "token": bt.hex()[:16] + "..."
            })

    # 4. AES-GCM Encryption
    pt = text.encode('utf-8')
    iv = os.urandom(12)
    aesgcm = AESGCM(file_enc_key)
    ct_blob = aesgcm.encrypt(iv, pt, None)
    
    # Extract parts
    # AES-GCM (in cryptography lib) -> ct || tag
    # But wait, python cryptography's encrypt returns ct + tag? 
    # Yes. AESGCM.encrypt returns ciphertext + tag.
    # The IV is NOT included in the return value of .encrypt(), we must manage it.
    # In `encrypt_file` we typically write IV + CT + Tag.
    # Let's break it down for the user.
    
    tag_length = 16
    ciphertext_only = ct_blob[:-tag_length]
    auth_tag = ct_blob[-tag_length:]

    return {
        "summary": {
            "total_keywords": len(keywords),
            "unique_keywords": len(set(keywords)),
            "plaintext_size": len(pt),
            "ciphertext_size": len(ct_blob),
        },
        "keys": {
            "file_key_preview": file_enc_key.hex()[:8] + "...",
            "hmac_key_preview": hmac_key.hex()[:8] + "...",
        },
        "tokens": {
            "keywords": hmac_tokens,
            "ngrams": ngram_samples
        },
        "encryption": {
            "iv_hex": iv.hex(),
            "ciphertext_hex": ciphertext_only.hex(),
            "tag_hex": auth_tag.hex(),
            "full_blob_hex": iv.hex() + ciphertext_only.hex() + auth_tag.hex()
        }
    }
