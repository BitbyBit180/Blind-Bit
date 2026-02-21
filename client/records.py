"""
Records Module — Encrypted Structured Data Storage & Advanced String Search
============================================================================

Store JSON objects or plain text as encrypted records with full
searchable index coverage. Supports:
  • JSON records (flat or nested — all string values indexed)
  • Plain text records
  • Fuzzy matching via Levenshtein edit distance
  • All existing search modes: exact, substring, phrase, wildcard

Security: same SSE model — records are AES-256-GCM encrypted,
indexed with HMAC tokens. Server never sees plaintext.
"""

import os
import json
import time
import uuid
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client.encrypt import (
    preprocess, preprocess_ordered, generate_base_token,
    generate_randomized_token, generate_ngrams, generate_bigrams,
    compute_tf, update_document_frequencies, compute_tfidf,
    MIN_NGRAM, IV_LENGTH, TAG_LENGTH,
    TOKEN_TYPE_KEYWORD, TOKEN_TYPE_NGRAM, TOKEN_TYPE_BIGRAM,
)


# ---------------------------------------------------------------------------
# Fuzzy matching — Levenshtein distance
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def fuzzy_match(query: str, target: str, max_distance: int = 2) -> bool:
    """Check if query fuzzy-matches target within max_distance edits."""
    return levenshtein_distance(query.lower(), target.lower()) <= max_distance


def find_fuzzy_keywords(query_word: str, all_keywords: list,
                        max_distance: int = 2) -> list:
    """Find keywords that fuzzy-match the query word."""
    return [kw for kw in all_keywords if fuzzy_match(query_word, kw, max_distance)]


# ---------------------------------------------------------------------------
# JSON flattening — extract all searchable strings from nested JSON
# ---------------------------------------------------------------------------

def flatten_json(data, prefix="") -> dict:
    """Recursively flatten a JSON object into dot-notation key-value pairs.

    Input:  {"patient": {"name": "Alice", "age": 30}}
    Output: {"patient.name": "Alice", "patient.age": "30"}
    """
    items = {}
    if isinstance(data, dict):
        for k, v in data.items():
            new_key = f"{prefix}.{k}" if prefix else k
            items.update(flatten_json(v, new_key))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            new_key = f"{prefix}[{i}]"
            items.update(flatten_json(v, new_key))
    else:
        items[prefix] = str(data)
    return items


def extract_searchable_text(data) -> str:
    """Extract all searchable text from JSON or plain text."""
    if isinstance(data, dict):
        flat = flatten_json(data)
        return " ".join(flat.values())
    elif isinstance(data, list):
        flat = flatten_json({"root": data})
        return " ".join(flat.values())
    else:
        return str(data)


# ---------------------------------------------------------------------------
# Record encryption
# ---------------------------------------------------------------------------

def encrypt_record(data, file_encryption_key: bytes) -> tuple:
    """Encrypt a record (JSON or text) with AES-256-GCM.

    Returns (record_id, encrypted_bytes, encryption_time)
    """
    if isinstance(data, (dict, list)):
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        record_type = "json"
    else:
        plaintext = str(data).encode("utf-8")
        record_type = "text"

    record_id = str(uuid.uuid4())
    iv = os.urandom(IV_LENGTH)

    start = time.perf_counter()
    aesgcm = AESGCM(file_encryption_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
    enc_time = time.perf_counter() - start

    encrypted = iv + ct_with_tag[-TAG_LENGTH:] + ct_with_tag[:-TAG_LENGTH]

    return record_id, encrypted, record_type, enc_time


def decrypt_record(encrypted_bytes: bytes, file_encryption_key: bytes) -> str:
    """Decrypt a record from its encrypted bytes."""
    iv = encrypted_bytes[:IV_LENGTH]
    tag = encrypted_bytes[IV_LENGTH:IV_LENGTH + TAG_LENGTH]
    ciphertext = encrypted_bytes[IV_LENGTH + TAG_LENGTH:]

    aesgcm = AESGCM(file_encryption_key)
    plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Record index construction
# ---------------------------------------------------------------------------

def build_record_index(
    data,
    record_id: str,
    hmac_key: bytes,
    token_randomization_key: bytes,
    counter: int,
) -> tuple:
    """Build encrypted search index for a record.

    Indexes all string content with K, N, and B tokens.
    Returns (entries, index_time, tfidf_scores, keyword_list)
    """
    searchable_text = extract_searchable_text(data)
    keywords = preprocess(searchable_text)
    ordered = preprocess_ordered(searchable_text)

    if not keywords:
        return [], 0.0, {}, []

    start = time.perf_counter()
    entries = []

    # TF-IDF
    tf = compute_tf(ordered)
    update_document_frequencies(keywords)
    tfidf = compute_tfidf(tf)

    # K-tokens
    for kw in keywords:
        base = generate_base_token(hmac_key, kw)
        rand = generate_randomized_token(token_randomization_key, base, counter)
        score = tfidf.get(kw, 0.0)
        entries.append((rand, record_id, TOKEN_TYPE_KEYWORD, score))

    # N-tokens
    all_ngrams = set()
    for kw in keywords:
        if len(kw) >= MIN_NGRAM:
            for ng in generate_ngrams(kw):
                all_ngrams.add(ng)
    for ng in all_ngrams:
        base = generate_base_token(hmac_key, f"__ng__{ng}")
        rand = generate_randomized_token(token_randomization_key, base, counter)
        entries.append((rand, record_id, TOKEN_TYPE_NGRAM, 0.0))

    # B-tokens
    bigrams = list(set(generate_bigrams(ordered))) if len(ordered) >= 2 else []
    for bg in bigrams:
        base = generate_base_token(hmac_key, f"__bg__{bg}")
        rand = generate_randomized_token(token_randomization_key, base, counter)
        entries.append((rand, record_id, TOKEN_TYPE_BIGRAM, 0.0))

    idx_time = time.perf_counter() - start
    return entries, idx_time, tfidf, keywords
