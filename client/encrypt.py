"""
Encrypt Module — File Encryption & Encrypted Index Construction
================================================================

Enhanced features:
  • N-gram substring indexing — enables partial/substring string matching
  • TF-IDF relevance scoring — search results ranked by keyword importance
  • Phrase-aware indexing — ordered word pairs for phrase search
  • Standard keyword indexing with HMAC-SHA256 + forward privacy

Workflow:
  1. Extract text from PDF / TXT files.
  2. Preprocess: lowercase → remove punctuation → tokenize →
     remove English stopwords → deduplicate.
  3. Generate n-grams (character-level substrings) for substring search.
  4. Compute TF-IDF scores per keyword.
  5. Generate bigram tokens for phrase matching.
  6. Encrypt the original file with AES-256-GCM (random 12-byte IV).
  7. Build encrypted searchable index with all token types.
"""

import os
import re
import math
import time
import uuid
import hmac
import hashlib
import string

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

def extract_text_from_pdf(filepath: str) -> str:
    """Extract text from a PDF file using pdfminer.six."""
    from pdfminer.high_level import extract_text
    return extract_text(filepath)


def extract_text_from_txt(filepath: str) -> str:
    """Read plain text from a TXT file."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def extract_text(filepath: str) -> str:
    """Route to the correct extractor based on file extension."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".pdf":
        return extract_text_from_pdf(filepath)
    elif ext == ".txt":
        return extract_text_from_txt(filepath)
    else:
        raise ValueError(f"Unsupported file type: {ext}. Only PDF and TXT are accepted.")


# ---------------------------------------------------------------------------
# Text preprocessing
# ---------------------------------------------------------------------------

_STOPWORDS = {
    "i", "me", "my", "myself", "we", "our", "ours", "ourselves", "you",
    "your", "yours", "yourself", "yourselves", "he", "him", "his", "himself",
    "she", "her", "hers", "herself", "it", "its", "itself", "they", "them",
    "their", "theirs", "themselves", "what", "which", "who", "whom", "this",
    "that", "these", "those", "am", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "having", "do", "does", "did", "doing",
    "a", "an", "the", "and", "but", "if", "or", "because", "as", "until",
    "while", "of", "at", "by", "for", "with", "about", "against", "between",
    "through", "during", "before", "after", "above", "below", "to", "from",
    "up", "down", "in", "out", "on", "off", "over", "under", "again",
    "further", "then", "once", "here", "there", "when", "where", "why",
    "how", "all", "both", "each", "few", "more", "most", "other", "some",
    "such", "no", "nor", "not", "only", "own", "same", "so", "than", "too",
    "very", "s", "t", "can", "will", "just", "don", "should", "now", "d",
    "ll", "m", "o", "re", "ve", "y", "ain", "aren", "couldn", "didn",
    "doesn", "hadn", "hasn", "haven", "isn", "ma", "mightn", "mustn",
    "needn", "shan", "shouldn", "wasn", "weren", "won", "wouldn",
}


def _get_stopwords() -> set:
    return _STOPWORDS


def preprocess(text: str) -> list:
    """Lowercase, strip punctuation, tokenize, remove stopwords, deduplicate."""
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    tokens = text.split()
    stopwords = _get_stopwords()
    seen = set()
    unique_keywords = []
    for token in tokens:
        token = token.strip()
        if token and token not in stopwords and token not in seen:
            seen.add(token)
            unique_keywords.append(token)
    return unique_keywords


def preprocess_ordered(text: str) -> list:
    """Like preprocess but preserves order AND duplicates (for TF & bigrams)."""
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    tokens = text.split()
    stopwords = _get_stopwords()
    return [t.strip() for t in tokens if t.strip() and t.strip() not in stopwords]


# ---------------------------------------------------------------------------
# N-gram generation (substring matching)
# ---------------------------------------------------------------------------

MIN_NGRAM = 2  # minimum substring length to index


def generate_ngrams(word: str, min_n: int = MIN_NGRAM) -> set:
    """Generate character-level n-grams from a word for substring search.

    For word "encryption" with min_n=3:
        enc, ncr, cry, ryp, ypt, pti, tio, ion,   (3-grams)
        encr, ncry, cryp, rypt, ...                (4-grams)
        ... up to the full word.

    This allows searching for "crypt" to match "encryption".
    """
    ngrams = set()
    for n in range(min_n, len(word) + 1):
        for i in range(len(word) - n + 1):
            ngrams.add(word[i:i + n])
    return ngrams


# ---------------------------------------------------------------------------
# TF-IDF computation
# ---------------------------------------------------------------------------

# Global document frequency tracker (persisted in memory for the session)
_document_frequencies = {}  # keyword -> number of documents containing it
_total_documents = 0


def compute_tf(all_tokens: list) -> dict:
    """Compute term frequency for each keyword in a document.

    TF(t, d) = count(t in d) / total_tokens(d)
    """
    total = len(all_tokens) if all_tokens else 1
    tf = {}
    for token in all_tokens:
        tf[token] = tf.get(token, 0) + 1
    for token in tf:
        tf[token] = tf[token] / total
    return tf


def update_document_frequencies(unique_keywords: list) -> None:
    """Update global document frequency counts when a new file is uploaded."""
    global _total_documents
    _total_documents += 1
    for kw in unique_keywords:
        _document_frequencies[kw] = _document_frequencies.get(kw, 0) + 1


def compute_tfidf(tf_scores: dict) -> dict:
    """Compute TF-IDF for each keyword.

    IDF(t) = log(N / (1 + df(t)))  where N = total docs, df = doc frequency.
    TF-IDF = TF * IDF
    """
    tfidf = {}
    n = max(_total_documents, 1)
    for keyword, tf_val in tf_scores.items():
        df = _document_frequencies.get(keyword, 0)
        idf = math.log(1 + n / (1 + df))
        tfidf[keyword] = round(tf_val * idf, 6)
    return tfidf


# ---------------------------------------------------------------------------
# Bigram generation (phrase search)
# ---------------------------------------------------------------------------

def generate_bigrams(ordered_tokens: list) -> list:
    """Generate word-level bigrams for phrase/adjacency search.

    Input:  ["symmetric", "searchable", "encryption"]
    Output: ["symmetric|searchable", "searchable|encryption"]
    """
    bigrams = []
    for i in range(len(ordered_tokens) - 1):
        bigrams.append(f"{ordered_tokens[i]}|{ordered_tokens[i + 1]}")
    return bigrams


# ---------------------------------------------------------------------------
# AES-256-GCM file encryption
# ---------------------------------------------------------------------------
IV_LENGTH = 12
TAG_LENGTH = 16


def encrypt_file(filepath: str, file_encryption_key: bytes, storage_dir: str = "storage") -> tuple:
    """Encrypt a file with AES-256-GCM.

    Layout: [ IV (12B) ][ Auth Tag (16B) ][ Ciphertext ]
    Returns: (file_id, enc_filepath, encryption_time_seconds)
    """
    os.makedirs(storage_dir, exist_ok=True)

    with open(filepath, "rb") as fh:
        plaintext = fh.read()

    file_id = str(uuid.uuid4())
    iv = os.urandom(IV_LENGTH)

    start = time.perf_counter()
    aesgcm = AESGCM(file_encryption_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
    encryption_time = time.perf_counter() - start

    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]

    enc_filepath = os.path.join(storage_dir, f"{file_id}.enc")
    with open(enc_filepath, "wb") as fh:
        fh.write(iv)
        fh.write(tag)
        fh.write(ciphertext)

    return file_id, enc_filepath, encryption_time


# ---------------------------------------------------------------------------
# HMAC token generation
# ---------------------------------------------------------------------------

def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def generate_base_token(hmac_key: bytes, keyword: str) -> bytes:
    """base_token = HMAC-SHA256(hmac_key, keyword_bytes)"""
    return _hmac_sha256(hmac_key, keyword.encode("utf-8"))


def generate_randomized_token(token_randomization_key: bytes, base_token: bytes, counter: int) -> str:
    """randomized_token = HMAC-SHA256(rand_key, base_token || counter)"""
    message = base_token + counter.to_bytes(8, "big")
    return _hmac_sha256(token_randomization_key, message).hex()


# ---------------------------------------------------------------------------
# Encrypted searchable index construction (enhanced)
# ---------------------------------------------------------------------------

TOKEN_TYPE_KEYWORD = "K"   # exact keyword
TOKEN_TYPE_NGRAM   = "N"   # substring n-gram
TOKEN_TYPE_BIGRAM  = "B"   # phrase bigram


def build_encrypted_index(
    keywords: list,
    file_id: str,
    hmac_key: bytes,
    token_randomization_key: bytes,
    counter: int,
    raw_text: str = "",
) -> tuple:
    """Build a comprehensive encrypted search index for one file.

    Generates three types of tokens:
      • K-tokens: exact keyword matches (original behaviour)
      • N-tokens: n-gram substring tokens for partial matching
      • B-tokens: bigram tokens for phrase/adjacent-word search

    Also computes TF-IDF relevance scores.

    Returns:
        (list_of_(token_hex, file_id, token_type, score) tuples,
         index_creation_time, tfidf_scores_dict)
    """
    start = time.perf_counter()
    index_entries = []

    # --- Compute TF-IDF ---
    ordered_tokens = preprocess_ordered(raw_text) if raw_text else keywords
    tf_scores = compute_tf(ordered_tokens)
    update_document_frequencies(keywords)
    tfidf_scores = compute_tfidf(tf_scores)

    # --- K-tokens: exact keyword ---
    for keyword in keywords:
        base_token = generate_base_token(hmac_key, keyword)
        rand_token = generate_randomized_token(token_randomization_key, base_token, counter)
        score = tfidf_scores.get(keyword, 0.0)
        index_entries.append((rand_token, file_id, TOKEN_TYPE_KEYWORD, score))

    # --- N-tokens: character n-grams for substring search ---
    all_ngrams = set()
    for keyword in keywords:
        if len(keyword) >= MIN_NGRAM:
            for ng in generate_ngrams(keyword):
                all_ngrams.add(ng)

    for ngram in all_ngrams:
        base_token = generate_base_token(hmac_key, f"__ng__{ngram}")
        rand_token = generate_randomized_token(token_randomization_key, base_token, counter)
        index_entries.append((rand_token, file_id, TOKEN_TYPE_NGRAM, 0.0))

    # --- B-tokens: word bigrams for phrase search ---
    bigrams = generate_bigrams(ordered_tokens) if ordered_tokens else []
    unique_bigrams = list(set(bigrams))
    for bigram in unique_bigrams:
        base_token = generate_base_token(hmac_key, f"__bg__{bigram}")
        rand_token = generate_randomized_token(token_randomization_key, base_token, counter)
        index_entries.append((rand_token, file_id, TOKEN_TYPE_BIGRAM, 0.0))

    index_time = time.perf_counter() - start
    return index_entries, index_time, tfidf_scores
