"""
Server Application — Upload, Search, Delete & Analytics (Enhanced)
===================================================================

Enhanced search capabilities:
  • Exact keyword search (AND/OR) with TF-IDF ranked results
  • Substring search via n-gram tokens
  • Phrase search via bigram tokens
  • Wildcard search (prefix*, *suffix, *contains*)
  • Search analytics tracking
"""

import uuid
import logging
from datetime import datetime, timezone

from server import database as db

# ---------------------------------------------------------------------------
# Security-aware logger
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="sse_security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("sse_server")

DEFAULT_PAD_K = 5


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def upload(file_id: str, filename: str, token_file_pairs: list) -> None:
    """Register a new encrypted file and its index tokens."""
    timestamp = datetime.now(timezone.utc).isoformat()
    db.add_file(file_id, filename, timestamp)
    db.add_tokens(token_file_pairs)
    logger.info("UPLOAD | file_id=%s | tokens=%d | time=%s",
                file_id, len(token_file_pairs), timestamp)


# ---------------------------------------------------------------------------
# Search (enhanced with ranking and multiple modes)
# ---------------------------------------------------------------------------

def search(keyword_token_lists: list, mode: str = "AND") -> list:
    """Basic search returning file IDs (backward compatible)."""
    mode = mode.upper()
    if mode not in ("AND", "OR"):
        raise ValueError("Search mode must be 'AND' or 'OR'.")

    per_keyword_results = []
    for tokens_for_keyword in keyword_token_lists:
        file_ids = set(db.search_tokens(tokens_for_keyword))
        per_keyword_results.append(file_ids)

    if not per_keyword_results:
        result_set = set()
    elif mode == "AND":
        result_set = per_keyword_results[0]
        for s in per_keyword_results[1:]:
            result_set = result_set.intersection(s)
    else:
        result_set = set()
        for s in per_keyword_results:
            result_set = result_set.union(s)

    result_list = list(result_set)
    padded = pad_results(result_list)

    logger.info("SEARCH | mode=%s | real_results=%d | padded_total=%d",
                mode, len(result_list), len(padded))
    return padded


def search_ranked(keyword_token_lists: list, mode: str = "AND") -> list:
    """Enhanced search returning ranked results with TF-IDF scores.

    Returns list of {file_id, score, match_count} dicts, sorted by score.
    """
    mode = mode.upper()
    if mode not in ("AND", "OR"):
        raise ValueError("Search mode must be 'AND' or 'OR'.")

    # Flatten all tokens for a scored search
    all_tokens = []
    per_keyword_file_sets = []

    for tokens_for_keyword in keyword_token_lists:
        all_tokens.extend(tokens_for_keyword)
        file_ids = set(db.search_tokens(tokens_for_keyword))
        per_keyword_file_sets.append(file_ids)

    # Get scored results
    scored_results = db.search_tokens_with_scores(all_tokens)

    # Apply AND/OR filter
    if not per_keyword_file_sets:
        valid_file_ids = set()
    elif mode == "AND":
        valid_file_ids = per_keyword_file_sets[0]
        for s in per_keyword_file_sets[1:]:
            valid_file_ids = valid_file_ids.intersection(s)
    else:
        valid_file_ids = set()
        for s in per_keyword_file_sets:
            valid_file_ids = valid_file_ids.union(s)

    # Filter and sort by score
    ranked = [r for r in scored_results if r["file_id"] in valid_file_ids]
    ranked.sort(key=lambda r: (r["score"], r["match_count"]), reverse=True)

    logger.info("SEARCH_RANKED | mode=%s | results=%d", mode, len(ranked))
    return ranked


def record_search(mode: str, num_tokens: int, num_results: int,
                  duration_ms: float, search_type: str = "exact") -> None:
    """Record a search operation for analytics."""
    timestamp = datetime.now(timezone.utc).isoformat()
    db.add_search_record(timestamp, mode, num_tokens, num_results,
                         duration_ms, search_type)


# ---------------------------------------------------------------------------
# Result-size padding
# ---------------------------------------------------------------------------

def pad_results(file_ids: list, k: int = DEFAULT_PAD_K) -> list:
    padded = list(file_ids)
    while len(padded) < k:
        padded.append(f"dummy-{uuid.uuid4()}")
    return padded


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def delete(file_id: str) -> bool:
    success = db.delete_file(file_id)
    if success:
        logger.info("DELETE | file_id=%s | time=%s",
                     file_id, datetime.now(timezone.utc).isoformat())
    else:
        logger.warning("DELETE_FAILED | file_id=%s not found", file_id)
    return success


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def list_files() -> list:
    return db.list_files()


def get_counter() -> int:
    return db.get_counter()


def increment_counter() -> int:
    return db.increment_counter()


def get_index_stats() -> dict:
    return db.get_index_stats()


def get_search_history(limit: int = 50) -> list:
    return db.get_search_history(limit)


# ---------------------------------------------------------------------------
# Record operations (structured data)
# ---------------------------------------------------------------------------

def upload_record(record_id: str, record_type: str, encrypted_blob: bytes,
                  token_entries: list, keywords: list) -> None:
    """Store an encrypted record and its search index."""
    import json
    timestamp = datetime.now(timezone.utc).isoformat()
    db.add_record(record_id, record_type, encrypted_blob, timestamp,
                  json.dumps(keywords))
    db.add_record_tokens(token_entries)
    logger.info("RECORD_UPLOAD | record_id=%s | type=%s | tokens=%d",
                record_id, record_type, len(token_entries))


def search_records(token_lists: list, mode: str = "AND") -> list:
    """Search records using token lists. Returns record IDs."""
    mode = mode.upper()
    per_kw = []
    for tokens in token_lists:
        ids = set(db.search_record_tokens(tokens))
        per_kw.append(ids)

    if not per_kw:
        return []
    if mode == "AND":
        result = per_kw[0]
        for s in per_kw[1:]:
            result = result.intersection(s)
    else:
        result = set()
        for s in per_kw:
            result = result.union(s)
    return list(result)


def search_records_ranked(token_lists: list, mode: str = "AND") -> list:
    """Search records with TF-IDF ranking."""
    mode = mode.upper()
    all_tokens = []
    per_kw = []
    for tokens in token_lists:
        all_tokens.extend(tokens)
        ids = set(db.search_record_tokens(tokens))
        per_kw.append(ids)

    scored = db.search_record_tokens_scored(all_tokens)

    if not per_kw:
        valid = set()
    elif mode == "AND":
        valid = per_kw[0]
        for s in per_kw[1:]:
            valid = valid.intersection(s)
    else:
        valid = set()
        for s in per_kw:
            valid = valid.union(s)

    ranked = [r for r in scored if r["record_id"] in valid]
    ranked.sort(key=lambda r: (r["score"], r["match_count"]), reverse=True)
    return ranked


def delete_record(record_id: str) -> bool:
    success = db.delete_record(record_id)
    if success:
        logger.info("RECORD_DELETE | record_id=%s", record_id)
    return success


def list_records() -> list:
    try:
        return db.list_records()
    except Exception:
        return []


def get_record_blob(record_id: str) -> bytes:
    return db.get_record_blob(record_id)


def get_record_stats() -> dict:
    try:
        return {
            "total_records": db.get_record_count(),
            "total_tokens": db.get_record_token_count(),
        }
    except Exception:
        return {"total_records": 0, "total_tokens": 0}

