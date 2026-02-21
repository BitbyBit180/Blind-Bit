"""
Audit Module — File Integrity & Tamper Detection
=================================================

Client-side integrity verification:
  • Computes SHA-256 hash of each .enc file at upload time
  • Stores hashes in a local manifest (JSON)
  • verify_all() re-hashes and flags tampered files
"""

import os
import json
import hashlib

MANIFEST_PATH = "integrity_manifest.json"


def _load_manifest() -> dict:
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, "r") as f:
            return json.load(f)
    return {}


def _save_manifest(manifest: dict) -> None:
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)


def hash_file(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def register_file(file_id: str, enc_filepath: str, filename: str) -> None:
    """Record the hash of a newly encrypted file."""
    manifest = _load_manifest()
    manifest[file_id] = {
        "filename": filename,
        "enc_path": enc_filepath,
        "hash": hash_file(enc_filepath),
    }
    _save_manifest(manifest)


def remove_file(file_id: str) -> None:
    """Remove a file from the manifest."""
    manifest = _load_manifest()
    manifest.pop(file_id, None)
    _save_manifest(manifest)


def verify_all(storage_dir: str = "storage") -> list:
    """Verify integrity of all registered encrypted files.

    Returns list of dicts:
        {file_id, filename, status: "intact"|"tampered"|"missing"}
    """
    manifest = _load_manifest()
    results = []
    for file_id, info in manifest.items():
        enc_path = info["enc_path"]
        if not os.path.exists(enc_path):
            results.append({
                "file_id": file_id,
                "filename": info["filename"],
                "status": "missing",
            })
        else:
            current_hash = hash_file(enc_path)
            status = "intact" if current_hash == info["hash"] else "tampered"
            results.append({
                "file_id": file_id,
                "filename": info["filename"],
                "status": status,
            })
    return results
