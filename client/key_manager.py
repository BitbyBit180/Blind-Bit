"""
Key Manager — Client-Side Cryptographic Key Management
=======================================================

Security design:
  • master_key: 256-bit random key generated via os.urandom (CSPRNG).
  • HKDF-SHA256 derives three independent sub-keys from the master_key,
    each bound to a unique purpose through the `info` parameter:
        1. file_encryption_key  — used for AES-256-GCM file encryption.
        2. hmac_key             — used for HMAC-SHA256 search token generation.
        3. token_randomization_key — used for forward-privacy token randomization.
  • Keys are NEVER sent to the server; they live exclusively on the client.
  • The keyfile is written locally and should be protected with OS-level
    file permissions in a production deployment.
"""

import os
import json
import base64

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MASTER_KEY_LENGTH = 32  # 256 bits
DERIVED_KEY_LENGTH = 32  # 256 bits per sub-key
DEFAULT_KEYFILE = "client_keys.json"

# Unique HKDF info strings — cryptographically bind each derived key to its role
_INFO_FILE_ENC = b"sse-file-encryption-key"
_INFO_HMAC = b"sse-hmac-key"
_INFO_TOKEN_RAND = b"sse-token-randomization-key"


# ---------------------------------------------------------------------------
# Key derivation helpers
# ---------------------------------------------------------------------------

def _derive_key(master_key: bytes, info: bytes) -> bytes:
    """Derive a 256-bit sub-key from the master key using HKDF-SHA256.

    HKDF (HMAC-based Key Derivation Function, RFC 5869) ensures that
    even if the master key has slightly non-uniform entropy, each
    derived key is computationally indistinguishable from random.
    The `info` parameter acts as a domain separator so that each
    derived key is independent.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=None,  # No salt — acceptable when master key is uniformly random
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(master_key)


def generate_master_key() -> bytes:
    """Generate a cryptographically secure 256-bit master key."""
    return os.urandom(MASTER_KEY_LENGTH)


def derive_keys(master_key: bytes) -> dict:
    """Derive all three sub-keys from the master key.

    Returns a dict with bytes values:
        - file_encryption_key
        - hmac_key
        - token_randomization_key
    """
    return {
        "file_encryption_key": _derive_key(master_key, _INFO_FILE_ENC),
        "hmac_key": _derive_key(master_key, _INFO_HMAC),
        "token_randomization_key": _derive_key(master_key, _INFO_TOKEN_RAND),
    }


# ---------------------------------------------------------------------------
# Persistence helpers (client-side only)
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    """Encode bytes as URL-safe Base64 string for JSON serialization."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    """Decode a URL-safe Base64 string back to bytes."""
    return base64.urlsafe_b64decode(text.encode("ascii"))


def save_keys(master_key: bytes, filepath: str = DEFAULT_KEYFILE) -> None:
    """Persist the master key to a local JSON file.

    Only the master key is stored — sub-keys are re-derived on load.
    In production this file should be encrypted at rest or stored in
    a hardware security module (HSM).
    """
    payload = {"master_key": _b64(master_key)}
    with open(filepath, "w") as fh:
        json.dump(payload, fh, indent=2)


def load_keys(filepath: str = DEFAULT_KEYFILE) -> tuple:
    """Load the master key and derive all sub-keys.

    Returns:
        (master_key: bytes, derived_keys: dict)
    """
    with open(filepath, "r") as fh:
        payload = json.load(fh)
    master_key = _unb64(payload["master_key"])
    return master_key, derive_keys(master_key)
