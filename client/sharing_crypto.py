"""
Sharing Crypto — X25519 Key Wrapping for Secure File Sharing
=============================================================

Provides asymmetric key wrapping so a file owner can share
a per-file AES-256-GCM key with another user without revealing
the owner's master key or requiring server-side decryption.

Protocol (sealed-box pattern):
  1. Owner generates an ephemeral X25519 keypair.
  2. ECDH(ephemeral_private, recipient_public) → shared_secret.
  3. HKDF-SHA256(shared_secret, info="blindbit-file-share") → wrapping_key.
  4. AES-256-GCM(wrapping_key, file_key) → wrapped_key.
  5. Transmit: (wrapped_key, ephemeral_public, iv, tag) to server.

Recipient reverses:
  1. ECDH(recipient_private, ephemeral_public) → shared_secret.
  2. HKDF → wrapping_key.
  3. AES-GCM decrypt → file_key.
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_SHARE_HKDF_INFO = b"blindbit-file-share"
_OWNER_WRAP_HKDF_INFO = b"blindbit-owner-file-key"
_PRIVKEY_WRAP_HKDF_INFO = b"blindbit-privkey-wrap"
IV_LENGTH = 12
TAG_LENGTH = 16


# ---------------------------------------------------------------------------
# X25519 Keypair Generation
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> tuple:
    """Generate an X25519 key pair.

    Returns:
        (private_key_bytes, public_key_bytes) — each 32 bytes.
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()
    return priv_bytes, pub_bytes


# ---------------------------------------------------------------------------
# Private Key Encryption (stored on server, encrypted with master key)
# ---------------------------------------------------------------------------

def encrypt_private_key(private_key_bytes: bytes, master_key: bytes) -> tuple:
    """Encrypt an X25519 private key using AES-256-GCM keyed from master_key.

    Returns:
        (encrypted_private_key, iv, tag)
    """
    wrapping_key = _derive_wrapping_key(master_key, _PRIVKEY_WRAP_HKDF_INFO)
    iv = os.urandom(IV_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ct_with_tag = aesgcm.encrypt(iv, private_key_bytes, None)
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]
    return ciphertext, iv, tag


def decrypt_private_key(encrypted_priv: bytes, iv: bytes, tag: bytes,
                        master_key: bytes) -> bytes:
    """Decrypt an X25519 private key.

    Returns:
        private_key_bytes (32 bytes)
    """
    wrapping_key = _derive_wrapping_key(master_key, _PRIVKEY_WRAP_HKDF_INFO)
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(iv, encrypted_priv + tag, None)


# ---------------------------------------------------------------------------
# Per-File AES Key Generation & Owner Wrapping
# ---------------------------------------------------------------------------

def generate_file_key() -> bytes:
    """Generate a cryptographically secure random 256-bit AES key."""
    return os.urandom(32)


def encrypt_file_key_for_owner(file_key: bytes, master_key: bytes) -> tuple:
    """Wrap a per-file AES key for the owner using their master-derived key.

    Returns:
        (encrypted_file_key, iv, tag)
    """
    wrapping_key = _derive_wrapping_key(master_key, _OWNER_WRAP_HKDF_INFO)
    iv = os.urandom(IV_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ct_with_tag = aesgcm.encrypt(iv, file_key, None)
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]
    return ciphertext, iv, tag


def decrypt_file_key_for_owner(encrypted_key: bytes, iv: bytes, tag: bytes,
                               master_key: bytes) -> bytes:
    """Unwrap the per-file AES key for the owner.

    Returns:
        file_key (32 bytes)
    """
    wrapping_key = _derive_wrapping_key(master_key, _OWNER_WRAP_HKDF_INFO)
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(iv, encrypted_key + tag, None)


# ---------------------------------------------------------------------------
# Asymmetric Key Wrapping (for sharing)
# ---------------------------------------------------------------------------

def wrap_file_key(file_key: bytes, recipient_public_bytes: bytes) -> tuple:
    """Wrap a file AES key for a recipient using X25519 ECDH.

    Protocol:
      1. Generate ephemeral X25519 keypair.
      2. ECDH(ephemeral_private, recipient_public) → shared_secret.
      3. HKDF(shared_secret) → wrapping_key.
      4. AES-GCM(wrapping_key, file_key) → wrapped_key.

    Returns:
        (wrapped_key, ephemeral_public_bytes, iv, tag)
    """
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    recipient_public = X25519PublicKey.from_public_bytes(recipient_public_bytes)
    shared_secret = ephemeral_private.exchange(recipient_public)

    wrapping_key = _derive_wrapping_key(shared_secret, _SHARE_HKDF_INFO)

    iv = os.urandom(IV_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ct_with_tag = aesgcm.encrypt(iv, file_key, None)
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]

    return ciphertext, ephemeral_public.public_bytes_raw(), iv, tag


def unwrap_file_key(wrapped_key: bytes, ephemeral_public_bytes: bytes,
                    iv: bytes, tag: bytes,
                    recipient_private_bytes: bytes) -> bytes:
    """Unwrap a file AES key as the recipient.

    Returns:
        file_key (32 bytes)
    """
    recipient_private = X25519PrivateKey.from_private_bytes(recipient_private_bytes)
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)

    shared_secret = recipient_private.exchange(ephemeral_public)
    wrapping_key = _derive_wrapping_key(shared_secret, _SHARE_HKDF_INFO)

    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(iv, wrapped_key + tag, None)


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _derive_wrapping_key(key_material: bytes, info: bytes) -> bytes:
    """Derive a 256-bit wrapping key from key material using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(key_material)
