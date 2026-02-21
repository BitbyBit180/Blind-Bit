"""
Decrypt Module — Client-Side AES-256-GCM Decryption
=====================================================

Decryption uses the same file_encryption_key that was used during upload.
The .enc file layout is:
    [ IV (12 bytes) ][ Auth Tag (16 bytes) ][ Ciphertext ]

The authentication tag is verified by AES-GCM; if the ciphertext has been
tampered with, decryption will raise an InvalidTag exception.

Security notes:
  • Decryption happens exclusively on the client — the server never
    possesses the encryption key.
  • The IV is unique per file; reuse would compromise GCM security.
  • The authentication tag guarantees ciphertext integrity and authenticity.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IV_LENGTH = 12   # 96-bit IV
TAG_LENGTH = 16  # 128-bit authentication tag


def decrypt_file(file_id: str, file_encryption_key: bytes, storage_dir: str = "storage") -> bytes:
    """Decrypt an encrypted file and return the plaintext bytes.

    Args:
        file_id: UUID of the encrypted file.
        file_encryption_key: 256-bit AES key (must match the key used to encrypt).
        storage_dir: Directory containing .enc files.

    Returns:
        Plaintext bytes.

    Raises:
        FileNotFoundError: If the .enc file does not exist.
        cryptography.exceptions.InvalidTag: If the authentication tag
            verification fails (ciphertext was corrupted or tampered with).
    """
    enc_path = os.path.join(storage_dir, f"{file_id}.enc")
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    with open(enc_path, "rb") as fh:
        data = fh.read()

    # Parse layout: IV || Tag || Ciphertext
    iv = data[:IV_LENGTH]
    tag = data[IV_LENGTH : IV_LENGTH + TAG_LENGTH]
    ciphertext = data[IV_LENGTH + TAG_LENGTH :]

    # Reconstruct the format expected by the cryptography library:
    # ciphertext || tag
    ct_with_tag = ciphertext + tag

    aesgcm = AESGCM(file_encryption_key)
    plaintext = aesgcm.decrypt(iv, ct_with_tag, None)
    return plaintext
