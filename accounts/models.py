"""
Accounts models — user profile, TOTP 2FA, data-passphrase unlock support,
and DEK (Data Encryption Key) management.
"""
import os
import base64
import json
import secrets
import pyotp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

from django.db import models
from django.contrib.auth.models import User

# Imported lazily inside methods to avoid circular-import issues at module load
# (drive.sse_bridge → client.* → no accounts dependency, so it is safe here).
from drive.sse_bridge import wrap_dek_with_master_key, unwrap_dek_with_master_key


class UserProfile(models.Model):
    """Extended user profile with TOTP 2FA, encrypted key storage, and DEK management."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    salt = models.CharField(max_length=64, blank=True)
    totp_secret = models.TextField(blank=True, default='')
    is_2fa_enabled = models.BooleanField(default=False)
    recovery_code_hashes = models.TextField(blank=True, default='[]')
    data_passphrase_hash = models.TextField(blank=True, default='')
    is_data_passphrase_set = models.BooleanField(default=False)

    # DEK (Data Encryption Key) — stored encrypted, never in plaintext.
    # master_key  = KDF(password + TOTP_secret + salt)
    # encrypted_dek = AES-GCM(master_key, DEK)
    # Files/records are encrypted with DEK, not master_key.
    # On password change: re-wrap SAME DEK with new master_key — no file re-encryption needed.
    encrypted_dek = models.BinaryField(null=True, blank=True)
    dek_iv = models.BinaryField(null=True, blank=True)
    dek_auth_tag = models.BinaryField(null=True, blank=True)


    def save(self, *args, **kwargs):
        if not self.salt:
            self.salt = os.urandom(32).hex()
        super().save(*args, **kwargs)

    @property
    def _fernet(self):
        """Derive a Fernet key from Django SECRET_KEY."""
        # Use a fixed salt for the system-wide key derivation to ensure stability
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'blindbit-system-salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))
        return Fernet(key)

    def set_totp_secret(self, secret: str):
        """Encrypt and store the TOTP secret."""
        if not secret:
            self.totp_secret = ''
        else:
            self.totp_secret = self._fernet.encrypt(secret.encode()).decode()
        self.save()

    def get_totp_secret(self) -> str:
        """Decrypt and return the TOTP secret."""
        if not self.totp_secret:
            return ''
        try:
            return self._fernet.decrypt(self.totp_secret.encode()).decode()
        except:
            return ''

    def generate_totp_secret(self):
        """Generate a new TOTP secret for the user."""
        secret = pyotp.random_base32()
        self.set_totp_secret(secret)
        return secret

    def get_totp_uri(self):
        """Get the provisioning URI for QR code generation."""
        secret = self.get_totp_secret()
        if not secret:
            return ''
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.user.email or self.user.username,
            issuer_name='BlindBit SSE'
        )

    def verify_totp(self, code: str) -> bool:
        """Verify a TOTP code."""
        secret = self.get_totp_secret()
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    def __str__(self):
        return f"{self.user.username} (2FA: {'ON' if self.is_2fa_enabled else 'OFF'})"

    # ------------------------------------------------------------------
    # DEK management
    # ------------------------------------------------------------------

    def has_dek(self) -> bool:
        """Return True when an encrypted DEK is stored for this user."""
        return bool(self.encrypted_dek)

    def generate_and_wrap_dek(self, master_key: bytes) -> bytes:
        """Generate a fresh 256-bit DEK, wrap it with *master_key*, persist, and return plaintext DEK.

        Call once at registration (or on first login for legacy accounts).
        The plaintext DEK is returned so the caller can put it in the session;
        it is NOT stored anywhere in the database.
        """
        dek = os.urandom(32)  # 256-bit random key
        iv, ciphertext, auth_tag = wrap_dek_with_master_key(master_key, dek)
        self.encrypted_dek = ciphertext
        self.dek_iv = iv
        self.dek_auth_tag = auth_tag
        self.save(update_fields=['encrypted_dek', 'dek_iv', 'dek_auth_tag'])
        return dek

    def unwrap_dek(self, master_key: bytes) -> bytes:
        """Decrypt and return the plaintext DEK using *master_key*.

        Raises ValueError if no DEK is stored or if the authentication tag
        does not match (wrong password / tampered data).
        """
        if not self.has_dek():
            raise ValueError("No DEK stored for this user profile.")
        iv = bytes(self.dek_iv)
        ciphertext = bytes(self.encrypted_dek)
        auth_tag = bytes(self.dek_auth_tag)
        return unwrap_dek_with_master_key(master_key, iv, ciphertext, auth_tag)

    def rewrap_dek(self, old_master_key: bytes, new_master_key: bytes) -> None:
        """Re-wrap the SAME DEK under a new master key (for password changes).

        The DEK itself is never regenerated — existing encrypted files remain
        decryptable with the exact same derived sub-keys.
        Raises ValueError if the old master key cannot unwrap the current DEK.
        """
        dek = self.unwrap_dek(old_master_key)  # authenticate + decrypt
        iv, ciphertext, auth_tag = wrap_dek_with_master_key(new_master_key, dek)
        self.encrypted_dek = ciphertext
        self.dek_iv = iv
        self.dek_auth_tag = auth_tag
        self.save(update_fields=['encrypted_dek', 'dek_iv', 'dek_auth_tag'])

    def set_data_passphrase(self, passphrase: str):
        normalized = (passphrase or '').strip()
        if not normalized:
            return
        self.data_passphrase_hash = make_password(normalized)
        self.is_data_passphrase_set = True
        self.save(update_fields=['data_passphrase_hash', 'is_data_passphrase_set'])

    def verify_data_passphrase(self, passphrase: str) -> bool:
        normalized = (passphrase or '').strip()
        if not normalized:
            return False

        # Backward-compatibility path for users created before data-passphrase rollout.
        if not self.is_data_passphrase_set or not self.data_passphrase_hash:
            return self.user.check_password(normalized)
        return check_password(normalized, self.data_passphrase_hash)

    def bootstrap_data_passphrase_from_password(self, password: str):
        if self.is_data_passphrase_set:
            return
        if password and self.user.check_password(password):
            self.set_data_passphrase(password)

    def _get_recovery_hashes(self):
        try:
            data = json.loads(self.recovery_code_hashes or '[]')
            if isinstance(data, list):
                return [str(x) for x in data]
        except Exception:
            pass
        return []

    def generate_recovery_codes(self, count: int = 10):
        """Generate one-time recovery codes, persist only hashes, return plaintext codes once."""
        codes = []
        hashes = []
        for _ in range(max(1, count)):
            code = secrets.token_hex(4).upper()
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
            hashes.append(make_password(formatted))
        self.recovery_code_hashes = json.dumps(hashes)
        self.save(update_fields=['recovery_code_hashes'])
        return codes

    def verify_and_consume_recovery_code(self, code: str) -> bool:
        normalized = (code or '').strip().upper()
        if not normalized:
            return False

        hashes = self._get_recovery_hashes()
        if not hashes:
            return False

        remaining = []
        matched = False
        for hashed in hashes:
            if (not matched) and check_password(normalized, hashed):
                matched = True
                continue
            remaining.append(hashed)

        if matched:
            self.recovery_code_hashes = json.dumps(remaining)
            self.save(update_fields=['recovery_code_hashes'])
        return matched
