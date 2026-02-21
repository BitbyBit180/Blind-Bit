"""
Accounts models — User profile with TOTP 2FA.
The TOTP secret is cryptographically tied to key derivation:
  master_key = HKDF(password_hash + totp_secret)
Without 2FA, data cannot be decrypted.
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


class UserProfile(models.Model):
    """Extended user profile with TOTP 2FA and encrypted key storage."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    salt = models.CharField(max_length=64, blank=True)
    totp_secret = models.TextField(blank=True, default='')
    is_2fa_enabled = models.BooleanField(default=False)
    recovery_code_hashes = models.TextField(blank=True, default='[]')


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
