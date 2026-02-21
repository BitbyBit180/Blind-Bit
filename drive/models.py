"""
Drive models — Encrypted file/record storage via Django ORM.
"""
from django.db import models
from django.contrib.auth.models import User


class EncryptedFile(models.Model):
    """Stores encrypted file blobs with metadata."""
    file_id = models.CharField(max_length=64, unique=True, db_index=True)
    filename = models.CharField(max_length=255)
    encrypted_data = models.BinaryField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Per-file AES key wrapped with owner's master-derived key
    encrypted_file_key = models.BinaryField(blank=True, null=True)
    file_key_iv = models.BinaryField(blank=True, null=True)
    file_key_tag = models.BinaryField(blank=True, null=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.filename} ({self.file_id[:12]}...)"

    @property
    def has_per_file_key(self):
        return bool(self.encrypted_file_key)


class FileIndex(models.Model):
    """Encrypted search index for files — HMAC tokens."""
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='tokens')
    token = models.CharField(max_length=128, db_index=True)
    token_type = models.CharField(max_length=1, choices=[('K','Keyword'),('N','N-gram'),('B','Bigram')], default='K')
    score = models.FloatField(default=0.0)

    class Meta:
        indexes = [models.Index(fields=['token'])]


class EncryptedRecord(models.Model):
    """Stores encrypted structured data (JSON/text)."""
    record_id = models.CharField(max_length=64, unique=True, db_index=True)
    record_type = models.CharField(max_length=10, choices=[('json','JSON'),('text','Text')])
    encrypted_data = models.BinaryField()
    keywords_json = models.TextField(default='[]')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='records')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.record_type} record ({self.record_id[:12]}...)"


class RecordIndex(models.Model):
    """Encrypted search index for records."""
    record = models.ForeignKey(EncryptedRecord, on_delete=models.CASCADE, related_name='tokens')
    token = models.CharField(max_length=128, db_index=True)
    token_type = models.CharField(max_length=1, choices=[('K','Keyword'),('N','N-gram'),('B','Bigram')], default='K')
    score = models.FloatField(default=0.0)

    class Meta:
        indexes = [models.Index(fields=['token'])]


class SearchHistory(models.Model):
    """Track search analytics per user."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='searches')
    search_type = models.CharField(max_length=20)  # exact, substring, phrase, wildcard, fuzzy, regex
    logic_mode = models.CharField(max_length=3)  # AND, OR
    token_count = models.IntegerField(default=0)
    result_count = models.IntegerField(default=0)
    duration_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class FileShare(models.Model):
    """Tracks per-file sharing: stores the file AES key wrapped for the recipient."""
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='shares')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_files')
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_shares')
    wrapped_key = models.BinaryField()          # File AES key wrapped with recipient's X25519 public key
    ephemeral_public = models.BinaryField()     # Ephemeral X25519 public key used for wrapping
    wrapped_iv = models.BinaryField()           # IV used for the AES-GCM wrapping
    wrapped_tag = models.BinaryField()          # Auth tag from the AES-GCM wrapping
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('file', 'shared_with')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.owner.username} → {self.shared_with.username}: {self.file.filename}"

