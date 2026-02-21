from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Add encrypted DEK storage fields to UserProfile.

    encrypted_dek  — AES-GCM ciphertext of the random Data Encryption Key
    dek_iv         — 12-byte GCM IV used during wrap
    dek_auth_tag   — 16-byte GCM authentication tag

    All three are nullable: NULL means the user's DEK has not been generated
    yet (legacy account). A bootstrap path in accounts/views.py will
    transparently generate the DEK on the user's next successful login.
    """

    dependencies = [
        ('accounts', '0006_userprofile_data_passphrase_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='encrypted_dek',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='dek_iv',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='dek_auth_tag',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
