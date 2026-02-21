from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_userprofile_recovery_code_hashes'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='data_passphrase_hash',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='is_data_passphrase_set',
            field=models.BooleanField(default=False),
        ),
    ]
