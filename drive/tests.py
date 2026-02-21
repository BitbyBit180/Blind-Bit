import base64
import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.models import UserProfile
from .models import EncryptedFile, EncryptedRecord
from .views import parse_query


class DriveSecurityAndSearchTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='VeryStrongPass123')
        self.client.force_login(self.user)
        self.search_url = reverse('search_api')

    def _set_2fa_session(self):
        session = self.client.session
        session['_dek'] = base64.b64encode(b'test-master-key').decode()
        session['_2fa_verified'] = True
        session['is_2fa_verified'] = True
        session.save()

    def test_upload_page_allows_access_when_vault_locked(self):
        session = self.client.session
        session['_2fa_verified'] = True
        session['is_2fa_verified'] = True
        session.pop('_dek', None)
        session.save()

        response = self.client.get(reverse('upload_page'))
        self.assertEqual(response.status_code, 200)

    def test_upload_file_returns_session_key_error_when_vault_locked(self):
        session = self.client.session
        session['_2fa_verified'] = True
        session['is_2fa_verified'] = True
        session.pop('_dek', None)
        session.save()

        response = self.client.post(reverse('upload_file'))
        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertIn('Vault key is unavailable', payload['error'])

    def test_upload_file_recovers_dek_from_cached_passphrase(self):
        profile = UserProfile.objects.create(user=self.user, is_2fa_enabled=True)
        profile.generate_totp_secret()
        profile.set_data_passphrase('VeryStrongPass123')

        session = self.client.session
        session['_2fa_verified'] = True
        session['is_2fa_verified'] = True
        session['_vault_passphrase'] = 'VeryStrongPass123'
        session.pop('_dek', None)
        session.save()

        response = self.client.post(reverse('upload_file'))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'No file selected')

        session = self.client.session
        self.assertTrue(bool(session.get('_dek')))

    def test_upload_page_recovers_master_key_from_cached_passphrase(self):
        profile = UserProfile.objects.create(user=self.user, is_2fa_enabled=True)
        profile.generate_totp_secret()
        profile.set_data_passphrase('VeryStrongPass123')

        session = self.client.session
        session['_2fa_verified'] = True
        session['is_2fa_verified'] = True
        session['_vault_passphrase'] = 'VeryStrongPass123'
        session.pop('_mk', None)
        session.save()

        response = self.client.get(reverse('upload_page'))
        self.assertEqual(response.status_code, 200)

        session = self.client.session
        self.assertTrue(bool(session.get('_mk')))

    @patch('drive.views.derive_keys', return_value={
        'file_encryption_key': b'k' * 32,
        'hmac_key': b'h' * 32,
        'token_randomization_key': b't' * 32,
    })
    def test_search_api_rejects_invalid_logic(self, _derive_keys):
        self._set_2fa_session()
        response = self.client.post(
            self.search_url,
            data=json.dumps({'query': 'alpha', 'mode': 'exact', 'logic': 'XOR'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Invalid logic mode')

    @patch('drive.views.derive_keys', return_value={
        'file_encryption_key': b'k' * 32,
        'hmac_key': b'h' * 32,
        'token_randomization_key': b't' * 32,
    })
    def test_search_api_rejects_invalid_mode(self, _derive_keys):
        self._set_2fa_session()
        response = self.client.post(
            self.search_url,
            data=json.dumps({'query': 'alpha', 'mode': 'unknown', 'logic': 'AND'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Invalid search mode')

    @patch('drive.views.generate_tokens_for_search')
    @patch('drive.views.derive_keys', return_value={
        'file_encryption_key': b'k' * 32,
        'hmac_key': b'h' * 32,
        'token_randomization_key': b't' * 32,
    })
    def test_search_api_parses_plus_minus_terms(self, _derive_keys, mock_generate_tokens):
        self._set_2fa_session()
        mock_generate_tokens.side_effect = [
            ([['req-token']], 0.001),
            ([['opt-token']], 0.001),
            ([['neg-token']], 0.001),
        ]

        response = self.client.post(
            self.search_url,
            data=json.dumps({'query': '+alpha beta -gamma', 'mode': 'exact', 'logic': 'AND'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_generate_tokens.call_count, 3)
        self.assertEqual(mock_generate_tokens.call_args_list[0].args[0], 'alpha')
        self.assertEqual(mock_generate_tokens.call_args_list[1].args[0], 'beta')
        self.assertEqual(mock_generate_tokens.call_args_list[2].args[0], 'gamma')

    def test_parse_query_splits_required_optional_and_excluded_terms(self):
        required, optional, excluded = parse_query('+alpha beta -gamma +delta -omega')
        self.assertEqual(required, ['alpha', 'delta'])
        self.assertEqual(optional, ['beta'])
        self.assertEqual(excluded, ['gamma', 'omega'])

    def test_delete_file_requires_2fa_session(self):
        ef = EncryptedFile.objects.create(
            file_id='file-1',
            filename='note.txt',
            encrypted_data=b'abc',
            owner=self.user,
        )
        response = self.client.post(reverse('delete_file', kwargs={'file_id': ef.file_id}))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(EncryptedFile.objects.filter(file_id='file-1').exists())

    def test_delete_record_requires_2fa_session(self):
        rec = EncryptedRecord.objects.create(
            record_id='rec-1',
            record_type='text',
            encrypted_data=b'abc',
            keywords_json='[]',
            owner=self.user,
        )
        response = self.client.post(reverse('delete_record', kwargs={'record_id': rec.record_id}))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(EncryptedRecord.objects.filter(record_id='rec-1').exists())

    @patch('drive.views.derive_keys', return_value={
        'file_encryption_key': b'k' * 32,
        'hmac_key': b'h' * 32,
        'token_randomization_key': b't' * 32,
    })
    def test_delete_file_succeeds_with_2fa_session(self, _derive_keys):
        self._set_2fa_session()
        ef = EncryptedFile.objects.create(
            file_id='file-2',
            filename='note2.txt',
            encrypted_data=b'abc',
            owner=self.user,
        )
        response = self.client.post(reverse('delete_file', kwargs={'file_id': ef.file_id}))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(EncryptedFile.objects.filter(file_id='file-2').exists())
