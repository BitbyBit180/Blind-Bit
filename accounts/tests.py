import pyotp
from unittest.mock import Mock
from django.contrib.auth.models import User
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.test import TestCase, RequestFactory
from django.urls import reverse
from accounts.adapters import BlindBitSocialAccountAdapter
from accounts.models import UserProfile


class AccountPolicyTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_register_rejects_password_shorter_than_10(self):
        response = self.client.post(
            reverse('register'),
            data={
                'username': 'bob',
                'email': 'bob@example.com',
                'password': 'short123',
                'password2': 'short123',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='bob').exists())
        self.assertContains(response, 'at least 10 characters')

    def test_login_locks_after_repeated_password_failures(self):
        User.objects.create_user(username='eve', password='StrongPassword123')
        url = reverse('login')
        for _ in range(5):
            self.client.post(url, data={'username': 'eve', 'password': 'wrong-pass'})

        response = self.client.post(url, data={'username': 'eve', 'password': 'StrongPassword123'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Too many login attempts')

    def test_security_headers_present(self):
        response = self.client.get(reverse('login'))
        self.assertIn('Content-Security-Policy', response.headers)
        self.assertIn('Permissions-Policy', response.headers)

    def _create_2fa_user(self, username='alice', password='StrongPassword123'):
        user = User.objects.create_user(username=username, password=password)
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=True)
        profile.generate_totp_secret()
        return user, profile

    def test_login_requires_otp_for_non_trusted_device(self):
        self._create_2fa_user()

        # Step 1: Login with password
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        # Should redirect to 2FA verification
        self.assertRedirects(response, reverse('verify_2fa'))

    def test_login_skips_otp_after_trusted_device_is_remembered(self):
        _, profile = self._create_2fa_user()
        code = pyotp.TOTP(profile.get_totp_secret()).now()

        # Step 1: First login, provide password
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response, reverse('verify_2fa'))

        # Step 2: Provide OTP and check 'remember_device'
        response2 = self.client.post(reverse('verify_2fa'), {
            'totp_code': code,
            'remember_device': 'on'
        })
        self.assertRedirects(response2, reverse('dashboard'))

        # Log out
        self.client.post(reverse('logout'))

        # Second login - should bypass 2FA due to trusted device cookie
        response3 = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        # Jumps straight to dashboard
        self.assertRedirects(response3, reverse('dashboard'))

    def test_login_requires_otp_on_new_device_even_if_old_device_was_remembered(self):
        _, profile = self._create_2fa_user()
        code = pyotp.TOTP(profile.get_totp_secret()).now()

        # Initial login from first device/user-agent and remember it.
        self.client.defaults['HTTP_USER_AGENT'] = 'Device-A-UA'
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response, reverse('verify_2fa'))
        response2 = self.client.post(reverse('verify_2fa'), {
            'totp_code': code,
            'remember_device': 'on'
        })
        self.assertRedirects(response2, reverse('dashboard'))
        self.client.post(reverse('logout'))

        # Simulate a new device/user-agent. Trusted cookie should not validate.
        self.client.defaults['HTTP_USER_AGENT'] = 'Device-B-UA'
        response3 = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response3, reverse('verify_2fa'))

    def test_remember_device_cookie_is_not_secure_over_http(self):
        _, profile = self._create_2fa_user()
        code = pyotp.TOTP(profile.get_totp_secret()).now()

        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response, reverse('verify_2fa'))

        response2 = self.client.post(reverse('verify_2fa'), {
            'totp_code': code,
            'remember_device': 'on'
        })
        self.assertRedirects(response2, reverse('dashboard'))
        cookie = response2.cookies.get('trusted_device_2fa')
        self.assertIsNotNone(cookie)
        self.assertEqual(cookie['secure'], '')

    def test_remember_device_cookie_is_secure_over_https(self):
        _, profile = self._create_2fa_user()
        code = pyotp.TOTP(profile.get_totp_secret()).now()

        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        }, secure=True)
        self.assertRedirects(response, reverse('verify_2fa'))

        response2 = self.client.post(reverse('verify_2fa'), {
            'totp_code': code,
            'remember_device': 'on'
        }, secure=True)
        self.assertRedirects(response2, reverse('dashboard'))
        cookie = response2.cookies.get('trusted_device_2fa')
        self.assertIsNotNone(cookie)
        self.assertTrue(cookie['secure'])

    def test_login_accepts_and_consumes_recovery_code(self):
        _, profile = self._create_2fa_user()
        recovery_codes = profile.generate_recovery_codes()

        # Step 1: Login with password
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response, reverse('verify_2fa'))

        # Step 2: Provide recovery code instead of TOTP
        response2 = self.client.post(reverse('verify_2fa'), {
            'recovery_code': recovery_codes[0]
        })
        # Recovery codes force a redirection to setup_2fa to re-enroll
        self.assertRedirects(response2, reverse('setup_2fa'))

        # Log out
        self.client.post(reverse('logout'))

        # Second login with same code should fail
        response3 = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response3, reverse('verify_2fa'))
        
        response4 = self.client.post(reverse('verify_2fa'), {
            'recovery_code': recovery_codes[0]
        })
        self.assertEqual(response4.status_code, 200)
        self.assertContains(response4, 'Invalid recovery code.')

    def test_setup_2fa_redirects_to_dashboard_after_verify(self):
        user = User.objects.create_user(username='sam', password='StrongPassword123')
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=False)
        profile.generate_totp_secret()
        self.client.force_login(user)

        verify = self.client.post(
            reverse('setup_2fa'),
            data={'totp_code': pyotp.TOTP(profile.get_totp_secret()).now()},
        )
        self.assertEqual(verify.status_code, 302)
        self.assertEqual(verify.url, reverse('dashboard'))

        # Recovery codes are still available on-demand after the redirect.
        page = self.client.get(reverse('recovery_codes'))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'Recovery Codes')

    def test_legacy_password_login_bootstraps_data_passphrase(self):
        user = User.objects.create_user(username='legacy', password='StrongPassword123')
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=False)
        profile.generate_totp_secret()

        response = self.client.post(reverse('login'), {
            'username': 'legacy',
            'password': 'StrongPassword123'
        })
        self.assertRedirects(response, reverse('setup_2fa'))
        profile.refresh_from_db()
        self.assertTrue(profile.is_data_passphrase_set)

    def test_unlock_data_requires_valid_passphrase(self):
        user = User.objects.create_user(username='vaultuser', password='StrongPassword123')
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=True)
        profile.generate_totp_secret()
        profile.set_data_passphrase('VaultPassphrase123')

        self.client.force_login(user)
        session = self.client.session
        session['is_2fa_verified'] = True
        session['_2fa_verified'] = True
        session.pop('_mk', None)
        session.save()

        page = self.client.get(reverse('unlock_data'))
        self.assertEqual(page.status_code, 200)

        bad = self.client.post(reverse('unlock_data'), {'data_passphrase': 'bad-pass'})
        self.assertEqual(bad.status_code, 200)
        self.assertContains(bad, 'Invalid data passphrase')

        good = self.client.post(reverse('unlock_data'), {'data_passphrase': 'VaultPassphrase123'})
        self.assertRedirects(good, reverse('dashboard'))

    def test_post_auth_redirects_to_unlock_for_social_linked_password_user(self):
        user = User.objects.create_user(
            username='google-linked',
            email='google-linked@example.com',
            password='StrongPassword123',
        )
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=False)
        profile.generate_totp_secret()

        self.client.force_login(user)
        session = self.client.session
        session.pop('_mk', None)
        session.pop('_vault_passphrase', None)
        session['_2fa_verified'] = True
        session['is_2fa_verified'] = True
        session.save()

        response = self.client.get(reverse('post_auth'))
        self.assertRedirects(response, reverse('unlock_data'))

    def test_verify_2fa_redirects_to_unlock_when_no_passphrase_available(self):
        user = User.objects.create_user(username='otp-user', password='StrongPassword123')
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=True)
        profile.generate_totp_secret()

        session = self.client.session
        session['pending_2fa_uid'] = user.id
        session.pop('pre_2fa_password', None)
        session.pop('_mk', None)
        session.save()

        response = self.client.post(reverse('verify_2fa'), {
            'totp_code': pyotp.TOTP(profile.get_totp_secret()).now(),
        })
        self.assertRedirects(response, reverse('unlock_data'))


class DEKTests(TestCase):
    """Tests for the DEK (Data Encryption Key) key-wrapping layer."""

    PASSWORD = 'StrongPassword123'
    NEW_PASSWORD = 'NewStrongPass456'

    def _register_user(self, username='dekuser'):
        """Helper: create a user and produce a profile with DEK (as register_view does)."""
        user = User.objects.create_user(username=username, password=self.PASSWORD)
        profile = UserProfile.objects.create(user=user)
        profile.generate_totp_secret()
        profile.set_data_passphrase(self.PASSWORD)
        # Simulate what _unlock_vault_with_passphrase does on first login
        from drive.sse_bridge import derive_master_key
        secret = profile.get_totp_secret()
        salt_bytes = bytes.fromhex(profile.salt)
        master_key = derive_master_key(self.PASSWORD, secret, salt_bytes)
        profile.generate_and_wrap_dek(master_key)
        del master_key
        return user, profile

    def test_dek_generated_on_registration(self):
        """DEK fields must be populated after generate_and_wrap_dek is called."""
        _, profile = self._register_user()
        profile.refresh_from_db()
        self.assertTrue(profile.has_dek())
        self.assertIsNotNone(profile.encrypted_dek)
        self.assertIsNotNone(profile.dek_iv)
        self.assertIsNotNone(profile.dek_auth_tag)

    def test_dek_survives_password_change_rewrap(self):
        """rewrap_dek must produce the SAME DEK under a new master key."""
        _, profile = self._register_user()
        from drive.sse_bridge import derive_master_key
        secret = profile.get_totp_secret()
        salt_bytes = bytes.fromhex(profile.salt)

        old_mk = derive_master_key(self.PASSWORD, secret, salt_bytes)
        original_dek = profile.unwrap_dek(old_mk)

        new_mk = derive_master_key(self.NEW_PASSWORD, secret, salt_bytes)
        profile.rewrap_dek(old_mk, new_mk)
        profile.refresh_from_db()

        rewrapped_dek = profile.unwrap_dek(new_mk)
        self.assertEqual(original_dek, rewrapped_dek,
                         "DEK must be identical before and after re-wrapping")

        del old_mk, new_mk

    def test_dek_bootstrap_for_legacy_user(self):
        """A user without a DEK must get one generated transparently on first vault unlock."""
        user = User.objects.create_user(username='legacydek', password=self.PASSWORD)
        profile = UserProfile.objects.create(user=user)
        profile.generate_totp_secret()
        profile.set_data_passphrase(self.PASSWORD)
        # Deliberately do NOT generate a DEK (simulates a pre-DEK legacy account)
        self.assertFalse(profile.has_dek())

        # Simulate a login call to _unlock_vault_with_passphrase
        self.client.force_login(user)
        response = self.client.post(reverse('unlock_data'), {
            'data_passphrase': self.PASSWORD,
        })
        # The view should succeed and redirect away from unlock_data
        self.assertNotEqual(response.status_code, 200)

        profile.refresh_from_db()
        self.assertTrue(profile.has_dek(),
                        "DEK must be bootstrapped for legacy accounts on first unlock")

    def test_rewrap_dek_rejects_wrong_old_master_key(self):
        """rewrap_dek must raise ValueError when the old master key is wrong."""
        _, profile = self._register_user()
        import os
        wrong_key = os.urandom(32)
        new_key = os.urandom(32)
        with self.assertRaises(ValueError):
            profile.rewrap_dek(wrong_key, new_key)

    def test_unwrap_dek_raises_when_no_dek_stored(self):
        """unwrap_dek must raise ValueError if no DEK has been generated yet."""
        user = User.objects.create_user(username='nodekuser', password=self.PASSWORD)
        profile = UserProfile.objects.create(user=user)
        import os
        with self.assertRaises(ValueError):
            profile.unwrap_dek(os.urandom(32))


class SocialAdapterTests(TestCase):
    def test_pre_social_login_links_existing_user_with_same_email(self):
        existing = User.objects.create_user(
            username='existing-user',
            email='existing@example.com',
            password='StrongPassword123',
        )
        request = RequestFactory().get('/accounts/google/login/callback/')
        request.user = AnonymousUser()

        sociallogin = Mock()
        sociallogin.is_existing = False
        sociallogin.user = Mock(email='existing@example.com')
        sociallogin.account = Mock(extra_data={'email': 'existing@example.com'})
        sociallogin.email_addresses = []
        sociallogin.connect = Mock()

        adapter = BlindBitSocialAccountAdapter()
        adapter.pre_social_login(request, sociallogin)

        sociallogin.connect.assert_called_once_with(request, existing)

