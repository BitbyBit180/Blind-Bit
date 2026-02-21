import pyotp
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse
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

        response = self.client.post(
            reverse('login'),
            data={'username': 'alice', 'password': 'StrongPassword123'},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Enter either a 2FA code or a recovery code.')

    def test_login_skips_otp_after_trusted_device_is_remembered(self):
        _, profile = self._create_2fa_user()
        code = pyotp.TOTP(profile.get_totp_secret()).now()

        first = self.client.post(
            reverse('login'),
            data={
                'username': 'alice',
                'password': 'StrongPassword123',
                'totp_code': code,
                'remember_device': 'on',
            },
        )
        self.assertEqual(first.status_code, 302)

        self.client.post(reverse('logout'))

        second = self.client.post(
            reverse('login'),
            data={'username': 'alice', 'password': 'StrongPassword123'},
        )
        self.assertEqual(second.status_code, 302)
        self.assertEqual(second.url, reverse('dashboard'))

    def test_login_accepts_and_consumes_recovery_code(self):
        _, profile = self._create_2fa_user()
        recovery_codes = profile.generate_recovery_codes()

        first = self.client.post(
            reverse('login'),
            data={
                'username': 'alice',
                'password': 'StrongPassword123',
                'recovery_code': recovery_codes[0],
            },
        )
        self.assertEqual(first.status_code, 302)
        self.assertEqual(first.url, reverse('setup_2fa'))

        self.client.post(reverse('logout'))

        second = self.client.post(
            reverse('login'),
            data={
                'username': 'alice',
                'password': 'StrongPassword123',
                'recovery_code': recovery_codes[0],
            },
        )
        self.assertEqual(second.status_code, 200)
        self.assertContains(second, 'Invalid recovery code.')

    def test_setup_2fa_shows_recovery_codes_after_verify(self):
        user = User.objects.create_user(username='sam', password='StrongPassword123')
        profile = UserProfile.objects.create(user=user, is_2fa_enabled=False)
        profile.generate_totp_secret()
        self.client.force_login(user)

        verify = self.client.post(
            reverse('setup_2fa'),
            data={'totp_code': pyotp.TOTP(profile.get_totp_secret()).now()},
        )
        self.assertEqual(verify.status_code, 302)
        self.assertEqual(verify.url, reverse('recovery_codes'))

        page = self.client.get(reverse('recovery_codes'))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'Save These Recovery Codes')
