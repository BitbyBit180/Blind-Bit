"""
Accounts views - registration, login, Google post-auth handling, 2FA, and data unlock.
"""
import io
import base64
import hashlib

import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core import signing
from django.core.cache import cache
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit

from drive.sse_bridge import derive_master_key
from .models import UserProfile

LOCKOUT_SECONDS = 15 * 60
MAX_PASSWORD_FAILS_USER = 5
MAX_PASSWORD_FAILS_IP = 20
MAX_OTP_FAILS_USER = 5
MAX_OTP_FAILS_IP = 20
TRUSTED_DEVICE_COOKIE = 'trusted_device_2fa'
TRUSTED_DEVICE_SALT = 'accounts.trusted_device_2fa'
TRUSTED_DEVICE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60


def _auth_context(**kwargs) -> dict:
    google_available = bool(getattr(settings, 'GOOGLE_OAUTH_AVAILABLE', False))
    google_enabled = bool(getattr(settings, 'GOOGLE_OAUTH_ENABLED', False))

    ctx = {
        'google_oauth_enabled': google_enabled,
        'google_oauth_available': google_available,
    }
    ctx.update(kwargs)
    return ctx


def google_signin_start_view(request):
    if not bool(getattr(settings, 'GOOGLE_OAUTH_AVAILABLE', False)):
        messages.warning(
            request,
            'Google sign-in is currently unavailable. Please continue with username and password.',
        )
        return redirect('login')
    return redirect('/accounts/google/login/')


def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '') or 'unknown'


def _counter_key(scope: str, key: str) -> str:
    return f"auth_fail:{scope}:{key}"


def _lock_key(scope: str, key: str) -> str:
    return f"auth_lock:{scope}:{key}"


def _is_locked(scope: str, key: str) -> bool:
    if not key:
        return False
    return bool(cache.get(_lock_key(scope, key)))


def _register_failure(scope: str, key: str, max_fails: int):
    if not key:
        return
    ckey = _counter_key(scope, key)
    attempts = cache.get(ckey, 0) + 1
    cache.set(ckey, attempts, timeout=LOCKOUT_SECONDS)
    if attempts >= max_fails:
        cache.set(_lock_key(scope, key), 1, timeout=LOCKOUT_SECONDS)


def _clear_failures(scope: str, key: str):
    if not key:
        return
    cache.delete(_counter_key(scope, key))
    cache.delete(_lock_key(scope, key))


def _trusted_device_fingerprint(user, profile, request) -> str:
    ua = (request.META.get('HTTP_USER_AGENT') or '')[:256]
    material = f"{user.id}:{user.password}:{profile.get_totp_secret()}:{ua}"
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def _has_valid_trusted_device(request, user, profile) -> bool:
    token = request.COOKIES.get(TRUSTED_DEVICE_COOKIE)
    if not token:
        return False
    try:
        payload = signing.loads(
            token,
            salt=TRUSTED_DEVICE_SALT,
            max_age=TRUSTED_DEVICE_MAX_AGE_SECONDS,
        )
    except (signing.BadSignature, signing.SignatureExpired):
        return False

    return (
        payload.get('uid') == user.id
        and payload.get('fp') == _trusted_device_fingerprint(user, profile, request)
    )


def _set_trusted_device_cookie(response, request, user, profile):
    payload = {
        'uid': user.id,
        'fp': _trusted_device_fingerprint(user, profile, request),
    }
    token = signing.dumps(payload, salt=TRUSTED_DEVICE_SALT)
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE,
        token,
        max_age=TRUSTED_DEVICE_MAX_AGE_SECONDS,
        httponly=True,
        secure=request.is_secure(),
        samesite='Lax',
        path='/',
    )


def _clear_trusted_device_cookie(response):
    response.delete_cookie(TRUSTED_DEVICE_COOKIE, path='/')


def _set_master_key_from_passphrase(request, profile, passphrase: str) -> bool:
    if not profile.verify_data_passphrase(passphrase):
        return False

    profile.bootstrap_data_passphrase_from_password(passphrase)
    secret = profile.get_totp_secret()
    if not secret:
        secret = profile.generate_totp_secret()

    salt_bytes = bytes.fromhex(profile.salt)
    mk = derive_master_key(passphrase, secret, salt_bytes)
    request.session['_mk'] = base64.b64encode(mk).decode()
    return True


def _auth_redirect_target(profile, has_master_key: bool, used_recovery_code: bool = False):
    if used_recovery_code:
        return 'setup_2fa'
    if not profile.is_2fa_enabled:
        return 'setup_2fa'
    if has_master_key:
        return 'dashboard'
    return 'unlock_data'


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')

        if not username or not password:
            messages.error(request, 'Username and password are required.')
            return render(request, 'accounts/register.html', _auth_context())
        if password != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'accounts/register.html', _auth_context())
        if len(password) < 10:
            messages.error(request, 'Password must be at least 10 characters.')
            return render(request, 'accounts/register.html', _auth_context())
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'accounts/register.html', _auth_context())

        user = User.objects.create_user(username=username, email=email, password=password)
        profile = UserProfile.objects.create(user=user)
        profile.generate_totp_secret()
        profile.set_data_passphrase(password)

        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        _set_master_key_from_passphrase(request, profile, password)
        request.session['_2fa_verified'] = False
        request.session['is_2fa_verified'] = False
        return redirect('setup_2fa')

    return render(request, 'accounts/register.html', _auth_context())


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        ip = _client_ip(request)
        user_key = username.lower().strip()

        if _is_locked('pwd_user', user_key) or _is_locked('pwd_ip', ip):
            messages.error(request, 'Too many login attempts. Try again in 15 minutes.')
            return render(request, 'accounts/login.html', _auth_context(username=username))

        user = authenticate(request, username=username, password=password)
        if user is None:
            _register_failure('pwd_user', user_key, MAX_PASSWORD_FAILS_USER)
            _register_failure('pwd_ip', ip, MAX_PASSWORD_FAILS_IP)
            messages.error(request, 'Invalid username or password.')
            return render(request, 'accounts/login.html', _auth_context(username=username))

        _clear_failures('pwd_user', user_key)
        _clear_failures('pwd_ip', ip)

        profile = UserProfile.objects.get_or_create(user=user)[0]
        requires_otp = profile.is_2fa_enabled and not _has_valid_trusted_device(request, user, profile)

        if requires_otp:
            request.session['pending_2fa_uid'] = user.id
            request.session['pre_2fa_password'] = password
            return redirect('verify_2fa')

        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        has_master_key = _set_master_key_from_passphrase(request, profile, password)
        request.session['_2fa_verified'] = profile.is_2fa_enabled
        request.session['is_2fa_verified'] = profile.is_2fa_enabled

        response = redirect(_auth_redirect_target(profile, has_master_key))

        if profile.is_2fa_enabled:
            _set_trusted_device_cookie(response, request, user, profile)
        else:
            _clear_trusted_device_cookie(response)

        return response

    return render(request, 'accounts/login.html', _auth_context())


@login_required
def post_auth_view(request):
    """Entry-point after social login; enforces 2FA and data unlock."""
    profile = UserProfile.objects.get_or_create(user=request.user)[0]

    if not profile.get_totp_secret():
        profile.generate_totp_secret()

    if profile.is_2fa_enabled:
        if _has_valid_trusted_device(request, request.user, profile):
            request.session['_2fa_verified'] = True
            request.session['is_2fa_verified'] = True
        elif not request.session.get('is_2fa_verified'):
            request.session['pending_2fa_uid'] = request.user.id
            request.session.pop('pre_2fa_password', None)
            return redirect('verify_2fa')
    else:
        request.session['_2fa_verified'] = False
        request.session['is_2fa_verified'] = False

    if not request.session.get('_mk'):
        return redirect('unlock_data')

    return redirect('setup_2fa' if not profile.is_2fa_enabled else 'dashboard')


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def verify_2fa_view(request):
    pending_uid = request.session.get('pending_2fa_uid')
    pre_password = request.session.get('pre_2fa_password')

    if not pending_uid:
        messages.error(request, 'Session expired. Please log in again.')
        return redirect('login')

    try:
        user = User.objects.get(id=pending_uid)
        profile = user.profile
    except User.DoesNotExist:
        messages.error(request, 'Invalid user session.')
        return redirect('login')

    if request.method == 'POST':
        totp_code = request.POST.get('totp_code', '')
        recovery_code = request.POST.get('recovery_code', '').strip().upper()
        remember_device = request.POST.get('remember_device') == 'on'
        ip = _client_ip(request)
        otp_user_key = str(user.id)
        used_recovery_code = False

        if _is_locked('otp_user', otp_user_key) or _is_locked('otp_ip', ip):
            messages.error(request, 'Too many 2FA attempts. Try again in 15 minutes.')
            return render(request, 'accounts/verify_2fa.html')

        if not totp_code and not recovery_code:
            _register_failure('otp_user', otp_user_key, MAX_OTP_FAILS_USER)
            _register_failure('otp_ip', ip, MAX_OTP_FAILS_IP)
            messages.error(request, 'Enter either a 2FA code or a recovery code.')
            return render(request, 'accounts/verify_2fa.html')

        if totp_code and not profile.verify_totp(totp_code):
            _register_failure('otp_user', otp_user_key, MAX_OTP_FAILS_USER)
            _register_failure('otp_ip', ip, MAX_OTP_FAILS_IP)
            messages.error(request, 'Invalid 2FA code.')
            return render(request, 'accounts/verify_2fa.html')

        if (not totp_code) and recovery_code:
            if not profile.verify_and_consume_recovery_code(recovery_code):
                _register_failure('otp_user', otp_user_key, MAX_OTP_FAILS_USER)
                _register_failure('otp_ip', ip, MAX_OTP_FAILS_IP)
                messages.error(request, 'Invalid recovery code.')
                return render(request, 'accounts/verify_2fa.html')
            used_recovery_code = True
            request.session['_needs_authenticator_reenroll'] = True
            messages.warning(
                request,
                'Recovery code accepted. Reconnect your authenticator app now.',
            )

        _clear_failures('otp_user', otp_user_key)
        _clear_failures('otp_ip', ip)

        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        request.session['_2fa_verified'] = True
        request.session['is_2fa_verified'] = True

        request.session.pop('pending_2fa_uid', None)

        has_master_key = False
        if pre_password:
            has_master_key = _set_master_key_from_passphrase(request, profile, pre_password)
        request.session.pop('pre_2fa_password', None)

        response = redirect(_auth_redirect_target(profile, has_master_key, used_recovery_code))

        if used_recovery_code:
            _clear_trusted_device_cookie(response)
        elif remember_device:
            _set_trusted_device_cookie(response, request, user, profile)
        else:
            _clear_trusted_device_cookie(response)

        return response

    return render(request, 'accounts/verify_2fa.html')


@login_required
def unlock_data_view(request):
    profile = UserProfile.objects.get_or_create(user=request.user)[0]

    if profile.is_2fa_enabled and not request.session.get('is_2fa_verified'):
        request.session['pending_2fa_uid'] = request.user.id
        return redirect('verify_2fa')

    if request.session.get('_mk'):
        return redirect('setup_2fa' if not profile.is_2fa_enabled else 'dashboard')

    if request.method == 'POST':
        passphrase = request.POST.get('data_passphrase', '')
        if _set_master_key_from_passphrase(request, profile, passphrase):
            messages.success(request, 'Data vault unlocked.')
            return redirect('setup_2fa' if not profile.is_2fa_enabled else 'dashboard')
        messages.error(request, 'Invalid data passphrase.')

    return render(request, 'accounts/unlock_data.html', {
        'is_2fa_enabled': profile.is_2fa_enabled,
    })


@login_required
def setup_2fa_view(request):
    profile = UserProfile.objects.get_or_create(user=request.user)[0]
    secret = profile.get_totp_secret()
    is_reenroll = bool(request.session.get('_needs_authenticator_reenroll'))

    if not secret:
        secret = profile.generate_totp_secret()

    if request.method == 'POST':
        if request.POST.get('regenerate_secret') == '1':
            profile.generate_totp_secret()
            request.session['_needs_authenticator_reenroll'] = True
            messages.info(request, 'Generated a new authenticator secret. Scan the new QR and verify.')
            return redirect('setup_2fa')

        code = request.POST.get('totp_code', '')
        ip = _client_ip(request)
        otp_user_key = str(request.user.id)
        if _is_locked('otp_setup_user', otp_user_key) or _is_locked('otp_setup_ip', ip):
            messages.error(request, 'Too many 2FA setup attempts. Try again in 15 minutes.')
            return redirect('setup_2fa')
        if profile.verify_totp(code):
            profile.is_2fa_enabled = True
            profile.save(update_fields=['is_2fa_enabled'])
            request.session['_2fa_verified'] = True
            request.session['is_2fa_verified'] = True
            request.session.pop('_needs_authenticator_reenroll', None)
            _clear_failures('otp_setup_user', otp_user_key)
            _clear_failures('otp_setup_ip', ip)
            codes = profile.generate_recovery_codes()
            request.session['_fresh_recovery_codes'] = codes
            messages.success(request, '2FA verified. Save your new recovery codes.')
            return redirect('recovery_codes')

        _register_failure('otp_setup_user', otp_user_key, MAX_OTP_FAILS_USER)
        _register_failure('otp_setup_ip', ip, MAX_OTP_FAILS_IP)
        messages.error(request, 'Invalid code. Try again.')

    uri = profile.get_totp_uri()
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'accounts/setup_2fa.html', {
        'qr_code': qr_b64,
        'secret': secret,
        'is_reenroll': is_reenroll,
    })


@login_required
def recovery_codes_view(request):
    codes = request.session.pop('_fresh_recovery_codes', None)
    if not codes:
        messages.info(request, 'No new recovery codes to display.')
        return redirect('dashboard')
    return render(request, 'accounts/recovery_codes.html', {'codes': codes})


@require_POST
def logout_view(request):
    logout(request)
    return redirect('login')
