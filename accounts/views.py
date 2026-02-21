"""
Accounts views - registration, login, Google post-auth handling, 2FA, data unlock,
and password change (with DEK re-wrapping so encrypted data is never lost).
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


def _unlock_vault_with_passphrase(request, profile, passphrase: str) -> bool:
    """Verify passphrase, derive master key, and store DEK in session.

    Flow:
      1. Verify the data passphrase (fallback: Django password).
      2. Derive master_key = KDF(passphrase + TOTP_secret + salt).
      3a. If user already has a DEK  → unwrap it.
      3b. If not (legacy account)    → generate & wrap a fresh DEK (one-time bootstrap).
      4. Store DEK in session['_dek'] — master key is discarded immediately.

    Returns True on success, False if the passphrase is wrong.
    """
    if not profile.verify_data_passphrase(passphrase):
        return False

    profile.bootstrap_data_passphrase_from_password(passphrase)
    secret = profile.get_totp_secret()
    if not secret:
        secret = profile.generate_totp_secret()

    salt_bytes = bytes.fromhex(profile.salt)
    master_key = derive_master_key(passphrase, secret, salt_bytes)

    try:
        if profile.has_dek():
            dek = profile.unwrap_dek(master_key)
        else:
            # Legacy account: generate DEK for the first time, transparently.
            dek = profile.generate_and_wrap_dek(master_key)
    finally:
        # Wipe the master key from local scope — it must not linger in memory.
        del master_key

    request.session['_dek'] = base64.b64encode(dek).decode()
    return True


# Keep an alias so any third-party code referencing the old name still works.
_set_master_key_from_passphrase = _unlock_vault_with_passphrase


def _auto_unlock_for_social(request, user, profile) -> bool:
    """Auto-bootstrap and unlock vault for social-only accounts."""
    if user.has_usable_password():
        return False

    synthetic_passphrase = f"social::{user.id}::{user.password}"
    if not profile.is_data_passphrase_set:
        profile.set_data_passphrase(synthetic_passphrase)
    return _unlock_vault_with_passphrase(request, profile, synthetic_passphrase)


def _auth_redirect_target(profile, has_dek: bool, used_recovery_code: bool = False):
    if used_recovery_code:
        return 'setup_2fa'
    if not profile.is_2fa_enabled:
        return 'setup_2fa'
    if has_dek:
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
        has_dek = _unlock_vault_with_passphrase(request, profile, password)
        request.session['_2fa_verified'] = profile.is_2fa_enabled
        request.session['is_2fa_verified'] = profile.is_2fa_enabled

        response = redirect(_auth_redirect_target(profile, has_dek))

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

    if not request.session.get('_dek'):
        if _auto_unlock_for_social(request, request.user, profile):
            pass
        else:
            return redirect('unlock_data')

    return redirect('dashboard')


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

        has_dek = False
        if pre_password:
            has_dek = _unlock_vault_with_passphrase(request, profile, pre_password)
        elif _auto_unlock_for_social(request, user, profile):
            has_dek = True
        request.session.pop('pre_2fa_password', None)

        response = redirect(_auth_redirect_target(profile, has_dek, used_recovery_code))

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

    if request.session.get('_dek'):
        return redirect('setup_2fa' if not profile.is_2fa_enabled else 'dashboard')

    if request.method == 'POST':
        passphrase = request.POST.get('data_passphrase', '')
        if _unlock_vault_with_passphrase(request, profile, passphrase):
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


@login_required
@require_POST
def change_password_view(request):
    """Change the user's password while keeping encrypted data accessible.

    The DEK is re-wrapped with the new master key but is NEVER regenerated,
    so all files encrypted with the DEK remain decryptable after the change.
    """
    profile = UserProfile.objects.get_or_create(user=request.user)[0]

    # Must have a live DEK in session (i.e. vault is unlocked)
    dek_b64 = request.session.get('_dek')
    if not dek_b64:
        messages.error(request, 'Your vault is locked. Please unlock it before changing your password.')
        return redirect('unlock_data')

    current_password = request.POST.get('current_password', '')
    new_password = request.POST.get('new_password', '')
    new_password2 = request.POST.get('new_password2', '')

    if not current_password or not new_password:
        messages.error(request, 'Current and new password are required.')
        return redirect('dashboard')
    if new_password != new_password2:
        messages.error(request, 'New passwords do not match.')
        return redirect('dashboard')
    if len(new_password) < 10:
        messages.error(request, 'New password must be at least 10 characters.')
        return redirect('dashboard')
    if not request.user.check_password(current_password):
        messages.error(request, 'Current password is incorrect.')
        return redirect('dashboard')

    # Derive current and new master keys
    totp_secret = profile.get_totp_secret()
    salt_bytes = bytes.fromhex(profile.salt)
    old_master_key = derive_master_key(current_password, totp_secret, salt_bytes)
    new_master_key = derive_master_key(new_password, totp_secret, salt_bytes)

    try:
        if profile.has_dek():
            # Re-wrap the SAME DEK — do NOT regenerate it.
            profile.rewrap_dek(old_master_key, new_master_key)
        else:
            # Edge case: no DEK yet (very old account that somehow reached here).
            # Generate one now; the session DEK takes precedence anyway.
            dek = base64.b64decode(dek_b64)
            from drive.sse_bridge import wrap_dek_with_master_key
            iv, ciphertext, auth_tag = wrap_dek_with_master_key(new_master_key, dek)
            profile.encrypted_dek = ciphertext
            profile.dek_iv = iv
            profile.dek_auth_tag = auth_tag
            profile.save(update_fields=['encrypted_dek', 'dek_iv', 'dek_auth_tag'])
    except ValueError as exc:
        messages.error(request, f'Password change failed: {exc}')
        return redirect('dashboard')
    finally:
        del old_master_key, new_master_key

    # Update the Django auth password and keep the session alive.
    request.user.set_password(new_password)
    request.user.save()

    # Update data-passphrase hash to match the new password.
    profile.set_data_passphrase(new_password)

    # Re-authenticate the session so Django doesn't log the user out.
    from django.contrib.auth import update_session_auth_hash
    update_session_auth_hash(request, request.user)

    # DEK in session is unchanged (DEK itself never changed), so no session update needed.
    messages.success(request, 'Password changed successfully. Your encrypted data is untouched.')
    return redirect('dashboard')
