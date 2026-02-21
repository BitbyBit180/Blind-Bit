"""
Django settings for BlindBit SSE Web Application.
Security-hardened configuration.
"""
import os
from pathlib import Path
from decouple import config, Csv

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Core Security ---
SECRET_KEY = config('DJANGO_SECRET_KEY', default='dev-only-insecure-secret-key')
DEBUG = config('DJANGO_DEBUG', default=True, cast=bool)
ALLOWED_HOSTS = config('DJANGO_ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'accounts',
    'drive',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'blindbit_web.security_headers.SecurityHeadersMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'blindbit_web.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'blindbit_web.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        # Use a single project-local SQLite DB by default; env can still override.
        'NAME': config(
            'DJANGO_DB_PATH',
            default=str(BASE_DIR / 'app.sqlite3'),
        ),
    }
}

# --- Password Validation (Strengthened) ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 10}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- Internationalization ---
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

# --- Static & Media ---
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Auth Redirects ---
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/accounts/post-auth/'
LOGOUT_REDIRECT_URL = '/accounts/login/'
SITE_ID = 1

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
)

ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_AUTHENTICATION_METHOD = 'username_email'
ACCOUNT_USERNAME_REQUIRED = True
ACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_LOGIN_ON_GET = True
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_ADAPTER = 'accounts.adapters.BlindBitSocialAccountAdapter'
SOCIALACCOUNT_PROVIDERS = {}

GOOGLE_OAUTH_AVAILABLE = False
GOOGLE_OAUTH_CONFIGURED = bool(config('GOOGLE_CLIENT_ID', default='').strip())
GOOGLE_OAUTH_ENABLED = False
try:
    import requests  # noqa: F401
    import jwt  # noqa: F401
except Exception:
    GOOGLE_OAUTH_AVAILABLE = False
else:
    INSTALLED_APPS.append('allauth.socialaccount.providers.google')
    GOOGLE_OAUTH_AVAILABLE = True
    GOOGLE_OAUTH_ENABLED = GOOGLE_OAUTH_CONFIGURED
    SOCIALACCOUNT_PROVIDERS['google'] = {
        'APP': {
            'client_id': config('GOOGLE_CLIENT_ID', default=''),
            'secret': config('GOOGLE_CLIENT_SECRET', default=''),
            'key': '',
        },
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
    }

# --- SSE storage directory ---
SSE_STORAGE_DIR = BASE_DIR / 'storage'

# --- Session Security ---
SESSION_COOKIE_HTTPONLY = True          # Prevent JS access to session cookie
SESSION_COOKIE_SAMESITE = 'Lax'        # CSRF protection
SESSION_COOKIE_AGE = 3600              # 1 hour session expiry
SESSION_SAVE_EVERY_REQUEST = True      # Rolling expiry on activity

# --- CSRF Security ---
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'

# --- Security Headers ---
SECURE_CONTENT_TYPE_NOSNIFF = True     # Prevent MIME-type sniffing
X_FRAME_OPTIONS = 'DENY'              # Prevent clickjacking
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = 'same-origin'

# --- Search Privacy Controls ---
SEARCH_OBFUSCATION_DECOYS = config('SEARCH_OBFUSCATION_DECOYS', default=2, cast=int)
SEARCH_OBFUSCATION_ENABLED = config('SEARCH_OBFUSCATION_ENABLED', default=True, cast=bool)

# --- Caches (used by auth lockout counters) ---
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'blindbit-security-cache',
    }
}

# --- File Upload Limits ---
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10 MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10 MB

# --- Production-only settings (enabled when DEBUG=False) ---
if not DEBUG:
    SESSION_COOKIE_SECURE = True       # HTTPS-only session cookie
    CSRF_COOKIE_SECURE = True          # HTTPS-only CSRF cookie
    SECURE_SSL_REDIRECT = True         # Force HTTPS
    SECURE_HSTS_SECONDS = 31536000     # 1 year HSTS
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_BROWSER_XSS_FILTER = True
