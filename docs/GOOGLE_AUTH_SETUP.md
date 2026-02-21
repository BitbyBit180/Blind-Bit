# Google Auth Setup (BlindBit)

This guide explains how to enable and test Google Sign-In for the current BlindBit implementation.

## 1. Prerequisites

- Python virtual environment for this project
- Google Cloud project with OAuth credentials
- Internet access for package installation

## 2. Install Required Packages

From project root:

```powershell
cd "D:\E drive\BlindBit\Blind-Bit"
.\venv\Scripts\activate
python -m pip install -r requirements.txt
```

If needed, install directly:

```powershell
python -m pip install django-allauth requests
```

## 3. Run Migrations

```powershell
python manage.py migrate
```

## 4. Configure Google OAuth in Google Cloud

1. Open Google Cloud Console.
2. Go to `APIs & Services` -> `Credentials`.
3. Create `OAuth client ID` (type: `Web application`).
4. Add Authorized Redirect URI(s):
   - `http://127.0.0.1:8000/accounts/google/login/callback/`
   - Optional: `http://localhost:8000/accounts/google/login/callback/`
5. Copy `Client ID` and `Client Secret`.

## 5. Set Environment Variables

In PowerShell (current terminal session):

```powershell
$env:GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
$env:GOOGLE_CLIENT_SECRET="your-client-secret"
$env:DJANGO_DEBUG="True"
```

Optional local app config values:

```powershell
$env:DJANGO_SECRET_KEY="your-local-secret"
$env:DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost"
```

## 6. Start Server

```powershell
python manage.py runserver
```

Open:

- `http://127.0.0.1:8000/accounts/login/`

Click:

- `Continue with Google`

## 7. Expected Flow in This Project

After Google callback:

1. User is sent to `/accounts/post-auth/`
2. If 2FA is enabled:
   - New/untrusted device -> OTP required
   - Trusted device (30 days) -> OTP may be skipped
3. If encryption key session (`_mk`) is missing:
   - User is sent to `/accounts/unlock/`
   - Data passphrase is required to unlock vault

## 8. Important Notes

- Google auth handles identity login.
- Data encryption access still depends on your data passphrase + TOTP secret derivation logic.
- Trusted-device cookie skips OTP only; it does not permanently skip unlock when `_mk` is absent.

## 9. Troubleshooting

### A) `ModuleNotFoundError: No module named 'requests'`

Install:

```powershell
python -m pip install requests
```

### B) Google button not visible / Google provider disabled

Check:

- `requests` installed in active venv
- `GOOGLE_CLIENT_ID` is set and non-empty

### C) `redirect_uri_mismatch` from Google

The callback URL in Google Console must exactly match:

- `http://127.0.0.1:8000/accounts/google/login/callback/`

### D) Login works but files/actions fail with 2FA required or key missing

Complete:

1. 2FA verification (if prompted)
2. Data unlock at `/accounts/unlock/`

## 10. Production Checklist

- Use HTTPS domain callback URL in Google Console
- Set `DJANGO_DEBUG=False`
- Set strong `DJANGO_SECRET_KEY`
- Set secure host list in `DJANGO_ALLOWED_HOSTS`
- Ensure TLS termination and secure cookie behavior
