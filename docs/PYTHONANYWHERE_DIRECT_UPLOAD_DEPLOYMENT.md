# Deploy BlindBit on PythonAnywhere (Direct Upload, No GitHub)

This guide is for deploying this project by uploading files directly to PythonAnywhere.

## 1. Prerequisites

- A PythonAnywhere account (Beginner or higher).
- A local copy of this project (`Blind-Bit` folder).
- PythonAnywhere Bash console access.

## 2. Upload Project Files

1. On your computer, zip the project folder.
2. In PythonAnywhere, open the `Files` tab.
3. Upload the zip file to your home directory, for example:
   - `/home/<your-username>/Blind-Bit.zip`
4. Open a `Bash` console and extract it:

```bash
cd ~
unzip Blind-Bit.zip
```

Your project should now be at:

```text
/home/<your-username>/Blind-Bit
```

## 3. Create Virtual Environment and Install Dependencies

In a Bash console:

```bash
cd ~/Blind-Bit
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

If `python3.11` is unavailable on your account, use the version shown in PythonAnywhere consoles (for example `python3.10`).

## 4. Create Production `.env`

Create `~/Blind-Bit/.env`:

```dotenv
DJANGO_SECRET_KEY=replace-with-a-long-random-secret
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=<your-username>.pythonanywhere.com
DJANGO_DB_PATH=/home/<your-username>/Blind-Bit/app.sqlite3
SEARCH_OBFUSCATION_ENABLED=True
SEARCH_OBFUSCATION_DECOYS=2
```

Notes:
- Keep `DJANGO_DEBUG=False` in production.
- `DJANGO_ALLOWED_HOSTS` must include your actual domain.
- Google OAuth is optional; only add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` if you need it.

## 5. Initialize Database and Static Files

```bash
cd ~/Blind-Bit
source .venv/bin/activate
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py createsuperuser
```

## 6. Create the PythonAnywhere Web App

1. Go to the `Web` tab.
2. Click `Add a new web app`.
3. Choose your domain (`<your-username>.pythonanywhere.com`).
4. Choose `Manual configuration` (not Flask/Django quickstart).
5. Pick the same Python version used for `.venv`.

## 7. Configure Virtualenv and Paths

In the `Web` tab:

- **Virtualenv**:
  - `/home/<your-username>/Blind-Bit/.venv`
- **Working directory**:
  - `/home/<your-username>/Blind-Bit`

## 8. Configure Static and Media Mapping

In `Web` tab -> `Static files`:

- URL: `/static/`
  - Directory: `/home/<your-username>/Blind-Bit/static`
- URL: `/media/`
  - Directory: `/home/<your-username>/Blind-Bit/media`

## 9. Edit WSGI File

Open the WSGI file from the `Web` tab (something like `/var/www/<your-username>_pythonanywhere_com_wsgi.py`) and replace contents with:

```python
import os
import sys

project_home = "/home/<your-username>/Blind-Bit"
if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "blindbit_web.settings")

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Save the file.

## 10. Reload and Verify

1. Go back to the `Web` tab.
2. Click `Reload`.
3. Open `https://<your-username>.pythonanywhere.com/`.

If something fails, check:
- `Web` tab -> error log
- `Web` tab -> server log

## 11. Update Workflow (When You Re-upload Files)

Each time you upload changed source files:

```bash
cd ~/Blind-Bit
source .venv/bin/activate
python manage.py migrate
python manage.py collectstatic --noinput
```

Then click `Reload` in the `Web` tab.

## 12. Common Issues

- `DisallowedHost`: `DJANGO_ALLOWED_HOSTS` is wrong. Set exact domain.
- Static files missing: run `collectstatic` and verify `/static/` mapping.
- `ModuleNotFoundError`: virtualenv path is wrong in `Web` tab.
- 500 error on startup: verify WSGI path and `DJANGO_SETTINGS_MODULE`.
- Permissions errors on SQLite/media/storage: keep project under `/home/<your-username>/...` and ensure directories exist.

## 13. Optional Hardening

- Keep `DJANGO_DEBUG=False`.
- Rotate `DJANGO_SECRET_KEY` if exposed.
- Restrict admin access and use a strong superuser password.
- Add regular backups for:
  - `app.sqlite3`
  - `media/`
  - `storage/`
