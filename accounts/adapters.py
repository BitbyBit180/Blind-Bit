import re

from django.contrib.auth import get_user_model
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class BlindBitSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Auto-populate required username for social signups to skip 3rdparty form."""

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)

        if user.username:
            return user

        email = (data.get('email') or sociallogin.account.extra_data.get('email') or '').strip()
        candidate = email.split('@')[0] if email else (data.get('name') or 'user')
        base = re.sub(r'[^a-zA-Z0-9_]+', '', candidate).lower() or 'user'
        base = base[:24]

        User = get_user_model()
        username = base
        counter = 1
        while User.objects.filter(username=username).exists():
            suffix = str(counter)
            username = f"{base[:max(1, 24 - len(suffix))]}{suffix}"
            counter += 1

        user.username = username
        return user
