from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class BlindBitSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Force explicit username confirmation during social signup."""

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        # Keep username empty so allauth shows the signup form and asks the user explicitly.
        user.username = ''
        return user
