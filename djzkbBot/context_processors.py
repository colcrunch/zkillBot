import urllib.parse

from django.conf import settings


def djzkb_settings(request):
    d_encoded = urllib.parse.quote(settings.DISCORD_CALLBACK_URL, safe='')
    d_redirect = (f"https://discord.com/api/oauth2/authorize"
                  f"?client_id={settings.DISCORD_APP_ID}"
                  f"&redirect_uri={d_encoded}"
                  f"&response_type=code"
                  f"&scope={'%20'.join(settings.DISCORD_LOGIN_TOKEN_SCOPES)}")
    return {
        'SITE_NAME': settings.SITE_NAME,
        'DISCORD_LOGIN_URL': d_redirect,
    }
