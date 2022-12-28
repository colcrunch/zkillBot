from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import requests

from logging import getLogger

logger = getLogger(__name__)


# Create your views here.
def login(request, token):
    pass


def callback(request):
    code = request.GET.get('code')

    data = {
        'client_id': settings.DISCORD_APP_ID,
        'client_secret': settings.DISCORD_APP_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': 'http://bot.local/discord/callback/',
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers)
    r.raise_for_status()

    t = r.json()

    return HttpResponse(str(t))


def revoke_token(request):
    pass


def refresh_token(request):
    pass
