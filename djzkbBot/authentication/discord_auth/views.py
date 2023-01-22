from requests_oauthlib import OAuth2Session

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate
from django.contrib import messages
from django.http import HttpResponse, HttpResponseBadRequest
from django.conf import settings
from django.urls import reverse

from .models import Token, DiscordCallbackRedirect
from .decorators import discord_token_required

from logging import getLogger

logger = getLogger(__name__)


# Create your views here.
@discord_token_required(scopes=settings.DISCORD_LOGIN_TOKEN_SCOPES)
def login(request, token):
    user = authenticate(token=token)
    if user:
        token.user = user
        if Token.objects.exclude(pk=token.pk).equivalent_to(token).require_valid().exists():
            token.delete()
        else:
            token.save()
        if user.is_active:
            login(request, user)
            return redirect(request.POST.get('next', request.GET.get('next', settings.LOGIN_REDIRECT_URL)))
        else:
            messages.error(request, "User account is currently disabled. Please contact an administrator")
            return redirect(settings.LOGIN_URL)
    messages.error(request, "Unable to authenticate using the selected token.")
    return redirect(settings.LOGIN_URL)


def callback(request):
    """
    Parses the SSO callback, validates, and retrieves Token.
    Also, internally redirects to target URL.
    """
    logger.debug(f"Recieved callback for {request.user} session {request.session.session_key[:5]}")

    code = request.GET.get('code', None)
    state = request.GET.get('state', None)
    if not code or not state:
        logger.warning("Missing parameters for code exchange.")
        return HttpResponseBadRequest()

    callback = get_object_or_404(
        DiscordCallbackRedirect,
        state=state,
        session_key=request.session.session_key
    )
    token = Token.objects.create_from_request(request)
    callback.token = token
    callback.save()

    logger.debug(
        f"Processed callback for {request.user}" 
        f"session {request.session.session_key[:5]}. Redirecting to {callback.url}"
    )

    return redirect(callback.url)


def sso_redirect(request, scopes=None, return_to=None):
    """
    Generates a DiscordCallbackRedirect for the specified request.
    Redirects to Discord for login.
    Accepts a view or url name as a redirect after SSO.
    """
    logger.debug(
        f"Initiating redirect of {request.user}" 
        f"session {request.session.session_key[:5] if request.session.session_key else '[no key]'}"
    )
    if scopes is None:
        scopes = list()
    elif isinstance(scopes, str):
        scopes = list([scopes])

    # ensure only one redirect object per session
    if request.session.session_key:
        DiscordCallbackRedirect.objects.filter(session_key=request.session.session_key).delete()

    # ensure there is a session
    if not request.session.exists(request.session.session_key):
        logger.debug("Creating new session.")
        request.session.create()

    if return_to:
        url = reverse(return_to)
    else:
        url = request.get_full_path()

    oauth = OAuth2Session(
        settings.DISCORD_APP_ID,
        redirect_uri=settings.DISCORD_CALLBACK_URL,
        scopes=scopes
    )
    redirect_url, state = oauth.authorization_url(settings.DISCORD_OAUTH_LOGIN_URL)

    DiscordCallbackRedirect.objects.create(
        session_key=request.session.session_key,
        state=state,
        url=url
    )
    return redirect(redirect_url)


def revoke_token(request):
    pass


def refresh_token(request):
    pass
