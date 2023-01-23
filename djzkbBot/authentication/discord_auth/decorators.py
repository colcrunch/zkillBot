from logging import getLogger
from functools import wraps

from .models import Token, DiscordCallbackRedirect

logger = getLogger(__name__)


def _check_callback(request):
    if not request.session.exists(request.session.session_key):
        logger.debug(f"Creating session for {request.user}")
        request.session.create()

    try:
        model = DiscordCallbackRedirect.objects.get(session_key=request.session.session_key)
        token = Token.objects.get(pk=model.token.pk)
        model.delete()
        logger.debug(f"Retrieved new token from callback for {request.user} session {request.session.session_key[:5]}")
        return token
    except:
        logger.debug(f"No callback for {request.user} session {request.session.session_key[:5]}", exc_info=True)
        return None


def discord_token_required(scopes='', new=False):
    """
    Decorator for views to request a Discord Token.
    Accepts required scopes as a space-separated string or list of strings.
    :param scopes:
    :param new:
    :return:
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Check if we are coming back from SSO with a token.
            token = _check_callback(request)
            if token:
                logger.debug("Got new token from {request.user} session {request.session.session_key [:5]}. Returning.")
                return view_func(request, token, *args, **kwargs)

            # otherwise send user to SSO to add a new token
            logger.debug("Redirecting {request.user} session {request.session.session_key [:5]} to SSO.")
            from .views import sso_redirect
            return sso_redirect(request, scopes=scopes)

        return _wrapped_view

    return decorator
