from logging import getLogger
from functools import wraps

from .models import Token

logger = getLogger(__name__)


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
            return
        return

    return decorator