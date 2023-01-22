from logging import getLogger
from datetime import timedelta
from typing import Union

import requests
from requests_oauthlib import OAuth2Session

from django.db import models
from django.utils import timezone
from django.conf import settings

from .errors import TokenError, IncompleteResponseError, TokenInvalidError


logger = getLogger(__name__)


def _process_scopes(scopes: Union[str, list, tuple, set]) -> tuple:
    if scopes is None:
        # support scope-less tokens
        scopes = ()
    if isinstance(scopes, str):
        # split a space-delimited string
        scopes = set(scopes.split())
    return tuple(scopes)


class TokenQuerySet(models.QuerySet):
    def get_expired(self) -> models.QuerySet:
        """
        Get all tokens that are expired.
        :return: All expired tokens.
        """
        return self.filter(created__lte=timezone.now() - models.F('ttl'))

    def bulk_refresh(self) -> models.QuerySet:
        """
        Refresh all refreshable tokens in the queryset and delete any expired token that fails or can not be
        refreshed.

        Excludes tokens for which the refresh was incomplete for other reasons.
        :return: All refreshed tokens
        """
        session = OAuth2Session(settings.DISCORD_APP_ID)
        auth = requests.auth.HTTPBasicAuth(
            settings.DISCORD_APP_ID,
            settings.DISCORD_APP_SECRET
        )
        incomplete = []
        for model in self.filter(refresh_token__is_null=False):
            try:
                model.refresh(session=session, auth=auth)
                logger.debug(f"Successfully refreshed {model}")
            except TokenError:
                logger.info(f'Refresh failed for {model}. Deleting.')
            except IncompleteResponseError:
                incomplete.append(model.pk)

    def require_valid(self) -> models.QuerySet:
        """
        Ensure all tokens are still valid and attempt to refresh any which are expired.

        Deletes those which fail to refresh or can not be refreshed.

        :return: All tokens which are still valid
        """
        expired = self.get_expired()
        valid = self.exclude(pk__in=expired)
        valid_expired = expired.bulk_refresh()
        return valid_expired | valid

    def require_scopes_fuzzy(self, scope_string: Union[str, list]) -> models.QuerySet:
        """
        Filter tokens which have at least a subset of given scopes.

        Args:
            scope_string: The required scopes.

        Returns:
            Tokens which have all requested scopes.
        """
        scopes = _process_scopes(scope_string)
        if not scopes:
            # asking for tokens with no scopes
            return self.filter(scopes__isnull=True)
        from .models import Scope
        scope_pks = Scope.objects.filter(name__in=scopes).values_list('pk', flat=True)
        if not len(scopes) == len(scope_pks):
            # there's a scope we don't recognize, so we can't have any tokens for it
            return self.none()
        tokens = self.all()
        for pk in scope_pks:
            tokens = tokens.filter(scopes__pk=pk)
        return tokens

    def require_scopes(self, scope_string: Union[str, list]) -> models.QuerySet:
        """
        Filter tokens which exactly have the given scopes.

        Args:
            scope_string: The required scopes.

        Returns:
            Tokens which have all requested scopes.
        """
        num_scopes = len(_process_scopes(scope_string))
        scopes_qs = self \
            .annotate(models.Count('scopes')) \
            .require_scopes_fuzzy(scope_string) \
            .filter(scopes__count=num_scopes) \
            .values('pk', 'scopes__id')
        pks = [v['pk'] for v in scopes_qs]
        return self.filter(pk__in=pks)

    def equivalent_to(self, token):
        """
        Fetch all tokens that match the discord user and scopes of the given reference token.

        Args
            token: the reference token
        """
        return self\
            .filter(discord_user_id=token.discord_user_id)\
            .require_scopes(token.scopes.all()).filter(models.Q(user=token.user) | models.Q(user__isnull=True))\
            .exclude(pk=token.pk)


class TokenManager(models.Manager):
    def get_queryset(self):
        """
        Replace the base queryset model with the custom TokenQueryset model.
        :rtype: :class:`djzkbBot.authentication.discord_auth.models.Token`
        """
        return TokenQuerySet(self.model, using=self._db)

    def __get_discord_user_id(self, token) -> str:
        """
        Gets the discord ID for the user that the token was issued to.

        :param token: a Discord Token

        :return: string representation of the discord userid
        """
        headers = {
            'Authorization': f"Bearer {token.get('access_token', None)}"
        }
        request_url = settings.DISCORD_API_BASE + "/users/@me"

        r = requests.get(request_url, headers=headers)
        r.raise_for_status()

        response = r.json()

        return response.get("id")

    def create_from_code(self, code, user=None):
        """
        Perform OAuth code exchange to retrieve a token.

        :param code: OAuth grant code.
        :param user: User who will oen the token.
        :rethrn: Token
        """

        logger.debug(f"Creating new token from {code}")
        oauth = OAuth2Session(
            settings.DISCORD_APP_ID,
            redirect_uri=settings.DISCORD_CALLBACK_URL
        )
        token = oauth.fetch_token(
            settings.DISCORD_TOKEN_URL,
            client_secret=settings.DISCORD_APP_SECRET,
            code=code
        )

        if token.get('access_token', None) is None:
            raise TokenInvalidError

        discord_id = self.__get_discord_user_id(token)
        duration = timedelta(seconds=token.get('expires_in', 604800))

        model = self.create(
            discord_user_id=discord_id,
            ttl=duration,
            access_token=token.get('access_token'),
            refresh_token=token.get('refresh_token'),
            user=user
        )

        if 'scope' in token:
            from .models import Scope

            if isinstance(token.get('scope'), str):
                token['scope'] = [token['scope']]

            for s in token.get('scope'):
                try:
                    scope = Scope.objects.get(name=s)
                    model.scopes.add(scope)
                except Scope.DoesNotExist:
                    # This scope was not created when the migration ran
                    # Create a placeholder model.
                    try:
                        help_text = s.split('.')[1].replace('_', ' ').capitalize()
                    except IndexError:
                        # Unusual scope name, missing periods.
                        help_text = s.replace('_', ' ').capitalize()
                    scope = Scope.objects.create(name=s, help_text=help_text)
                    model.scopes.add(scope)
            logger.debug(f"Added {model.scopes.all().count()} to new token.")

        if not settings.DISCORD_ALWAYS_CREATE_TOKEN:
            # see if we already have a token for this combination of discord user and scope combo.
            # if we have a matching token already we dont need this one.
            qs = self.get_queryset().equivalent_to(model)
            if qs.exists():
                logger.debug(
                    f"Identified {qs.count()} tokens equivalent to the new toke. "
                    f"Updating access and refresh tokens."
                    )
                qs.update(
                    access_token=model.access_token,
                    refresh_token=model.refresh_token,
                    created=model.created
                )
                if qs.filter(user=model.user).exists():
                    logger.debug(
                        "Equivalent token with the same user exists, deleting new token."
                    )
                    model.delete()
                    model = qs.filter(user=model.user)[0]

        logger.debug(f"Successfully created {model} for user {user or None}")
        return model

    def create_from_request(self, request):
        """
        Generate a token from the OAuth Callback request. Must contain 'code' in GET params.
        :param request: OAuth callback request.
        :return: Token
        """
        logger.debug(f"Creating new token for {request.user} session {request.session.session_key[:5]}")
        code = request.GET.get('code')

        model = self.create_from_code(
            code, user=request.user if request.user.is_authenticated else None
        )
        return model
