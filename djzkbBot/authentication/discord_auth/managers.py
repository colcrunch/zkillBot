from logging import getLogger
from typing import Union

import requests
from requests_oauthlib import OAuth2Session

from django.db import models
from django.utils import timezone
from django.conf import settings

from .errors import TokenError, IncompleteResponseError


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


class TokenManager(models.Manager):
    def get_queryset(self):
        """
        Replace the base queryset model with the custom TokenQueryset model.
        :rtype: :ckass:`djzkbBot.authentication.discord_auth.models.Token`
        """
        return TokenQuerySet(self.model, using=self._db)