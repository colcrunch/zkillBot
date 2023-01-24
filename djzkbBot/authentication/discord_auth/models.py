import datetime
import requests
from logging import getLogger

from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2.rfc6749.errors import (
    InvalidClientError,
    InvalidClientIdError,
    InvalidGrantError,
    InvalidTokenError,
    MissingTokenError,
)

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ImproperlyConfigured

from .managers import TokenManager
from .errors import TokenNotRefreshableError, TokenInvalidError, IncompleteResponseError, TokenExpiredError


logger = getLogger(__name__)


# Create your models here.
class Scope(models.Model):
    """
    Represents a scope granted by the Discord SSO
    """
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="The official name of the scope."
    )
    friendly_name = models.CharField(
        max_length=150,
        unique=True,
        help_text="A user friendly name for the scope."
    )
    help_text = models.TextField(help_text="The official description of the scope.")

    def __str__(self):
        return self.name

    class Meta:
        default_permissions = (())


class Token(models.Model):
    """
    Discord Access Token
    """
    created = models.DateTimeField(auto_now_add=True, editable=False)
    access_token = models.TextField(
        help_text="The access token granted by the Discord SSO.",
        editable=False
    )
    ttl = models.DurationField(
        null=False,
        help_text="The number of seconds that the token is valid for.",
        editable=False
    )
    refresh_token = models.TextField(
        null=True,
        help_text="A re-usuable token used to generate a new access token once they expire.",
        editable=False
    )
    discord_user_id = models.CharField(
        max_length=255,
        db_index=True,
        help_text="The discord user id for which this token is valid."
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text="The user that the token belongs to.",
        related_name="discord_token"
    )
    scopes = models.ManyToManyField(
        Scope,
        help_text="The scopes granted to this token"
    )

    objects = TokenManager()

    def __str__(self):
        return f'{self.discord_user_id} - {", ".join(s.name for s in self.scopes.all())}'

    def __repr__(self):
        return f'<{self.__class__.__name__}(id={self.pk}): {self.user.username}>'

    @property
    def can_refresh(self) -> bool:
        """
        Determine if the token can be refreshed.
        """
        return bool(self.refresh_token)

    @property
    def expires(self) -> datetime.datetime:
        """
        Determines when this token expires.
        :return: DateTime object representing expiry date.
        """
        return self.created + self.ttl

    @property
    def is_expired(self) -> bool:
        """
        Determine if the token is currently expir
        """
        return self.expires < timezone.now()

    @classmethod
    def get_token(cls, discord_user_id: str, scopes: tuple) -> "Token":
        """
        Helper method to get a token for a specific discord user with a specific set of scopes.

        :param discord_user_id: the discord user to filter on.
        :param scopes: a list of scopes to search for.
        :return: Matching token or `False` if no token is found.
        """
        token = Token.objects.filter(discord_user_id=discord_user_id).require_scopes(scopes).first()
        if token:
            return token
        return False

    def valid_access_token(self) -> str:
        """
        Refresh and return the access token to be used in calls to the Discord API.

        :return: A valid access token.
        :raises: TokenExpiredError when the token can not be refreshed.
        """
        if self.is_expired and not self.can_refresh:
            raise TokenExpiredError()
        elif self.is_expired and self.can_refresh:
            self.refresh()

        return self.access_token

    def refresh(self, session: OAuth2Session=None, auth: HTTPBasicAuth=None) -> None:
        """
        Refresh this token.
        :param session: the OAuth2Session to use to refresh the token.
        :param auth: Discord Authentication.
        """
        logger.debug(f"Attempting to refresh token {self}")
        if not self.can_refresh:
            logger.debug(f"Token not refreshable.")
            raise TokenNotRefreshableError

        if not session:
            session = OAuth2Session(settings.DISCORD_APP_ID)
        if not auth:
            auth = HTTPBasicAuth(
                settings.DISCORD_APP_ID,
                settings.DISCORD_APP_SECRET
            )

        try:
            token = session.refresh_token(
                "https://discord.com/api/oauth2/token",
                refresh_token=self.refresh_token,
                auth=auth
            )
            logger.debug("Retrieved new token from SSO server.")

            self.access_token = token['access_token']
            self.refresh_token = token['refresh_token']
            self.created = timezone.now()
            self.ttl = datetime.timedelta(seconds=token['expires_in'])
            self.save()
            logger.debug(f"Successfully refreshed {self}")
        except InvalidGrantError as e:
            logger.error(f"Refresh impossible for {self}: {e}")
            raise TokenInvalidError()
        except (InvalidTokenError, InvalidClientIdError) as e:
            logger.warning(f"Refresh failed for {self}: {e}")
            raise TokenInvalidError()
        except MissingTokenError as e:
            logger.info(f"Refresh failed for {self}: {e}")
            raise IncompleteResponseError()
        except InvalidClientError as e:
            logger.error("Discord credentials rejected by remote. Cannot refresh.")
            raise ImproperlyConfigured(
                "Verify that DISCORD_APP_ID and DISCORD_APP_SECRET settings in local.py"
            )

    def get_full_username(self):
        """
        Retrieves the full username (username and discriminator) from the Discord API.
        """
        headers = {
            'Authorization': f"Bearer {self.access_token}"
        }
        request_url = settings.DISCORD_API_BASE + "/users/@me"

        r = requests.get(request_url, headers=headers)
        r.raise_for_status()

        response = r.json()

        username = response.get("username")
        discriminator = response.get("discriminator")

        return f"{username}#{discriminator}"

    def get_email(self):
        """
        Gets the email from the discord API.
        """
        headers = {
            'Authorization': f"Bearer {self.access_token}"
        }
        request_url = settings.DISCORD_API_BASE + "/users/@me"

        r = requests.get(request_url, headers=headers)
        r.raise_for_status()

        response = r.json()

        return response.get("email", None)

    def get_avatar(self):
        """
                Gets the email from the discord API.
                """
        headers = {
            'Authorization': f"Bearer {self.access_token}"
        }
        request_url = settings.DISCORD_API_BASE + "/users/@me"

        r = requests.get(request_url, headers=headers)
        r.raise_for_status()

        response = r.json()

        return response.get("avatar", None)

    class Meta:
        default_permissions = (())


class DiscordCallbackRedirect(models.Model):
    """
    Records the intended destination for the SSO callback.
    Used to internally redirect SSO callbacks.
    """
    session_key = models.CharField(
        max_length=254,
        unique=True,
        help_text="Session key identifying the session this redirect was created for."
    )
    url = models.TextField(
        default="/",
        help_text="The internal URL to redirect this callback to"
    )
    state = models.CharField(
        max_length=128,
        help_text="OAuth2 state string to represent this session."
    )
    created = models.DateTimeField(auto_now_add=True)
    token = models.ForeignKey(
        Token,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        help_text="Token generated by a complete code exchange from callback processing."
    )

    def __str__(self):
        return f"{self.session_key}: {self.url}"

    def __repr__(self):
        return f"<{self.__class__.__name__}(pk={self.pk}): {self.session_key} to {self.url}>"
