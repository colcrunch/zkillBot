import logging

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User, Permission
from django.contrib import messages

from .models import UserProfile


logger = logging.getLogger(__name__)


class DiscordBackend(ModelBackend):
    def authenticate(self, request=None, token=None, **credentials):
        if not token:
            return None
        try:
            profile = UserProfile.objects.get(discord_user_id=token.discord_user_id)
            logger.debug(f"Authenticating {profile.user} by their discord account {profile.discord_user_id}")
            token.user = profile.user
            return profile.user
        except UserProfile.DoesNotExist:
            logger.debug(f"Unable to authenticate discord user {token.discord_user_id}. Creating new user.")
            return self.create_user(token)

    def create_user(self, token):
        username = self.iterate_username(token.get_full_username())
        email = token.get_email()
        user = User.objects.create_user(username, email=email, is_active=True)
        user.set_unusable_password()
        user.save()
        token.user = user
        user.profile.discord_user_id = token.discord_user_id
        user.profile.save()
        logger.debug(f"Created user {user}")
        return user

    @staticmethod
    def iterate_username(name):
        if User.objects.filter(username__startswith=name).exists():
            u = User.objects.filter(username__startswith=name)
            num = len(u)
            username = f"{name}_{num}"
            while u.filter(username=username).exists():
                num += 1
                username = f"{name}_{num}"
        else:
            username = name
        return username
