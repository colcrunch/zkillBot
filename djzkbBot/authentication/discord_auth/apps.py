from django.apps import AppConfig


class DiscordAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'djzkbBot.authentication.discord_auth'
    label = 'discord_auth'
