from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'djzkbBot.authentication'
    label = 'authentication'

    def ready(self):
        from djzkbBot.authentication import signals
