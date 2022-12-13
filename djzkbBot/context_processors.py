from django.conf import settings


def djzkb_settings(request):
    return {
        'SITE_NAME': settings.SITE_NAME,
    }
