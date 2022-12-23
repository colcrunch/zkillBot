# Every setting in base.py can be overloaded by redefining it here.
from .base import *

# These are required for Django to function properly. Don't touch.
ROOT_URLCONF = '{{ project_name }}.urls'
WSGI_APPLICATION = '{{ project_name }}.wsgi.application'
SECRET_KEY = '{{ secret_key }}'

# This is where css/images will be placed for your webserver to read
STATIC_ROOT = "/var/www/{{ project_name }}/static/"

# Change this to change the name of the auth site displayed
# in page titles and the site header.
SITE_NAME = '{{ project_name }}'

# This is your websites URL, set it accordingly
# Make sure this URL is WITHOUT a trailing slash
SITE_URL = "https://example.com"

# Django security
CSRF_TRUSTED_ORIGINS = [SITE_URL]

# Change this to enable/disable debug mode, which displays
# useful error messages but can leak sensitive data.
DEBUG = False

# Add any additional apps to this list.
INSTALLED_APPS += [

]

# To change the logging level for extensions, uncomment the following line.
# LOGGING['handlers']['extension_file']['level'] = 'DEBUG'


# Enter credentials to use MySQL/MariaDB. Comment out to use sqlite3
DATABASES['default'] = {
    'ENGINE': 'django.db.backends.mysql',
    'NAME': 'zkillbot',
    'USER': '',
    'PASSWORD': '',
    'HOST': '127.0.0.1',
    'PORT': '3306',
    'OPTIONS': {'charset': 'utf8mb4'},
}

# ESI Settings
ESI_SSO_CLIENT_ID = ''
ESI_SSO_CLIENT_SECRET = ''
ESI_SSO_CALLBACK_URL = f"{SITE_URL}/sso/callback"
ESI_USER_CONTACT_EMAIL = ''    # A server maintainer that CCP can contact in case of issues.

# Discord Settings
DISCORD_CALLBACK_URL = f"{SITE_URL}/discord/callback/"
DISCORD_APP_ID = ''
DISCORD_APP_SECRET = ''
DISCORD_BOT_TOKEN = ''

# Cache compression can help on bigger sites where ram starts to become an issue.
# Uncomment the following 3 lines to enable.

#CACHES["default"]["OPTIONS"] = {
#    "COMPRESSOR": "django_redis.compressors.lzma.LzmaCompressor",
#}