"""
DO NOT EDIT THIS FILE

This settings file contains everything needed for zKillBot projects to function.
It gets overwritten by the 'zkillbot update' command.
If you wish to make changes, overload the setting in your project's settings file (local.py).
"""

import os

from django.contrib import messages
from celery.schedules import crontab

INSTALLED_APPS = [
    'djzkbBot',
    'django_sass_compiler',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_celery_beat',
    'esi',
    'djzkbBot.authentication',
    'djzkbBot.authentication.discord_auth',
    'djzkbBot.public',
    'djzkbBot.bot',
]

SECRET_KEY = "wow I'm a really bad default secret key"

# Celery configuration
BROKER_URL = 'redis://localhost:6379/0'
CELERYBEAT_SCHEDULER = "django_celery_beat.schedulers.DatabaseScheduler"
CELERYBEAT_SCHEDULE = {}    # TODO: Add default tasks as needed.

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.dirname(PROJECT_DIR)

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'djzkbBot.urls'

LOCALE_PATHS = (
    os.path.join(BASE_DIR, 'locale/'),
)

LANGUAGES = (
    ("en", "English"),
    ("de", "German"),
    ("es", "Spanish"),
    ("zh-hans", "Chinese Simplified"),
    ("ru", "Russian"),
    ("ko", "Korean"),
    ("fr", "French"),
    ("ja", "Japanese"),
    ("it", "Italian"),
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(PROJECT_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'djzkbBot.context_processors.djzkb_settings',
            ],
        },
    },
]

WSGI_APPLICATION = 'djzkbBot.wsgi.application'

# Password validation
# https://docs.djangoproject.com/en/1.10/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend'
]

# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/

LANGUAGE_CODE = 'en-us'

LANGUAGE_COOKIE_AGE = 1209600

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(PROJECT_DIR, 'static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# Bootstrap messaging css workaround
MESSAGE_TAGS = {
    messages.ERROR: 'danger error'
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1"  # change the 1 here to change the database used
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"

DEBUG = True
ALLOWED_HOSTS = ['*']
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': str(os.path.join(BASE_DIR, 'db.sqlite3')),
    },
}

SITE_NAME = 'zkill Bot'

LOGIN_URL = 'authentication:login'  # view that handles login logic

LOGIN_REDIRECT_URL = 'bot:dashboard'  # default destination when logging in if no redirect specified
LOGOUT_REDIRECT_URL = 'public:home'  # destination after logging out
# Both of these redirects accept values as per the django redirect shortcut
# https://docs.djangoproject.com/en/1.11/topics/http/shortcuts/#redirect
# - url names eg 'authentication:dashboard'
# - relative urls eg '/dashboard'
# - absolute urls eg 'http://example.com/dashboard'

# scopes required on new tokens when logging in. Cannot be blank.
ESI_LOGIN_TOKEN_SCOPES = ['publicData']
DISCORD_LOGIN_TOKEN_SCOPES = ['identify', 'email', 'guilds']

ESI_API_URL = 'https://esi.evetech.net/'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
            'datefmt': "%d/%b/%Y %H:%M:%S"
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'log_file': {
            'level': 'INFO',  # edit this line to change logging level to file
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'log/allianceauth.log'),
            'formatter': 'verbose',
            'maxBytes': 1024 * 1024 * 5,  # edit this line to change max log file size
            'backupCount': 5,  # edit this line to change number of log backups
        },
        'console': {
            'level': 'DEBUG',  # edit this line to change logging level to console
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'djzkbBot': {
            'handlers': ['log_file', 'console'],
            'level': 'DEBUG',
        },
        'django': {
            'handlers': ['log_file', 'console'],
            'level': 'ERROR',
        },
        'esi': {
            'handlers': ['log_file', 'console'],
            'level': 'DEBUG',
        },
    }
}

# Style Compilation Settings
SASS_COMPILER_NO_BUILD = True
SASS_COMPILER_CLEAN = True

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
DISCORD_API_BASE = "https://discord.com/api"
DISCORD_OAUTH_BASE = f"{DISCORD_API_BASE}/oauth2"
DISCORD_TOKEN_URL = f"{DISCORD_OAUTH_BASE}/token"
DISCORD_OAUTH_LOGIN_URL = f"{DISCORD_OAUTH_BASE}/authorize"
DISCORD_ALWAYS_CREATE_TOKEN = False
