# Django settings for client project.
import os

import sys
from http.client import HTTPConnection
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse_lazy

try:
    RUNNING_DEVSERVER = (sys.argv[1] == 'runserver')
except:
    RUNNING_DEVSERVER = False

# Only the command itself counts: a "test" anywhere in the arguments of gunicorn must not select the development key.
RUNNING_TEST = len(sys.argv) > 1 and sys.argv[1] == 'test'

if RUNNING_DEVSERVER:
    INTERNAL_IPS = ('127.0.0.1',)
    DEBUG = True
else:
    DEBUG = False

if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

DOMAIN = os.getenv('DOMAIN', "localhost:8000")
ENABLE_PLAUSIBLE = os.getenv('ENABLE_PLAUSIBLE', 'False').lower() in ('true', '1', 't')

ALWAYS_REFRESH_TOKENS = os.getenv('ALWAYS_REFRESH_TOKENS', 'False').lower() in ('true', 'yes', '1')

REQUESTS_LOG_LEVEL = os.getenv('REQUESTS_LOG_LEVEL', 'INFO')
if REQUESTS_LOG_LEVEL == 'DEBUG':
    HTTPConnection.debuglevel = 2
ALLOWED_HOSTS = ['.localhost', '127.0.0.1', '[::1]'] + os.getenv('ALLOWED_HOSTS', 'oidc-demo.g10f.de').split(',')
SILENCED_SYSTEM_CHECKS = ['admin.E408']
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
INTERNAL_IPS = ('127.0.0.1',)

BASE_DIR = Path(__file__).resolve().parent.parent

ADMINS = (
    ('Gunnar Scherf', 'gunnar@g10f.de'),
)
BRAND = 'G10F+'
ABOUT = os.getenv('ABOUT_URL', 'https://g10f.de/')
OPENID_SSO_SERVER_BASE_URL = os.getenv('OPENID_SSO_SERVER_BASE_URL', 'https://sso.g10f.de/')

SITE_ID = 1
DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL', "postgres://client:client@localhost:5432/client"), conn_max_age=60)
}

TIME_ZONE = 'Europe/Berlin'
LANGUAGE_CODE = 'en-us'

# SITE_ID = 1

# Default in django 4.1
# USE_I18N = True
# USE_L10N = True

# Default from django 5.0
USE_TZ = True

gettext = lambda s: s

LANGUAGES = (
    ('en', gettext('English')),
    ('de', gettext('Deutsch')),
)

STATIC_ROOT = os.getenv('STATIC_ROOT', BASE_DIR.parent / 'htdocs/static')
MEDIA_ROOT = os.getenv('MEDIA_ROOT', BASE_DIR.parent / 'htdocs/media')

MEDIA_URL = ''
STATIC_URL = '/static/'

if RUNNING_TEST:
    STORAGES = {
        "default": {
            "BACKEND": "django.core.files.storage.InMemoryStorage",
        },
        "staticfiles": {
            "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
        },
    }
else:
    STORAGES = {
        "default": {
            "BACKEND": "django.core.files.storage.FileSystemStorage",
        },
        "staticfiles": {
            "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
        },
    }

WHITENOISE_ROOT = os.path.join(STATIC_ROOT, 'root')

LOGIN_URL = reverse_lazy('login')
LOGIN_REDIRECT_URL = reverse_lazy('login')
SESSION_COOKIE_NAME = 'client_session_id'

SSO = {
    'STAFF_GROUPS': os.getenv('SSO.STAFF_GROUPS', 'Staff,Superuser').split(','),
    'APP_NAME': 'OAuth2 Test',
    'SUPERUSER_GROUP': os.getenv('SSO.SUPERUSER_GROUP', 'Superuser')
}

AUTHENTICATION_BACKENDS = (
    'client.oauth2.backend.OAuth2Backend',
    'django.contrib.auth.backends.ModelBackend'
)

AUTH_USER_MODEL = 'oauth2.User'
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
# SESSION_COOKIE_AGE = 60 * 10  # seconds * Minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SECURE = not RUNNING_DEVSERVER
SESSION_COOKIE_SAMESITE = 'None' if SESSION_COOKIE_SECURE else 'Lax'

# Additional locations of static files
STATICFILES_DIRS = (
    BASE_DIR / 'static',
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
]

# The sessions are signed cookies, so whoever knows this key can forge a session, also one of an admin. That is why
# only the development server and the tests have a default, everything else refuses to start without a key.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    if RUNNING_DEVSERVER or RUNNING_TEST:
        SECRET_KEY = 'insecure-key-for-development-only'
    else:
        raise ImproperlyConfigured(
            'The environment variable SECRET_KEY must be set, you can generate a value with: openssl rand -hex 32')

if DEBUG:
    # don't use cached loader
    LOADERS = [
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    ]
else:
    LOADERS = [
        ('django.template.loaders.cached.Loader', (
            'django.template.loaders.filesystem.Loader',
            'django.template.loaders.app_directories.Loader',
        )),
    ]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'client/templates',
        ],
        # 'APP_DIRS': True,  # must not be set if loaders is set
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                "django.template.context_processors.request",
                'django.contrib.messages.context_processors.messages',
                'client.context_processors.settings',
            ],
            'loaders': LOADERS,
            'debug': DEBUG
        },
    },
]

MIDDLEWARE = [
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    # 'django.contrib.auth.middleware.AuthenticationMiddleware',
    'client.oauth2.middleware.OAuthAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'client.oauth2.middleware.LoginMiddleware',
]

ROOT_URLCONF = 'client.urls'
WSGI_APPLICATION = 'client.wsgi.application'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic',
    'django.contrib.staticfiles',
    'django.contrib.flatpages',
    'django.contrib.admin',
    'django.contrib.admindocs',
    'sorl.thumbnail',
    'client.oauth2',
    'client',
)

DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'webmaster@g10f.de')
SERVER_EMAIL = os.getenv('SERVER_EMAIL', 'webmaster@g10f.de')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '25'))

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(lineno)d %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'verbose',
        }
    },
    'root': {
        'handlers': ['console', 'mail_admins'],
        'level': os.getenv('ROOT_LOG_LEVEL', 'INFO'),
    },
    'loggers': {
        'client.oauth2': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'requests.packages.urllib3': {
            'handlers': ['console'],
            'level': os.getenv('REQUESTS_LOG_LEVEL', 'INFO'),
            'propagate': True,
        },
        'django': {
            'handlers': ['console', 'mail_admins'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
    },
}
