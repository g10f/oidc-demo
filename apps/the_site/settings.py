"""
Settings of the OpenID Connect demo (relying party).

Identity providers and clients are configured in the Django admin, everything else comes from environment
variables (see README.md).
"""
import os
import sys
from http.client import HTTPConnection
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse_lazy

# Only the command itself counts: a "test" anywhere in the arguments of gunicorn must not select the development key.
RUNNING_DEVSERVER = len(sys.argv) > 1 and sys.argv[1] == 'runserver'
RUNNING_TEST = len(sys.argv) > 1 and sys.argv[1] == 'test'

DEBUG = RUNNING_DEVSERVER
INTERNAL_IPS = ['127.0.0.1'] if DEBUG else []

BASE_DIR = Path(__file__).resolve().parent.parent

ALLOWED_HOSTS = ['.localhost', '127.0.0.1', '[::1]'] + os.getenv('ALLOWED_HOSTS', 'oidc-demo.g10f.de').split(',')

# The sessions are stored in the database, so a session can be ended from the server side (back-channel logout) and
# the secret key alone is not enough to forge one. The key still signs other values (e.g. password reset tokens), so
# the server (gunicorn) refuses to start without it. Commands of manage.py (runserver, migrate, test, ...) get a
# development key, so they work locally without setting one. PyCharm runs them through its own helper scripts.
RUNNING_MANAGE_PY = Path(sys.argv[0]).name in ('manage.py', 'django_manage.py', 'django_test_manage.py')
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    if RUNNING_MANAGE_PY:
        SECRET_KEY = 'insecure-key-for-development-only'
    else:
        raise ImproperlyConfigured(
            'The environment variable SECRET_KEY must be set, you can generate a value with: openssl rand -hex 32')

DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL', 'postgres://oidc_demo:oidc_demo@localhost:5432/oidc_demo'),
        conn_max_age=60)
}

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'relying_party',
]

MIDDLEWARE = [
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'relying_party.middleware.SessionMaxAgeMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'the_site.urls'
WSGI_APPLICATION = 'the_site.wsgi.application'

TEMPLATES = [
    # The pages of the demo, like in saml-demo.
    {
        'BACKEND': 'django.template.backends.jinja2.Jinja2',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': False,
        'OPTIONS': {
            'environment': 'the_site.jinja2.environment',
            'extensions': ['jinja2.ext.i18n'],
        },
    },
    # The Django admin only works with the Django template language.
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

AUTH_USER_MODEL = 'relying_party.User'
LOGIN_URL = reverse_lazy('relying_party:login')
LOGIN_REDIRECT_URL = reverse_lazy('relying_party:tokens')

SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'oidc_demo_session'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SECURE = not RUNNING_DEVSERVER
# Lax is enough: the identity provider sends the browser back with a top-level GET redirect, which carries Lax
# cookies. Front-channel logout runs in an iframe of the identity provider and gets no cookie with Lax, it finds
# the session by iss and sid instead (see views.frontchannel_logout).
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE

# The language comes from the browser (Accept-Language, LocaleMiddleware). The translations are made with Babel,
# because Django's makemessages can't read Jinja2 templates; see README.md.
LANGUAGE_CODE = 'en'
LANGUAGES = [('en', 'English'), ('de', 'Deutsch')]
LOCALE_PATHS = [BASE_DIR / 'locale']
TIME_ZONE = 'Europe/Berlin'
USE_I18N = True
USE_TZ = True

STATIC_ROOT = os.getenv('STATIC_ROOT', BASE_DIR.parent / 'htdocs/static')
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']

# The manifest storage gives the static files hashed names, so they can be cached forever. With it, a template
# referencing a missing static file fails with an error (when DEBUG is off). The tests run without collectstatic,
# so they use the storage without manifest.
if RUNNING_TEST:
    STATICFILES_BACKEND = 'whitenoise.storage.CompressedStaticFilesStorage'
else:
    STATICFILES_BACKEND = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
STORAGES = {
    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
    'staticfiles': {'BACKEND': STATICFILES_BACKEND},
}
WHITENOISE_ROOT = os.path.join(STATIC_ROOT, 'root')

# The signing keys of the identity providers are cached here (see relying_party.discovery).
CACHES = {
    'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
}

ABOUT_URL = os.getenv('ABOUT_URL', 'https://g10f.de/')
ENABLE_PLAUSIBLE = os.getenv('ENABLE_PLAUSIBLE', 'False').lower() in ('true', '1', 't')
DOMAIN = os.getenv('DOMAIN', 'localhost:8000')

ADMINS = [('Gunnar Scherf', 'gunnar@g10f.de')]
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'webmaster@g10f.de')
SERVER_EMAIL = os.getenv('SERVER_EMAIL', 'webmaster@g10f.de')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '25'))
if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Shows every request to the identity providers with headers and body, including the tokens. Only for debugging.
if os.getenv('REQUESTS_LOG_LEVEL', 'INFO') == 'DEBUG':
    HTTPConnection.debuglevel = 2

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {'()': 'django.utils.log.RequireDebugFalse'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler'},
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
        },
    },
    'root': {
        'handlers': ['console', 'mail_admins'],
        'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
    },
}
