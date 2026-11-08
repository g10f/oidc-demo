import json
from datetime import datetime

from django.conf import settings
from django.contrib.messages import get_messages
from django.templatetags.static import static
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext, ngettext
from jinja2 import Environment

from relying_party.browser_session import current_login, is_strong_authentication
from relying_party.protocol import is_http_url
from relying_party.views import user_navigation
from the_site import __version__


def to_pretty_json(value):
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)


def format_timestamp(value):
    """Seconds since the epoch (like exp and iat of a token) in the time zone of the site."""
    if not isinstance(value, (int, float)):
        return ''
    return timezone.localtime(datetime.fromtimestamp(value, tz=timezone.get_current_timezone())).strftime(
        '%Y-%m-%d %H:%M:%S')


def environment(**options):
    env = Environment(**options)
    # newstyle: _('Hello %(name)s', name=...) escapes the variables, the text of the template is not escaped
    env.install_gettext_callables(gettext, ngettext, newstyle=True)
    env.globals.update({
        'static': static,
        'url': reverse,
        'get_messages': get_messages,
        # Only http(s) urls from the identity provider become links or images, a javascript: url must not.
        'is_http_url': is_http_url,
        'current_login': current_login,
        'is_strong_authentication': is_strong_authentication,
        'user_navigation': user_navigation,
        'about_url': settings.ABOUT_URL,
        'enable_plausible': settings.ENABLE_PLAUSIBLE,
        'domain': settings.DOMAIN,
        'version': __version__,
    })
    env.filters['pretty_json'] = to_pretty_json
    env.filters['datetime'] = format_timestamp
    return env
