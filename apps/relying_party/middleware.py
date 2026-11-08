import time

from django.contrib import messages
from django.contrib.auth import logout as auth_logout
from django.utils.translation import gettext

from . import browser_session


class SessionMaxAgeMiddleware:
    """
    Ends the session after session_max_age of the client. The session cookie has no expiry date, so the session also
    ends when the browser is closed; the end time is kept in the session on the server, the browser can't change it.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        login = request.session.get(browser_session.LOGIN_KEY)
        if login and login.get('ends_at') and time.time() > login['ends_at']:
            auth_logout(request)  # also deletes the session in the database
            messages.info(request, gettext('Your session has expired, please log in again.'))
        return self.get_response(request)
