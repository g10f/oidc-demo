"""
What the demo keeps in the Django session (stored in the database), there are no tables for tokens:

- "oidc_pending": the started logins by state, with nonce and PKCE code verifier. A state is taken out when the
  callback uses it, so it is valid once and only in the browser that started the login (RFC 6749 10.12).
- "oidc_device": the running device authorization (RFC 8628).
- "oidc_login": the current login: client, iss, sub, sid, session_state, the end of the session (session_max_age
  of the client, checked by middleware.SessionMaxAgeMiddleware) and the token set with the checks.
  "history" holds the earlier token sets of this login (refreshes), newest first.
- "oidc_silent_login_at": when the last silent login (prompt=none) of Session Management was started.
- "oidc_navigation": the applications of the user at the g10f SSO for the navigation bar, for 5 minutes.
"""
import time

from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.utils import timezone

from .errors import ProtocolError
from .models import Client

PENDING_KEY = 'oidc_pending'
DEVICE_KEY = 'oidc_device'
LOGIN_KEY = 'oidc_login'
LOGOUT_STATE_KEY = 'oidc_logout_state'
NAVIGATION_KEY = 'oidc_navigation'
SILENT_LOGIN_KEY = 'oidc_silent_login_at'

# A login must be finished within 10 minutes, older states are dropped.
PENDING_MAX_AGE = 600
# Only the newest started logins are kept, so reloading the login page can't fill the session.
PENDING_MAX_COUNT = 10
HISTORY_MAX_COUNT = 10


def add_pending(request, state, pending):
    entries = {key: value for key, value in request.session.get(PENDING_KEY, {}).items()
               if time.time() - value['created'] < PENDING_MAX_AGE}
    entries[state] = pending
    newest = sorted(entries.items(), key=lambda item: item[1]['created'])[-PENDING_MAX_COUNT:]
    request.session[PENDING_KEY] = dict(newest)


def pop_pending(request, state):
    """The started login for the state of a response, it can only be taken once."""
    entries = request.session.get(PENDING_KEY, {})
    pending = entries.pop(state, None) if isinstance(state, str) else None
    if pending is None:
        raise ProtocolError('invalid_state', 'The response does not belong to a login started in this browser, '
                                             'or the login was already finished.')
    # Only written when something was taken out: a request with an unknown state must not create a session.
    request.session[PENDING_KEY] = entries
    if time.time() - pending['created'] >= PENDING_MAX_AGE:
        raise ProtocolError('invalid_state', 'The login took longer than 10 minutes, please start it again.')
    return pending


def set_login(request, client, token_set, session_state=None):
    """Called after django.contrib.auth.login, which may start a new session for another user."""
    claims = token_set.get('id_token_claims') or {}
    request.session.pop(NAVIGATION_KEY, None)  # it belongs to the previous login
    if hasattr(request, '_oidc_current_login'):
        del request._oidc_current_login
    request.session[LOGIN_KEY] = {
        'client': client.pk,
        'iss': claims.get('iss', client.identity_provider.issuer),
        'sub': claims.get('sub'),
        'sid': claims.get('sid'),
        'session_state': session_state,
        # Kept in the session and not in the cookie, so the browser can't extend it.
        'ends_at': time.time() + client.session_max_age if client.session_max_age else None,
        'tokens': token_set,
        'history': [],
    }


def current_login(request):
    """
    The OpenID Connect login of this session and its client, as pair. (None, None) if nobody is logged in or the
    user logged in with a password (admin).
    """
    # A page asks several times (view, navigation bar, template), the client is only read once per request.
    if not hasattr(request, '_oidc_current_login'):
        login = request.session.get(LOGIN_KEY)
        client = None
        if login and request.user.is_authenticated:
            client = Client.objects.select_related('identity_provider').filter(pk=login['client']).first()
        request._oidc_current_login = (login, client) if client else (None, None)
    return request._oidc_current_login


def is_strong_authentication(login, identity_provider):
    """
    Whether the user logged in with a strong (two factor) authentication, from the claims of the ID token: an acr the
    identity provider defines as strong (OpenID Connect Core 2), or "mfa" in amr (RFC 8176).
    """
    claims = login['tokens'].get('id_token_claims') or {}
    amr = claims.get('amr')
    if isinstance(amr, list) and 'mfa' in amr:
        return True
    return str(claims.get('acr', '')) in identity_provider.strong_acr_values.split()


def stop_session_checks(request):
    """The OP iframe of Session Management can't read its own state in this browser, no more checks for this login."""
    login = request.session[LOGIN_KEY]
    login['session_checks_stopped'] = True
    request.session.modified = True


def update_tokens(request, token_set):
    login = request.session[LOGIN_KEY]
    login['history'] = ([login['tokens']] + login['history'])[:HISTORY_MAX_COUNT]
    login['tokens'] = token_set
    request.session.modified = True


def delete_sessions(iss, sid=None, sub=None):
    """
    Ends the sessions of a logout from the identity provider (front-channel or back-channel). With a sid only that
    session, with a sub all sessions of the user. A logout token can contain both: then a session whose ID token
    had no sid is found by the sub. Returns the number of deleted sessions.

    The session data is encoded, so every active session is decoded and compared. That is simple and fast enough for
    a demo; a site with many users would store iss, sid and sub in extra columns of its own session model.
    """
    count = 0
    for session in Session.objects.filter(expire_date__gt=timezone.now()):
        login = SessionStore().decode(session.session_data).get(LOGIN_KEY)
        if not login or login.get('iss') != iss:
            continue
        if sid and login.get('sid'):
            if login['sid'] != sid:
                continue
        elif sid and not sub:
            continue  # the session has no sid, and there is no sub to find it by
        if sub and login.get('sub') != sub:
            continue
        session.delete()
        count += 1
    return count
