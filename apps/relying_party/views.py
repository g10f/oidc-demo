"""
The pages of the demo. The protocol steps are in protocol.py, the session data in browser_session.py; the views
only connect them with the requests of the browser.
"""
import logging
import time
from functools import wraps
from urllib.parse import urlsplit

import jwt
import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render, resolve_url
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_exempt, xframe_options_sameorigin
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import browser_session, protocol
from .api import bearer_token_required, validate_access_token
from .errors import ProtocolError
from .models import Client
from .users import RolesMissing, update_user

logger = logging.getLogger(__name__)

# The largest upload this demo reads at all; the SSO tells its own, usually smaller limit (picture_max_size).
MAX_PICTURE_SIZE = 5 * 1024 * 1024
NAVIGATION_CACHE_SECONDS = 300
# A "changed" of the OP iframe this soon after a silent login means it can't read its own state (see session_iframe).
SILENT_LOGIN_LOOP_SECONDS = 60
# Errors of a silent login (prompt=none) that mean: the user is no longer logged in at the identity provider.
SILENT_LOGIN_ERRORS = {'login_required', 'interaction_required', 'consent_required', 'account_selection_required'}


def render_error(request, error, status=400):
    return render(request, 'error.html', {'error': error}, status=status)


def shows_protocol_errors(view):
    """An error of the identity provider or in its answer is shown on the error page, it is no server error."""

    @wraps(view)
    def wrapped_view(request, *args, **kwargs):
        try:
            return view(request, *args, **kwargs)
        except ProtocolError as e:
            logger.info('%s: %s', request.path, e)
            return render_error(request, e)
        except requests.RequestException as e:
            # The exception text can contain the url with a token, so only its type is logged.
            logger.warning('%s: the identity provider can not be reached (%s)', request.path, type(e).__name__)
            return render_error(request, ProtocolError(
                'temporarily_unavailable', "The identity provider can't be reached, please try again later."),
                status=502)

    return wrapped_view


def safe_next_url(request, url):
    if url and url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()},
                                               require_https=request.is_secure()):
        return url
    return resolve_url(settings.LOGIN_REDIRECT_URL)


def get_redirect_uri(request, client):
    if client.flow in (Client.FLOW_IMPLICIT, Client.FLOW_IMPLICIT_ID_TOKEN):
        return request.build_absolute_uri(reverse('relying_party:implicit'))
    return request.build_absolute_uri(client.redirect_uri or reverse('relying_party:callback'))


def active_clients(flow):
    return Client.objects.filter(flow=flow, is_active=True, identity_provider__is_active=True) \
        .select_related('identity_provider').order_by('identity_provider__order', 'identity_provider__name', 'name')


def finish_login(request, client, token_set, session_state=None):
    if not token_set.get('id_token_claims'):
        # Without an ID token there is no authenticated user, only an access token (plain OAuth 2.0).
        raise ProtocolError('invalid_response', 'There is no ID token, the scope of the client must contain "openid".')
    user = update_user(client, token_set['id_token_claims'])
    auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    browser_session.set_login(request, client, token_set, session_state)
    return user


def redirect_to_identity_provider(request, client, next_url, prompt=None, login_hint=None):
    id_token_hint = None
    login, current_client = browser_session.current_login(request)
    if prompt == 'none' and login and current_client == client:
        id_token_hint = login['tokens'].get('id_token')
    if prompt == 'none':
        request.session[browser_session.SILENT_LOGIN_KEY] = time.time()
    url, state, pending = protocol.build_authentication_request(
        client, get_redirect_uri(request, client), prompt=prompt, login_hint=login_hint, id_token_hint=id_token_hint)
    pending['next'] = next_url
    browser_session.add_pending(request, state, pending)
    return HttpResponseRedirect(url)


# --- pages ------------------------------------------------------------------------------------------------------

def home(request):
    return render(request, 'home.html')


def login_page(request):
    next_url = request.GET.get('next', '')
    return render(request, 'login.html', {'clients': active_clients(Client.FLOW_CODE), 'next': next_url})


@never_cache
@shows_protocol_errors
def start_login(request, client_id):
    client = get_object_or_404(Client, pk=client_id, is_active=True, identity_provider__is_active=True)
    if client.flow == Client.FLOW_DEVICE:
        raise Http404('The device flow is started on the device page.')
    # Only the silent login of Session Management may change the prompt, everything else is configured.
    prompt = 'none' if request.GET.get('prompt') == 'none' else None
    return redirect_to_identity_provider(request, client, safe_next_url(request, request.GET.get('next')), prompt)


@never_cache
@shows_protocol_errors
def callback(request):
    """Core 3.1.2.5: the identity provider sends the browser back with code and state (or an error)."""
    params = request.GET
    if 'state' not in params and 'code' not in params and 'error' not in params:
        # A plain visit, e.g. of the old callback /oauth2/login/
        return HttpResponseRedirect(reverse('relying_party:login'))

    pending = browser_session.pop_pending(request, params.get('state'))
    client = get_object_or_404(Client.objects.select_related('identity_provider'), pk=pending['client'])
    next_url = pending.get('next') or resolve_url(settings.LOGIN_REDIRECT_URL)
    try:
        checks = protocol.check_authentication_response(client.identity_provider, params)
    except ProtocolError as e:
        if pending.get('prompt') == 'none' and e.error in SILENT_LOGIN_ERRORS:
            # Session Management 1.0 4.1: the session at the identity provider has ended, so it ends here too.
            auth_logout(request)
            messages.info(request, gettext('Your session at the identity provider has ended, you are logged out.'))
            return HttpResponseRedirect(reverse('relying_party:home'))
        raise
    if not params.get('code'):
        raise ProtocolError('invalid_response', 'The authentication response has no code.')

    token_set = protocol.exchange_code(client, params['code'], pending)
    token_set['checks'] = checks + token_set['checks']
    try:
        user = finish_login(request, client, token_set, params.get('session_state'))
    except RolesMissing as e:
        auth_logout(request)
        if e.extend_access_uri:
            return HttpResponseRedirect(protocol.add_query_parameters(
                e.extend_access_uri, {'redirect_uri': request.build_absolute_uri(next_url)}))
        raise
    if pending.get('prompt') != 'none':
        messages.success(request, gettext('Welcome %(user)s, you are logged in with %(provider)s.') % {
            'user': user, 'provider': client.identity_provider})
    # The redirect keeps the url with code and state out of the browser history.
    return HttpResponseRedirect(next_url)


@require_POST
def logout(request):
    """RP-Initiated Logout 1.0: ends the session here and, if the provider supports it, there too."""
    login, client = browser_session.current_login(request)
    auth_logout(request)
    id_token = login['tokens'].get('id_token') if login else None
    if client and client.identity_provider.end_session_endpoint and id_token:
        state = protocol.random_value()
        request.session[browser_session.LOGOUT_STATE_KEY] = state
        return HttpResponseRedirect(protocol.end_session_url(
            client, id_token, request.build_absolute_uri(reverse('relying_party:logged_out')), state))
    messages.info(request, gettext('You are logged out.'))
    return HttpResponseRedirect(reverse('relying_party:home'))


def logged_out(request):
    """The post_logout_redirect_uri. The state shows that the logout was started by this browser."""
    expected = request.session.pop(browser_session.LOGOUT_STATE_KEY, None)
    if expected and request.GET.get('state') == expected:
        messages.info(request, gettext('You are logged out, also at the identity provider.'))
    else:
        messages.info(request, gettext('You are logged out.'))
    return HttpResponseRedirect(reverse('relying_party:home'))


@never_cache
@login_required
def tokens(request):
    login, client = browser_session.current_login(request)
    if login is None:
        messages.info(request, gettext(
            'You are logged in with a password, there are no tokens. Log in with OpenID Connect.'))
        return HttpResponseRedirect(reverse('relying_party:login'))
    token_set = login['tokens']
    access_token = {'raw': token_set['access_token']}
    try:
        access_token['claims'] = jwt.decode(token_set['access_token'], options={'verify_signature': False})
    except jwt.PyJWTError:
        access_token['opaque'] = True  # not a JWT, only the identity provider knows what it means
    else:
        try:
            api_client, claims = validate_access_token(token_set['access_token'])
            access_token['api_result'] = f'Accepted by the API of this demo for the audience {api_client.client_id}.'
        except ProtocolError as e:
            access_token['api_error'] = e.description
    context = {
        'login': login,
        'client': client,
        'token_set': token_set,
        'access_token': access_token,
        'expired': token_set.get('expires_at') and token_set['expires_at'] < time.time(),
    }
    return render(request, 'tokens.html', context)


@require_POST
@never_cache
@login_required
@shows_protocol_errors
def refresh_tokens(request):
    login, client = browser_session.current_login(request)
    if login is None:
        return HttpResponseRedirect(reverse('relying_party:login'))
    browser_session.update_tokens(request, protocol.refresh(client, login['tokens']))
    messages.success(request, gettext('The tokens are refreshed.'))
    return HttpResponseRedirect(reverse('relying_party:tokens'))


def get_fresh_access_token(request, login, client):
    """The access token of the session, refreshed first if it is expired and there is a refresh token."""
    token_set = login['tokens']
    if token_set.get('expires_at') and token_set['expires_at'] < time.time() and token_set.get('refresh_token'):
        token_set = protocol.refresh(client, token_set)
        browser_session.update_tokens(request, token_set)
    return token_set['access_token']


@never_cache
@login_required
@shows_protocol_errors
def userinfo(request):
    login, client = browser_session.current_login(request)
    if login is None:
        return HttpResponseRedirect(reverse('relying_party:login'))
    access_token = get_fresh_access_token(request, login, client)
    claims, checks = protocol.fetch_userinfo(client, access_token, login['sub'])
    # "picture" is a url (Core 5.1), the g10f SSO answers with an object with the url.
    picture = claims.get('picture')
    if isinstance(picture, dict):
        picture = picture.get('url')
    # The g10f SSO only accepts an access token with the scope "picture" for changing the picture.
    granted_scope = login['tokens']['response'].get('scope') or client.scope
    context = {'client': client, 'claims': claims, 'checks': checks, 'picture': picture,
               'picture_endpoint': client.identity_provider.picture_endpoint,
               'picture_scope': 'picture' in str(granted_scope).split()}
    if context['picture_endpoint'] and context['picture_scope']:
        context['picture_max_size'] = protocol.picture_max_size(client, access_token)
    return render(request, 'userinfo.html', context)


@require_POST
@login_required
@shows_protocol_errors
def picture(request):
    """Upload or delete the picture at the g10f SSO, with the access token of the session."""
    login, client = browser_session.current_login(request)
    if login is None or not client.identity_provider.picture_endpoint:
        raise Http404('The identity provider has no picture endpoint.')
    access_token = get_fresh_access_token(request, login, client)
    if request.POST.get('action') == 'delete':
        protocol.delete_picture(client, access_token)
        request.session.pop(browser_session.NAVIGATION_KEY, None)  # the bar shows the picture too
        messages.success(request, gettext('The picture is deleted.'))
    else:
        upload = request.FILES.get('picture')
        if upload is None or not (upload.content_type or '').startswith('image/'):
            messages.error(request, gettext('Please choose an image file.'))
        elif upload.size > min(protocol.picture_max_size(client, access_token) or MAX_PICTURE_SIZE, MAX_PICTURE_SIZE):
            messages.error(request, gettext('The image is larger than the identity provider accepts.'))
        else:
            protocol.upload_picture(client, access_token, upload.read(), upload.content_type)
            request.session.pop(browser_session.NAVIGATION_KEY, None)  # the bar shows the picture too
            messages.success(request, gettext('The picture is uploaded.'))
    return HttpResponseRedirect(reverse('relying_party:userinfo'))


def user_navigation(request):
    """
    The shared navigation bar of the g10f SSO for base.html (see protocol.fetch_navigation), kept in the session for
    5 minutes so that not every page asks the SSO. None if there is none; an error only leaves the bar as without
    navigation, it is no reason to fail the page.
    """
    login, client = browser_session.current_login(request)
    if client is None or not client.identity_provider.user_navigation_uri:
        return None
    cached = request.session.get(browser_session.NAVIGATION_KEY)
    # 'navigation' in cached: an earlier development version kept another format in running sessions
    if cached and 'navigation' in cached and time.time() - cached['fetched_at'] < NAVIGATION_CACHE_SECONDS:
        return cached['navigation']
    token_set = login['tokens']
    if token_set.get('expires_at') and token_set['expires_at'] < time.time():
        return None  # the tokens page refreshes it, a page view should not
    try:
        navigation = protocol.fetch_navigation(client, token_set['access_token'], login['sub'])
    except ProtocolError as e:
        logger.info('The navigation can not be loaded: %s', e)
        navigation = None
    except requests.RequestException as e:
        logger.info('The navigation can not be loaded: %s', type(e).__name__)
        navigation = None
    # An error is kept too, so a broken API is not asked on every page.
    request.session[browser_session.NAVIGATION_KEY] = {'fetched_at': time.time(), 'navigation': navigation}
    return navigation


def profile(request):
    login, client = browser_session.current_login(request)
    if client is None or not client.identity_provider.profile_uri:
        raise Http404('The identity provider has no profile page.')
    return HttpResponseRedirect(client.identity_provider.profile_uri)


# --- device flow (RFC 8628) --------------------------------------------------------------------------------------

@never_cache
def device(request):
    device = request.session.get(browser_session.DEVICE_KEY)
    if device and device['expires_at'] < time.time():
        request.session.pop(browser_session.DEVICE_KEY)
        device = None
    return render(request, 'device.html', {'clients': active_clients(Client.FLOW_DEVICE), 'device': device})


@require_POST
@shows_protocol_errors
def device_start(request, client_id):
    client = get_object_or_404(Client, pk=client_id, flow=Client.FLOW_DEVICE, is_active=True,
                               identity_provider__is_active=True)
    request.session[browser_session.DEVICE_KEY] = protocol.start_device_authorization(client)
    return HttpResponseRedirect(reverse('relying_party:device'))


@require_POST
def device_cancel(request):
    request.session.pop(browser_session.DEVICE_KEY, None)
    return HttpResponseRedirect(reverse('relying_party:device'))


@require_POST
@never_cache
def device_poll(request):
    """Called by the device page every few seconds, sends at most one token request per interval."""
    device = request.session.get(browser_session.DEVICE_KEY)
    if device is None:
        return JsonResponse({'status': 'error', 'description': 'There is no running device login.'})
    if device['expires_at'] < time.time():
        request.session.pop(browser_session.DEVICE_KEY)
        return JsonResponse({'status': 'error', 'description': 'The code has expired, please start again.'})
    if time.time() < device['next_poll']:
        return JsonResponse({'status': 'pending', 'interval': device['interval']})

    client = get_object_or_404(Client.objects.select_related('identity_provider'), pk=device['client'])
    try:
        token_set = protocol.poll_device_token(client, device)
        if token_set is not None:
            request.session.pop(browser_session.DEVICE_KEY)
            user = finish_login(request, client, token_set)
            messages.success(request, gettext('Welcome %(user)s, you are logged in with %(provider)s.') % {
            'user': user, 'provider': client.identity_provider})
            return JsonResponse({'status': 'done', 'next': reverse('relying_party:tokens')})
    except ProtocolError as e:
        request.session.pop(browser_session.DEVICE_KEY, None)
        return JsonResponse({'status': 'error', 'description': f'{e.error}: {e.description}'})
    except requests.RequestException:
        # The next poll tries again.
        logger.warning('The token endpoint can not be reached for the device flow.')
    device['next_poll'] = time.time() + device['interval']
    request.session.modified = True
    return JsonResponse({'status': 'pending', 'interval': device['interval']})


# --- implicit flow (legacy) ---------------------------------------------------------------------------------------

@never_cache
@shows_protocol_errors
def implicit(request):
    """
    The implicit flow returns the tokens in the fragment of the url, which only the browser sees. The script of the
    page posts them back here, so the server can check them like in the code flow.
    """
    context = {'clients': list(active_clients(Client.FLOW_IMPLICIT)) + list(active_clients(
        Client.FLOW_IMPLICIT_ID_TOKEN))}
    if request.method == 'POST':
        params = request.POST
        pending = browser_session.pop_pending(request, params.get('state'))
        client = get_object_or_404(Client.objects.select_related('identity_provider'), pk=pending['client'])
        checks = protocol.check_authentication_response(client.identity_provider, params)
        access_token = params.get('access_token') or None
        if client.flow == Client.FLOW_IMPLICIT and not access_token:
            raise ProtocolError('invalid_response', 'The response has no access_token.')
        if not params.get('id_token'):
            raise ProtocolError('invalid_response', 'The response has no id_token.')
        header, claims, id_token_checks = protocol.validate_id_token(
            client, params['id_token'], nonce=pending['nonce'], max_age=pending.get('max_age'),
            acr_values=pending.get('acr_values', ''), access_token=access_token,
            require_at_hash=client.flow == Client.FLOW_IMPLICIT)
        context.update({'client': client, 'id_token': params['id_token'], 'claims': claims,
                        'checks': checks + id_token_checks, 'access_token': access_token})
        if access_token:
            try:
                context['userinfo'], userinfo_checks = protocol.fetch_userinfo(client, access_token, claims['sub'])
            except (ProtocolError, requests.RequestException) as e:
                context['userinfo_error'] = str(e) if isinstance(e, ProtocolError) else 'not reachable'
    return render(request, 'implicit.html', context)


# --- login and logout started by the identity provider ---------------------------------------------------------

@csrf_exempt
@never_cache
@shows_protocol_errors
def initiate_login(request):
    """Core 4: Initiating Login from a Third Party, e.g. a link in the portal of the identity provider."""
    params = request.POST if request.method == 'POST' else request.GET
    client = active_clients(Client.FLOW_CODE).filter(identity_provider__issuer=params.get('iss', '')).first()
    if client is None:
        raise ProtocolError('invalid_request', 'There is no client for this issuer.')
    next_url = safe_next_url(request, params.get('target_link_uri'))
    return redirect_to_identity_provider(request, client, next_url, login_hint=params.get('login_hint'))


@xframe_options_exempt
@never_cache
def frontchannel_logout(request):
    """
    Front-Channel Logout 1.0 2: the identity provider loads this page in an iframe, with iss and sid of the session.
    The session is found by them on the server. The cookie of the session is no help: browsers send a SameSite=Lax
    cookie only to a top-level page, not to an iframe in the page of another site. So iss and sid are required
    (frontchannel_logout_session_required at the identity provider).
    """
    iss, sid = request.GET.get('iss'), request.GET.get('sid')
    if not iss or not sid:
        return HttpResponse('The parameters iss and sid are required.', status=400, content_type='text/plain')
    if not Client.objects.filter(identity_provider__issuer=iss, frontchannel_logout=True, is_active=True).exists():
        return HttpResponse('No client with front-channel logout for this issuer.', status=400,
                            content_type='text/plain')
    browser_session.delete_sessions(iss, sid=sid)
    return HttpResponse('<!DOCTYPE html><title>Logged out</title>')


@csrf_exempt
@require_POST
def backchannel_logout(request):
    """Back-Channel Logout 1.0 2.5: the identity provider posts a logout token, server to server."""
    try:
        client, claims = protocol.validate_logout_token(request.POST.get('logout_token', ''))
    except ProtocolError as e:
        logger.info('Back-channel logout rejected: %s', e)
        response = JsonResponse({'error': e.error, 'error_description': e.description}, status=400)
    else:
        count = browser_session.delete_sessions(claims['iss'], sid=claims.get('sid'), sub=claims.get('sub'))
        logger.info('Back-channel logout of %s ended %d session(s).', client, count)
        response = HttpResponse(status=200)
    response['Cache-Control'] = 'no-store'
    return response


@xframe_options_sameorigin
@never_cache
def session_iframe(request):
    """
    Session Management 1.0 3.1: the RP iframe, which asks the OP iframe whether the session has changed. On "changed"
    it starts a silent login (prompt=none, section 5). The OP iframe compares with its own cookie; if the browser
    hides that cookie from an iframe of another site (third-party cookies, e.g. on localhost), the answer is always
    "changed". A "changed" right after a silent login therefore means the checks can't work: the script posts here,
    and the checks stay off for this login (base.html doesn't load the iframes any more).
    """
    login, client = browser_session.current_login(request)
    if request.method == 'POST':
        if login:
            browser_session.stop_session_checks(request)
        return HttpResponse(status=204)
    if not login or not client.session_management or not client.identity_provider.check_session_iframe \
            or not login.get('session_state') or login.get('session_checks_stopped'):
        return HttpResponse('<!DOCTYPE html><title>No session</title>')
    context = {
        'client': client,
        'session_state': login['session_state'],
        # The answers of the OP iframe are only accepted from the origin of the identity provider.
        'op_origin': '{0.scheme}://{0.netloc}'.format(urlsplit(client.identity_provider.check_session_iframe)),
        'check_url': reverse('relying_party:start_login', args=[client.pk]) + '?prompt=none',
        'recently_checked': time.time() - request.session.get(browser_session.SILENT_LOGIN_KEY, 0)
        < SILENT_LOGIN_LOOP_SECONDS,
    }
    return render(request, 'session_iframe.html', context)


# --- the demo as API ----------------------------------------------------------------------------------------------

@csrf_exempt
@bearer_token_required
def api_test(request):
    return JsonResponse({'api_client': str(request.api_client), 'claims': request.access_token_claims})
