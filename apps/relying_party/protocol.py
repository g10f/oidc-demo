"""
The OpenID Connect protocol of the relying party, one function per step, each with the section of the spec.

Specs:
- OpenID Connect Core 1.0 (Core), incl. errata 2
- RFC 6749 OAuth 2.0, RFC 7636 PKCE, RFC 9207 iss in the authorization response, RFC 9700 OAuth 2.0 security BCP
- RFC 8628 Device Authorization Grant
- OpenID Connect RP-Initiated Logout 1.0, Back-Channel Logout 1.0

Only this module reads the options of IdentityProvider and Client. Every function either returns its result or
raises ProtocolError, the views only decide what to show. The checks that passed are returned as a list, so the
token page can show what was verified.
"""
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

import jwt
import requests
from django.core.cache import cache
from django.utils.crypto import constant_time_compare

from .discovery import OPTIONAL_REQUEST_TIMEOUT, REQUEST_TIMEOUT, get_signing_key
from .errors import ProtocolError
from .models import Client

# Allowed clock difference in seconds between this server and the identity provider.
LEEWAY = 60
DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'


def check(name, detail, result='ok'):
    """One line of the list of checks on the token page. result is "ok" or "warning"."""
    return {'name': name, 'detail': detail, 'result': result}


def add_query_parameters(url, params):
    """Adds parameters to a url that may already have a query (Core 3.1.2.1 allows that for the endpoints)."""
    scheme, netloc, path, query, fragment = urlsplit(url)
    query_params = parse_qsl(query, keep_blank_values=True)
    query_params += [(key, value) for key, value in params.items() if value is not None]
    return urlunsplit((scheme, netloc, path, urlencode(query_params), fragment))


def is_http_url(value):
    """Only http(s) urls from the identity provider become links, a javascript: url must not."""
    return isinstance(value, str) and (value.startswith('https://') or value.startswith('http://'))


def audience_list(claims):
    """The aud claim of an unverified token as list of strings (aud can be a string or a list, RFC 7519 4.1.3)."""
    audiences = claims.get('aud')
    audiences = audiences if isinstance(audiences, list) else [audiences]
    return [aud for aud in audiences if isinstance(aud, str)]


def random_value():
    return secrets.token_urlsafe(32)


def code_challenge(code_verifier):
    # RFC 7636 4.2: S256, the plain method gives no protection if the request is read.
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


# --- 1. authentication request (Core 3.1.2.1, 3.2.2.1) ---------------------------------------------------------

def build_authentication_request(client, redirect_uri, prompt=None, login_hint=None, id_token_hint=None):
    """
    Returns the url to send the browser to, the state and what the callback needs to check the response
    (stored in the session under the state, see browser_session.py).
    """
    if not client.identity_provider.authorization_endpoint:
        raise ProtocolError('invalid_configuration',
                            f'The identity provider {client.identity_provider} has no authorization endpoint.')
    state = random_value()  # RFC 6749 10.12: binds the response to this browser, it is kept in the session
    nonce = random_value()  # Core 3.1.2.1: binds the ID token to this request
    pending = {
        'client': client.pk,
        'nonce': nonce,
        'redirect_uri': redirect_uri,
        'max_age': client.max_age,
        'acr_values': client.acr_values,
        'prompt': prompt or client.prompt,
        'created': time.time(),
    }

    # The extra parameters come first, so they can never replace one of the protocol parameters below.
    params = json.loads(client.extra_authorization_params) if client.extra_authorization_params else {}
    params.update({
        'response_type': client.flow,
        'client_id': client.client_id,
        'redirect_uri': redirect_uri,
        'scope': client.scope,
        'state': state,
        'nonce': nonce,
        'prompt': prompt or client.prompt or None,
        'max_age': client.max_age,
        'acr_values': client.acr_values or None,
        'ui_locales': client.ui_locales or None,
        'claims_locales': client.claims_locales or None,
        'claims': client.claims or None,
        'login_hint': login_hint,
        'id_token_hint': id_token_hint,
    })
    # PKCE (RFC 7636) for the code flow, RFC 9700 2.1.1 requires it also for confidential clients.
    if client.flow == Client.FLOW_CODE and not client.disable_pkce:
        code_verifier = secrets.token_urlsafe(64)
        pending['code_verifier'] = code_verifier
        params['code_challenge'] = code_challenge(code_verifier)
        params['code_challenge_method'] = 'S256'
    return add_query_parameters(client.identity_provider.authorization_endpoint, params), state, pending


# --- 2. authentication response (Core 3.1.2.5, 3.1.2.6, RFC 9207) ------------------------------------------------

def check_authentication_response(identity_provider, params):
    """The state was already matched with the session. Returns the checks, raises the error of the response."""
    checks = []
    # RFC 9207 2.4: the iss parameter tells which identity provider answered. It protects against mix-up attacks,
    # where a malicious provider gets the code of another one.
    iss = params.get('iss')
    if iss is None:
        if identity_provider.require_iss_parameter:
            raise ProtocolError('invalid_response', 'The authentication response has no iss parameter (RFC 9207).')
    elif iss != identity_provider.issuer:
        raise ProtocolError('invalid_response',
                            f'The response comes from the issuer {iss!r}, but the login was started at '
                            f'{identity_provider.issuer!r} (RFC 9207).')
    else:
        checks.append(check('iss parameter', 'The iss of the response is the issuer of the identity provider '
                                             '(RFC 9207).'))
    if params.get('error'):
        # RFC 6749 4.1.2.1, Core 3.1.2.6
        raise ProtocolError(params['error'], params.get('error_description', ''))
    return checks


# --- 3. token endpoint (Core 3.1.3, RFC 6749 4.1.3, 6, RFC 8628 3.4) -------------------------------------------

def _post_to_endpoint(client, url, data):
    """A POST with client authentication (Core 9) to the token or device authorization endpoint."""
    data = dict(data)
    headers = {'Accept': 'application/json'}
    method = client.auth_method
    if method == Client.AUTH_BASIC:
        # RFC 6749 2.3.1: id and secret are form-urlencoded before they are put into the Basic header.
        credentials = f'{quote_plus(client.client_id)}:{quote_plus(client.client_secret)}'
        headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode('ascii')
    elif method == Client.AUTH_POST:
        data['client_id'] = client.client_id
        data['client_secret'] = client.client_secret
    else:
        data['client_id'] = client.client_id

    response = requests.post(url, data=data, headers=headers, verify=client.identity_provider.verify_tls,
                             timeout=REQUEST_TIMEOUT)
    content_type = response.headers.get('Content-Type', '').split(';')[0].strip()
    try:
        if content_type in ('text/plain', 'application/x-www-form-urlencoded'):
            # Some old providers answer form-encoded instead of JSON (RFC 6749 5.1 requires JSON).
            content = dict(parse_qsl(response.text))
        else:
            content = response.json()
    except ValueError:
        raise ProtocolError('invalid_response',
                            f'The identity provider answered with HTTP status {response.status_code} and no JSON.')
    if not isinstance(content, dict):
        raise ProtocolError('invalid_response', 'The answer of the identity provider is not a JSON object.')
    # RFC 6749 5.2: errors come with status 400 (or 401) and an error member.
    if content.get('error') or response.status_code != 200:
        raise ProtocolError(str(content.get('error') or f'http_{response.status_code}'),
                            str(content.get('error_description', '')))
    return content


def token_request(client, data, nonce=None, max_age=None, acr_values='', previous=None):
    """Sends a token request and validates the answer. Returns the token set that is stored in the session."""
    response = _post_to_endpoint(client, client.identity_provider.token_endpoint, data)
    if not isinstance(response.get('access_token'), str):
        raise ProtocolError('invalid_response', 'The token response has no access_token.')
    checks = []
    # RFC 6749 7.1: the client must understand the token type, this demo only uses bearer tokens (RFC 6750).
    if str(response.get('token_type', '')).lower() == 'bearer':
        checks.append(check('token_type', 'The access token is a bearer token (RFC 6750).'))
    else:
        checks.append(check('token_type', f'The token type is {response.get("token_type")!r}, not "Bearer".',
                            'warning'))

    try:
        expires_in = int(response.get('expires_in', 0))
    except (TypeError, ValueError):
        expires_in = 0
    token_set = {
        'response': response,
        'access_token': response['access_token'],
        'refresh_token': response.get('refresh_token'),
        'expires_at': time.time() + expires_in if expires_in else None,
        'received_at': time.time(),
        'grant_type': data['grant_type'],
    }

    id_token = response.get('id_token')
    if id_token:
        _, claims, id_token_checks = validate_id_token(
            client, id_token, nonce=nonce, max_age=max_age, acr_values=acr_values,
            access_token=response['access_token'], previous_claims=previous['id_token_claims'] if previous else None)
        token_set.update({'id_token': id_token, 'id_token_claims': claims})
        checks += id_token_checks
    elif previous:
        # Core 12.2: a refresh response doesn't need to contain a new ID token, the old one stays valid.
        token_set.update({key: previous.get(key) for key in ('id_token', 'id_token_claims')})
        checks.append(check('id_token', 'The refresh response has no new ID token, the previous one is kept.'))
    elif data['grant_type'] != 'refresh_token' and 'openid' in client.scope.split():
        # Core 3.1.3.3: the token response of an OpenID Connect request contains an ID token.
        raise ProtocolError('invalid_response', 'The token response has no id_token.')

    if previous and not token_set['refresh_token']:
        # RFC 6749 6: without a new refresh token the old one is used again.
        token_set['refresh_token'] = previous.get('refresh_token')
    token_set['checks'] = checks
    return token_set


def exchange_code(client, code, pending):
    """Core 3.1.3.1: the code from the callback against the tokens, with the PKCE code verifier."""
    data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': pending['redirect_uri']}
    if pending.get('code_verifier'):
        data['code_verifier'] = pending['code_verifier']
    return token_request(client, data, nonce=pending['nonce'], max_age=pending.get('max_age'),
                         acr_values=pending.get('acr_values', ''))


def refresh(client, token_set):
    """Core 12, RFC 6749 6. Without scope the identity provider grants the same scope as before."""
    if not token_set.get('refresh_token'):
        raise ProtocolError('invalid_request', 'There is no refresh token, request the scope offline_access.')
    data = {'grant_type': 'refresh_token', 'refresh_token': token_set['refresh_token']}
    return token_request(client, data, previous=token_set)


# --- 4. ID token validation (Core 3.1.3.7, 3.2.2.11, 12.2) -----------------------------------------------------

def _hash_half(value, alg):
    """at_hash (Core 3.1.3.6): left half of the hash of the token, with the hash function of the signature."""
    if alg == 'EdDSA':
        digest = hashlib.sha512(value.encode('ascii')).digest()  # Ed25519, the usual curve
    else:
        digest = hashlib.new('sha' + alg[2:], value.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest[:len(digest) // 2]).rstrip(b'=').decode('ascii')


def _verification_key(client, header):
    alg = header.get('alg')
    if not isinstance(alg, str):
        raise ProtocolError('invalid_id_token', 'The alg of the token header is not a string.')
    if alg != client.id_token_signed_response_alg:
        # Core 3.1.3.7 step 7, RFC 8725 3.1: the algorithm is fixed by the client, never taken from the token.
        # Otherwise "none" or an HS256 signature with the public key as secret would be accepted.
        raise ProtocolError('invalid_id_token',
                            f'The token is signed with {alg!r}, but the client expects '
                            f'{client.id_token_signed_response_alg}.')
    if alg.startswith('HS'):
        if not client.client_secret:
            raise ProtocolError('invalid_id_token', 'An HS* signature needs a client secret (Core 10.1).')
        return client.client_secret.encode()
    return get_signing_key(client.identity_provider, header.get('kid'), alg)


def validate_id_token(client, id_token, nonce=None, max_age=None, acr_values='', access_token=None,
                      require_at_hash=False, previous_claims=None):
    """Returns header, claims and the checks of an ID token, raises ProtocolError if one check fails."""
    identity_provider = client.identity_provider
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as e:
        raise ProtocolError('invalid_id_token', f'The ID token is no JWT: {e}')
    key = _verification_key(client, header)
    try:
        # Signature (step 6), iss (step 2), aud (step 3), exp (step 9) and iat (step 10)
        claims = jwt.decode(
            id_token, key=key, algorithms=[header['alg']], audience=client.client_id, issuer=identity_provider.issuer,
            leeway=LEEWAY, options={'require': ['iss', 'sub', 'aud', 'exp', 'iat']})
    except jwt.PyJWTError as e:
        raise ProtocolError('invalid_id_token', f'The ID token is not valid: {e}')
    checks = [
        check('signature', f'Signed with {header["alg"]}, verified with the key of the identity provider '
                           f'(kid {header.get("kid")!r}).'),
        check('iss', f'The issuer is {identity_provider.issuer}.'),
        check('aud', f'The audience contains the client_id {client.client_id}.'),
        check('exp, iat', f'The token is valid now (leeway {LEEWAY} seconds).'),
    ]

    # Steps 4 and 5: with more than one audience the azp tells for which client the token was issued.
    audiences = claims['aud'] if isinstance(claims['aud'], list) else [claims['aud']]
    if 'azp' in claims:
        if claims['azp'] != client.client_id:
            raise ProtocolError('invalid_id_token', f'The token was issued for the client {claims["azp"]!r} (azp).')
        checks.append(check('azp', 'The authorized party is this client.'))
    elif len(audiences) > 1:
        checks.append(check('azp', 'The token has several audiences but no azp.', 'warning'))

    # Step 11: the nonce of the request, it binds the token to the login of this browser.
    if nonce is not None:
        token_nonce = claims.get('nonce')
        if not isinstance(token_nonce, str) or not constant_time_compare(token_nonce, nonce):
            raise ProtocolError('invalid_id_token', 'The nonce of the ID token does not match the request.')
        checks.append(check('nonce', 'The nonce is the one of the authentication request.'))

    # Core 3.1.3.8, 3.2.2.9: at_hash binds the access token to the ID token. In the implicit flow it is required.
    if access_token:
        if 'at_hash' in claims:
            if not constant_time_compare(str(claims['at_hash']), _hash_half(access_token, header['alg'])):
                raise ProtocolError('invalid_id_token', 'The at_hash does not match the access token.')
            checks.append(check('at_hash', 'The access token belongs to this ID token.'))
        elif require_at_hash:
            raise ProtocolError('invalid_id_token', 'The ID token has no at_hash (Core 3.2.2.10).')

    # Step 13: with max_age the identity provider must say when the user authenticated.
    if max_age is not None:
        auth_time = claims.get('auth_time')
        if not isinstance(auth_time, (int, float)):
            raise ProtocolError('invalid_id_token', 'max_age was requested, but the ID token has no auth_time.')
        if time.time() - auth_time > max_age + LEEWAY:
            raise ProtocolError('invalid_id_token', f'The authentication is older than max_age {max_age} seconds.')
        checks.append(check('auth_time', f'The user authenticated within max_age {max_age} seconds.'))

    # Step 12: the client SHOULD check that the acr is appropriate. Many providers answer with another value than
    # requested, so a mismatch is only shown.
    if acr_values:
        if claims.get('acr') in acr_values.split():
            checks.append(check('acr', f'The acr {claims["acr"]!r} is one of the requested values.'))
        else:
            checks.append(check('acr', f'The acr {claims.get("acr")!r} is not one of the requested {acr_values!r}.',
                                'warning'))

    # Core 12.2: an ID token from a refresh must belong to the same authentication as the first one.
    if previous_claims:
        for name in ('iss', 'sub', 'aud', 'azp', 'auth_time'):
            if name in previous_claims and claims.get(name) != previous_claims[name]:
                raise ProtocolError('invalid_id_token', f'The {name} of the refreshed ID token has changed.')
        if 'nonce' in claims and claims['nonce'] != previous_claims.get('nonce'):
            raise ProtocolError('invalid_id_token', 'The nonce of the refreshed ID token has changed.')
        checks.append(check('refresh', 'iss, sub, aud and auth_time are the same as in the first ID token.'))
    return header, claims, checks


# --- 5. UserInfo (Core 5.3) ------------------------------------------------------------------------------------

def fetch_userinfo(client, access_token, expected_sub):
    identity_provider = client.identity_provider
    if not identity_provider.userinfo_endpoint:
        raise ProtocolError('invalid_configuration', 'The identity provider has no userinfo endpoint.')
    url = identity_provider.userinfo_endpoint
    headers = {'Accept': 'application/json, application/jwt'}
    if identity_provider.userinfo_token_in_query:
        url = add_query_parameters(url, {'access_token': access_token})  # legacy, RFC 6750 2.3
    else:
        headers['Authorization'] = f'Bearer {access_token}'  # RFC 6750 2.1
    response = requests.get(url, headers=headers, verify=identity_provider.verify_tls, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        # Core 5.3.3, RFC 6750 3: the reason is in the WWW-Authenticate header.
        raise ProtocolError('userinfo_error', f'The userinfo endpoint answered with HTTP status '
                                              f'{response.status_code} {response.headers.get("WWW-Authenticate", "")}')
    checks = []
    if response.headers.get('Content-Type', '').split(';')[0].strip() == 'application/jwt':
        claims = _decode_signed_userinfo(client, response.text)
        checks.append(check('signature', 'The user info is a signed JWT, verified with the key of the provider.'))
    else:
        try:
            claims = response.json()
        except ValueError:
            raise ProtocolError('userinfo_error', 'The user info is not JSON.')
    if not isinstance(claims, dict):
        raise ProtocolError('userinfo_error', 'The user info is not a JSON object.')
    # Core 5.3.4: the sub MUST be the one of the ID token, otherwise the answer is about another user.
    if claims.get('sub') != expected_sub:
        raise ProtocolError('userinfo_error', 'The sub of the user info is not the sub of the ID token.')
    checks.append(check('sub', 'The sub is the one of the ID token.'))
    return claims, checks


def _decode_signed_userinfo(client, token):
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get('alg')
        if alg != client.id_token_signed_response_alg:
            raise ProtocolError('userinfo_error', f'The user info is signed with {alg!r}.')
        payload = jwt.decode(token, options={'verify_signature': False})
        # Core 5.3.2: a signed answer SHOULD contain iss and aud, they are checked if present.
        return jwt.decode(
            token, key=_verification_key(client, header), algorithms=[alg], leeway=LEEWAY,
            audience=client.client_id if 'aud' in payload else None,
            issuer=client.identity_provider.issuer if 'iss' in payload else None,
            options={'verify_aud': 'aud' in payload})
    except jwt.PyJWTError as e:
        raise ProtocolError('userinfo_error', f'The signed user info is not valid: {e}')


# --- 6. Device Authorization Grant (RFC 8628) ------------------------------------------------------------------

def start_device_authorization(client):
    """RFC 8628 3.1, 3.2: returns device_code, user_code, verification_uri and the polling interval."""
    if not client.identity_provider.device_authorization_endpoint:
        raise ProtocolError('invalid_configuration', 'The identity provider has no device authorization endpoint.')
    response = _post_to_endpoint(client, client.identity_provider.device_authorization_endpoint,
                                 {'scope': client.scope})
    for member in ('device_code', 'user_code', 'verification_uri'):
        if not isinstance(response.get(member), str):
            raise ProtocolError('invalid_response', f'The device authorization response has no {member}.')
    # The page shows the uris as links, a javascript: url must not become one.
    for member in ('verification_uri', 'verification_uri_complete'):
        if member in response and not is_http_url(response[member]):
            raise ProtocolError('invalid_response', f'The {member} of the device response is no http(s) url.')
    try:
        expires_in = int(response.get('expires_in', 600))
        interval = int(response.get('interval', 5))  # RFC 8628 3.2: 5 seconds if missing
    except (TypeError, ValueError):
        raise ProtocolError('invalid_response', 'expires_in or interval of the device response is no number.')
    return {
        'client': client.pk,
        'device_code': response['device_code'],
        'user_code': response['user_code'],
        'verification_uri': response['verification_uri'],
        'verification_uri_complete': response.get('verification_uri_complete'),
        'expires_at': time.time() + expires_in,
        'interval': interval,
        'next_poll': time.time() + interval,
    }


def poll_device_token(client, device):
    """
    RFC 8628 3.4, 3.5: one token request. Returns the token set, or None while the user has not finished yet;
    "slow_down" raises the interval in the device dict by 5 seconds.
    """
    try:
        return token_request(client, {'grant_type': DEVICE_CODE_GRANT, 'device_code': device['device_code']})
    except ProtocolError as e:
        if e.error == 'authorization_pending':
            return None
        if e.error == 'slow_down':
            device['interval'] += 5
            return None
        raise  # access_denied, expired_token and every other error end the flow


# --- 7. Logout (RP-Initiated Logout 1.0 2, Back-Channel Logout 1.0 2.6) --------------------------------------------

def end_session_url(client, id_token, post_logout_redirect_uri, state):
    params = {
        'id_token_hint': id_token,  # tells the provider which session to end
        'client_id': client.client_id,  # RP-Initiated Logout 2: also when the id token is expired
        'post_logout_redirect_uri': post_logout_redirect_uri,
        'state': state,
    }
    return add_query_parameters(client.identity_provider.end_session_endpoint, params)


def validate_logout_token(logout_token):
    """Back-Channel Logout 1.0 2.6. Returns the client and the claims, raises ProtocolError."""
    try:
        header = jwt.get_unverified_header(logout_token)
        unverified = jwt.decode(logout_token, options={'verify_signature': False})
    except jwt.PyJWTError as e:
        raise ProtocolError('invalid_request', f'The logout token is no JWT: {e}')
    client = Client.objects.filter(
        identity_provider__issuer=str(unverified.get('iss')), identity_provider__is_active=True,
        client_id__in=audience_list(unverified), backchannel_logout=True, is_active=True).first()
    if client is None:
        raise ProtocolError('invalid_request', 'No client with back-channel logout matches iss and aud.')
    # 2.4: explicit typing keeps an ID token from being used as logout token.
    if 'typ' in header and header['typ'] != 'logout+jwt':
        raise ProtocolError('invalid_request', f'The typ of the logout token is {header["typ"]!r}.')
    try:
        claims = jwt.decode(
            logout_token, key=_verification_key(client, header), algorithms=[header['alg']],
            audience=client.client_id, issuer=client.identity_provider.issuer, leeway=LEEWAY,
            options={'require': ['iss', 'aud', 'iat', 'exp', 'jti']})
    except jwt.PyJWTError as e:
        raise ProtocolError('invalid_request', f'The logout token is not valid: {e}')
    except ProtocolError as e:
        raise ProtocolError('invalid_request', e.description)
    events = claims.get('events')
    if not isinstance(events, dict) or not isinstance(events.get(BACKCHANNEL_LOGOUT_EVENT), dict):
        raise ProtocolError('invalid_request', 'The logout token has no back-channel logout event.')
    if 'nonce' in claims:
        raise ProtocolError('invalid_request', 'A logout token must not contain a nonce.')
    if not claims.get('sub') and not claims.get('sid'):
        raise ProtocolError('invalid_request', 'The logout token has neither sub nor sid.')
    if client.backchannel_logout_session_required and not claims.get('sid'):
        raise ProtocolError('invalid_request', 'The logout token has no sid.')
    # 2.6 step 10 (optional): a token is only accepted once, until it expires.
    jti_hash = hashlib.sha256(f'{claims["iss"]} {claims["jti"]}'.encode()).hexdigest()
    if not cache.add(f'logout_jti_{jti_hash}', True, timeout=max(int(claims['exp'] - time.time()), 0) + LEEWAY):
        raise ProtocolError('invalid_request', 'The logout token was already used.')
    return client, claims


# --- 8. APIs of the g10f SSO (not part of any spec) -----------------------------------------------------------

def fetch_navigation(client, access_token, sub):
    """
    The shared navigation bar of the apps at the g10f SSO, from its API. It is called with the access token; a call
    from the browser (JSONP with the cookie of the SSO) would only work on the same site.
    Returns {"apps": [{"title", "href"}], "profile": {"title", "href"} or None, "picture": url or None}.
    """
    identity_provider = client.identity_provider
    response = requests.get(identity_provider.user_navigation_uri, verify=identity_provider.verify_tls,
                            timeout=OPTIONAL_REQUEST_TIMEOUT,
                            headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'})
    if response.status_code != 200:
        raise ProtocolError('navigation_error', f'The navigation answered with HTTP status {response.status_code}.')
    try:
        data = response.json()
    except ValueError:
        raise ProtocolError('navigation_error', 'The navigation is not JSON.')
    # The answer must be about the logged in user, the SSO uses the sub as id.
    if not isinstance(data, dict) or data.get('id') != sub or not isinstance(data.get('apps'), list):
        raise ProtocolError('navigation_error', 'The navigation is not the one of the logged in user.')
    apps = []
    for app in data['apps']:
        link = app.get('link') if isinstance(app, dict) else None
        if isinstance(link, dict) and link.get('global_navigation') and is_http_url(link.get('href')):
            apps.append({'title': str(link.get('title', '')), 'href': link['href']})
    profile = data.get('profile')
    if isinstance(profile, dict) and is_http_url(profile.get('href')):
        profile = {'title': str(profile.get('title', '')), 'href': profile['href']}
    else:
        profile = None
    picture = data.get('picture_30x30')
    picture = picture.get('href') if isinstance(picture, dict) and is_http_url(picture.get('href')) else None
    return {'apps': apps, 'profile': profile, 'picture': picture}



def _picture_request(client, method, access_token, **kwargs):
    identity_provider = client.identity_provider
    headers = {'Authorization': f'Bearer {access_token}', **kwargs.pop('headers', {})}
    response = requests.request(method, identity_provider.picture_endpoint, headers=headers,
                                verify=identity_provider.verify_tls, timeout=REQUEST_TIMEOUT, **kwargs)
    if response.status_code >= 400:
        # The SSO says why in error_description, e.g. "picture not in scope".
        try:
            reason = response.json().get('error_description', '')
        except (ValueError, AttributeError):
            reason = ''
        raise ProtocolError('picture_error', f'The picture endpoint answered with HTTP status {response.status_code}. '
                                             f'{reason}'.strip())


def picture_max_size(client, access_token):
    """
    The largest picture the SSO accepts in bytes (max_size of its GET answer), None if it can't be read. It is the
    same for all users of the identity provider, so it is cached for an hour.
    """
    identity_provider = client.identity_provider
    cache_key = f'picture_max_size_{identity_provider.pk}'
    max_size = cache.get(cache_key)
    if max_size is not None:
        return max_size
    try:
        response = requests.get(identity_provider.picture_endpoint, verify=identity_provider.verify_tls,
                                timeout=OPTIONAL_REQUEST_TIMEOUT,
                                headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'})
        max_size = response.json().get('max_size') if response.status_code == 200 else None
    except (requests.RequestException, ValueError, AttributeError):
        return None
    if not isinstance(max_size, int) or max_size <= 0:
        return None
    cache.set(cache_key, max_size, 3600)
    return max_size


def upload_picture(client, access_token, data, content_type):
    _picture_request(client, 'POST', access_token, data=data, headers={'Content-Type': content_type})


def delete_picture(client, access_token):
    _picture_request(client, 'DELETE', access_token)
