"""
The demo as resource server: an API that accepts JWT access tokens of the configured identity providers
(RFC 6750 bearer tokens, RFC 9068 JWT profile for access tokens).
"""
import logging
from functools import wraps

import jwt
import requests
from django.http import JsonResponse

from .discovery import get_signing_key
from .errors import ProtocolError
from .models import ApiClient
from .protocol import LEEWAY, audience_list

logger = logging.getLogger(__name__)

# Access tokens are signed by the identity provider with its own keys, never with a shared secret.
ASYMMETRIC_ALGORITHMS = {'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'}


def validate_access_token(token):
    """Returns the ApiClient and the claims of a JWT access token, raises ProtocolError."""
    try:
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={'verify_signature': False})
    except jwt.PyJWTError as e:
        raise ProtocolError('invalid_token', f'The access token is no JWT: {e}')
    alg = header.get('alg')
    # The header is not verified yet, alg can be any JSON value, also an unhashable list.
    if not isinstance(alg, str) or alg not in ASYMMETRIC_ALGORITHMS:
        raise ProtocolError('invalid_token', f'The algorithm {alg!r} is not accepted.')
    api_client = ApiClient.objects.select_related('identity_provider').filter(
        identity_provider__issuer=str(unverified.get('iss')), identity_provider__is_active=True,
        client_id__in=audience_list(unverified), is_active=True).first()
    if api_client is None:
        raise ProtocolError('invalid_token', 'No API client of this demo matches iss and aud of the token.')
    # RFC 9068 4: without the typ check an ID token with the same audience would pass as access token.
    if api_client.require_jwt_access_token_type and str(header.get('typ', '')).lower() not in (
            'at+jwt', 'application/at+jwt'):
        raise ProtocolError('invalid_token', f'The token has the typ {header.get("typ")!r}, not "at+jwt".')
    try:
        key = get_signing_key(api_client.identity_provider, header.get('kid'), alg)
        claims = jwt.decode(token, key=key, algorithms=[alg], audience=api_client.client_id,
                            issuer=api_client.identity_provider.issuer, leeway=LEEWAY,
                            options={'require': ['iss', 'sub', 'aud', 'exp']})
    except jwt.PyJWTError as e:
        raise ProtocolError('invalid_token', f'The access token is not valid: {e}')
    except requests.RequestException:
        raise ProtocolError('temporarily_unavailable', 'The keys of the identity provider can not be loaded.')
    return api_client, claims


def bearer_token_required(view):
    """
    Only the Authorization header is accepted (RFC 6750 2.1): a token in the query string ends up in logs and the
    browser history.
    """

    @wraps(view)
    def wrapped_view(request, *args, **kwargs):
        scheme, _, token = request.headers.get('Authorization', '').partition(' ')
        if scheme.lower() != 'bearer' or not token:
            return unauthorized('invalid_request', 'The request has no bearer token in the Authorization header.')
        try:
            request.api_client, request.access_token_claims = validate_access_token(token.strip())
        except ProtocolError as e:
            logger.info('The access token was rejected: %s', e)
            return unauthorized(e.error, e.description)
        return view(request, *args, **kwargs)

    return wrapped_view


def unauthorized(error, description):
    response = JsonResponse({'error': error, 'error_description': description}, status=401)
    # RFC 6750 3: the reason is also given in the WWW-Authenticate header. Its description may only contain
    # printable ASCII without the quote and the backslash.
    header_description = ''.join(char for char in description if ' ' <= char <= '~' and char not in '"\\')
    response['WWW-Authenticate'] = f'Bearer error="{error}", error_description="{header_description}"'
    return response
