"""
Metadata and signing keys of an identity provider.

- OpenID Connect Discovery 1.0: the button "Load from discovery document" in the admin puts the endpoints of the
  document into the form. At runtime only the endpoints stored in the database are used.
- The signing keys (JWKS) are loaded at runtime and cached. A token with an unknown "kid" loads them again once,
  that is how a key rotation of the identity provider is picked up.
"""
import hashlib
import logging

import jwt
import requests
from django.core.cache import cache
from jwt import PyJWK

from .errors import ProtocolError

logger = logging.getLogger(__name__)

# Seconds to wait for the identity provider, without a limit a hanging provider would block the workers.
REQUEST_TIMEOUT = 10
# For the optional calls while a page is built (navigation bar, picture size): a slow SSO must not hold up the page.
OPTIONAL_REQUEST_TIMEOUT = 3
JWKS_CACHE_SECONDS = 3600

# Discovery member -> field of IdentityProvider
ENDPOINT_FIELDS = {
    'authorization_endpoint': 'authorization_endpoint',
    'token_endpoint': 'token_endpoint',
    'userinfo_endpoint': 'userinfo_endpoint',
    'jwks_uri': 'jwks_uri',
    'end_session_endpoint': 'end_session_endpoint',
    'device_authorization_endpoint': 'device_authorization_endpoint',
    'check_session_iframe': 'check_session_iframe',
}


WELL_KNOWN_PATH = '/.well-known/openid-configuration'


def discovery_url(issuer):
    # Discovery 4.1: a trailing slash of the issuer is removed before the well-known path is appended.
    return issuer.rstrip('/') + WELL_KNOWN_PATH


def fetch_discovery_document(url, verify_tls=True):
    """Loads the discovery document from its url (<issuer>/.well-known/openid-configuration) and checks it."""
    if not url.startswith('https://') and not url.startswith('http://') or not url.endswith(WELL_KNOWN_PATH):
        raise ProtocolError('invalid_discovery',
                            f'The discovery URL must be an http(s) URL ending with {WELL_KNOWN_PATH}.')
    # No redirects: the admin button may only reach the url it shows, not a host a redirect points to.
    response = requests.get(url, verify=verify_tls, timeout=REQUEST_TIMEOUT, allow_redirects=False,
                            headers={'Accept': 'application/json'})
    if response.status_code != 200:
        raise ProtocolError('invalid_discovery',
                            f'The discovery document answered with HTTP status {response.status_code}.')
    try:
        document = response.json()
    except ValueError:
        raise ProtocolError('invalid_discovery', 'The discovery document is not JSON.')
    if not isinstance(document, dict):
        raise ProtocolError('invalid_discovery', 'The discovery document is not a JSON object.')
    # Discovery 4.3: the issuer in the document MUST be the one the url was built from. Otherwise another provider
    # could hand out tokens in the name of this one.
    issuer = document.get('issuer')
    if not isinstance(issuer, str) or discovery_url(issuer) != url:
        raise ProtocolError('invalid_discovery',
                            f'The discovery document is for the issuer {issuer!r}, which does not belong to {url}.')
    return document


def endpoints_of(document):
    """
    The values of the document for all fields of IdentityProvider it describes. An endpoint the document doesn't
    have is empty, so the button in the admin replaces every value.
    """
    values = {}
    for member, field in ENDPOINT_FIELDS.items():
        value = document.get(member)
        values[field] = value if isinstance(value, str) else ''
    values['require_iss_parameter'] = document.get('authorization_response_iss_parameter_supported') is True
    return values


def _jwks_cache_key(identity_provider):
    # The uri is part of the key, so a changed jwks_uri never uses the keys of the old one.
    uri_hash = hashlib.sha256(identity_provider.jwks_uri.encode()).hexdigest()
    return f'jwks_{identity_provider.pk}_{uri_hash}'


def _load_jwks(identity_provider):
    if not identity_provider.jwks_uri:
        raise ProtocolError('signing_error', f'The identity provider {identity_provider} has no jwks_uri.')
    response = requests.get(identity_provider.jwks_uri, verify=identity_provider.verify_tls, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        raise ProtocolError('signing_error', f'The JWKS answered with HTTP status {response.status_code}.')
    try:
        data = response.json()
    except ValueError:
        raise ProtocolError('signing_error', 'The JWKS is not JSON.')
    if not isinstance(data, dict) or not isinstance(data.get('keys'), list):
        raise ProtocolError('signing_error', 'The JWKS has no list of keys.')
    cache.set(_jwks_cache_key(identity_provider), data, JWKS_CACHE_SECONDS)
    return data


# The key type (RFC 7518 6.1) that each family of signature algorithms needs.
KEY_TYPES = {'RS': 'RSA', 'PS': 'RSA', 'ES': 'EC', 'Ed': 'OKP'}


def _find_key(jwks, kid, alg):
    """
    The key for a token. Keys for encryption (use "enc") and keys of another type are skipped; "use" itself is
    optional (RFC 7517 4.2), and a key with an "alg" member is only used for that algorithm (RFC 7517 4.4).
    Without a kid in the token there must be exactly one matching key. Keys that can't be read are skipped.
    """
    candidates = []
    for data in jwks['keys']:
        if not isinstance(data, dict):
            continue
        if data.get('use') not in (None, 'sig'):
            continue
        if data.get('alg') not in (None, alg):
            continue
        if data.get('kty') != KEY_TYPES.get(alg[:2]):
            continue
        if kid is not None and data.get('kid') != kid:
            continue
        candidates.append(data)
    if len(candidates) != 1:
        return None
    try:
        return PyJWK.from_dict(candidates[0], algorithm=alg).key
    except (jwt.PyJWTError, ValueError, TypeError) as e:
        raise ProtocolError('signing_error', f'The key {kid!r} of the identity provider can not be used: {e}')


def get_signing_key(identity_provider, kid, alg):
    """The public key of the identity provider for a token with this kid and algorithm."""
    # kid and alg come from an unverified token header and can be anything JSON allows.
    if not isinstance(alg, str) or (kid is not None and not isinstance(kid, str)):
        raise ProtocolError('signing_error', 'The kid or alg of the token header is not a string.')
    jwks = cache.get(_jwks_cache_key(identity_provider))
    key = _find_key(jwks, kid, alg) if jwks else None
    if key is None:
        # Not in the cache: the identity provider may have rotated its keys (Core 10.1.1), so they are loaded again.
        # A made-up kid (e.g. a token sent to the API without login) also makes this site load them, which is
        # accepted for a demo: it costs one request to the JWKS of the identity provider, no more.
        key = _find_key(_load_jwks(identity_provider), kid, alg)
    if key is None:
        # repr keeps line breaks of the kid out of the message and the log.
        raise ProtocolError('signing_error', f'The JWKS has no single key for kid {kid!r} and algorithm {alg}.')
    return key
