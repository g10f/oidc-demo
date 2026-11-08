"""
Configuration of the identity providers (OpenID Providers) and of the clients registered there.

The fields are grouped like in the admin:
- standard: what OpenID Connect Discovery and Core define and every provider needs
- optional: spec features a provider or client may support
- legacy: quirks of older providers. They stay configurable because existing providers have to support them for a
  long time. Options that are broken from a security point of view (password grant, oob redirect) are gone.
The protocol options (endpoints, algorithms, legacy quirks) are only read in protocol.py, so the views don't need to
know about any special case.
"""
import json

from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models


def validate_json_object(value):
    try:
        data = json.loads(value)
    except ValueError as e:
        raise ValidationError(f'This is not valid JSON: {e}')
    if not isinstance(data, dict):
        raise ValidationError('The value must be a JSON object.')


class IdentityProvider(models.Model):
    # standard
    name = models.CharField(max_length=255, unique=True)
    issuer = models.CharField(
        max_length=2048, unique=True,
        help_text='Issuer identifier, exactly as in the "iss" claim. The discovery document is '
                  '<issuer>/.well-known/openid-configuration (OpenID Connect Discovery 4.1).')
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0, help_text='Overrides the alphabetic order on the login pages.')
    authorization_endpoint = models.URLField(max_length=2048, blank=True)
    token_endpoint = models.URLField(max_length=2048, blank=True)
    userinfo_endpoint = models.URLField(max_length=2048, blank=True)
    jwks_uri = models.URLField('JWKS URI', max_length=2048, blank=True)

    # optional
    home_uri = models.URLField(
        'home URI', max_length=2048, blank=True,
        help_text='Start page of the identity provider, linked from its name on the left of the navigation bar.')
    end_session_endpoint = models.URLField(
        max_length=2048, blank=True, help_text='RP-Initiated Logout 1.0, used for the logout when set.')
    device_authorization_endpoint = models.URLField(
        max_length=2048, blank=True, help_text='Device Authorization Grant (RFC 8628).')
    check_session_iframe = models.URLField(
        max_length=2048, blank=True,
        help_text='Session Management 1.0. Needs third-party cookies at the identity provider, so it does not work '
                  'reliably in Safari and Firefox.')
    require_iss_parameter = models.BooleanField(
        'require the iss parameter', default=False,
        help_text='RFC 9207: the authorization response must contain "iss". Taken from '
                  '"authorization_response_iss_parameter_supported" of the discovery document.')
    profile_uri = models.URLField(
        max_length=2048, blank=True, help_text='Page of the identity provider where users change their profile.')
    picture_endpoint = models.URLField(
        max_length=2048, blank=True,
        help_text='API of the g10f SSO to upload (POST) and delete (DELETE) the picture of the user. The access token '
                  'of the login is sent there and needs the scope "picture". Without it, the user info page only '
                  'shows the "picture" claim.')
    user_navigation_uri = models.URLField(
        max_length=2048, blank=True,
        help_text='Navigation API of the g10f SSO (…/api/v2/users/me/navigation/). The access token of the login is '
                  'sent there, the applications of the user are shown in the navigation bar.')
    strong_acr_values = models.CharField(
        'strong acr values', max_length=255, blank=True,
        help_text='Space separated acr values of the ID token that mean a strong (two factor) authentication, shown '
                  'with a shield next to the user. acr values are defined by each identity provider, the g10f SSO '
                  'uses "2". An amr with "mfa" (RFC 8176) counts too.')
    # legacy
    verify_tls = models.BooleanField(
        'verify TLS', default=True,
        help_text='Turning it off disables the TLS verification of all requests to this identity provider, also for '
                  'its signing keys. Only for development.')
    userinfo_token_in_query = models.BooleanField(
        'access token in the userinfo query', default=False,
        help_text='Sends the access token as "access_token" query parameter instead of the Authorization header. '
                  'RFC 6750 discourages it: the token ends up in logs.')
    check_roles = models.BooleanField(
        default=False, help_text='Users without any role in the roles claim are refused.')
    extend_access_uri = models.URLField(
        max_length=2048, blank=True, help_text='Where users without a role can ask for access (with check roles).')

    class Meta:
        ordering = ['order', 'name']

    def __str__(self):
        return self.name


class Client(models.Model):
    FLOW_CODE = 'code'
    FLOW_DEVICE = 'device'
    FLOW_IMPLICIT = 'id_token token'
    FLOW_IMPLICIT_ID_TOKEN = 'id_token'
    FLOW_CHOICES = [
        (FLOW_CODE, 'Authorization code flow with PKCE'),
        (FLOW_DEVICE, 'Device authorization grant (RFC 8628)'),
        (FLOW_IMPLICIT, 'Implicit flow, id_token token (legacy)'),
        (FLOW_IMPLICIT_ID_TOKEN, 'Implicit flow, id_token only (legacy)'),
    ]
    AUTH_BASIC = 'client_secret_basic'
    AUTH_POST = 'client_secret_post'
    AUTH_NONE = 'none'
    AUTH_METHOD_CHOICES = [
        (AUTH_BASIC, 'client_secret_basic (HTTP Basic)'),
        (AUTH_POST, 'client_secret_post (in the request body)'),
        (AUTH_NONE, 'none (public client)'),
    ]
    ALG_CHOICES = [(alg, alg) for alg in (
        'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA',
        'HS256', 'HS384', 'HS512')]

    # standard
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE, related_name='clients')
    name = models.CharField(max_length=255, blank=True, help_text='Shown on the login button.')
    is_active = models.BooleanField(default=True)
    flow = models.CharField(max_length=32, choices=FLOW_CHOICES, default=FLOW_CODE)
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255, blank=True)
    token_endpoint_auth_method = models.CharField(
        max_length=32, choices=AUTH_METHOD_CHOICES, default=AUTH_BASIC,
        help_text='A client without secret always uses "none".')
    scope = models.CharField(
        max_length=2048, default='openid profile email',
        help_text='Requested at the identity provider.')
    id_token_signed_response_alg = models.CharField(
        'ID token signing algorithm', max_length=16, choices=ALG_CHOICES, default='RS256',
        help_text='The only algorithm accepted for the ID token. HS* uses the client secret as key.')
    redirect_uri = models.CharField(
        max_length=2048, blank=True,
        help_text='Path or URL of the callback. Empty means /oidc/callback/ of this site.')

    # optional parameters of the authentication request (OpenID Connect Core 3.1.2.1, 5.5)
    prompt = models.CharField(max_length=255, blank=True)
    max_age = models.PositiveIntegerField(
        blank=True, null=True, help_text='Seconds. The auth_time of the ID token is checked against it.')
    acr_values = models.CharField(
        max_length=255, blank=True, help_text='The acr of the ID token is checked against it.')
    ui_locales = models.CharField(max_length=255, blank=True)
    claims_locales = models.CharField(max_length=255, blank=True)
    claims = models.TextField(blank=True, validators=[validate_json_object], help_text='JSON object (Core 5.5).')
    extra_authorization_params = models.TextField(
        blank=True, validators=[validate_json_object],
        help_text='JSON object with additional parameters, e.g. {"kc_idp_hint": "google"} for Keycloak.')
    roles_claim = models.CharField(
        max_length=255, blank=True, default='roles',
        help_text='Claim of the ID token with the roles (list or space separated). Empty: roles are not read.')
    staff_roles = models.CharField(
        max_length=2048, blank=True,
        help_text='Space separated roles that give staff status in this demo (admin login). Leave it empty unless '
                  'you trust every administrator of this identity provider. The status is set at each login.')
    superuser_roles = models.CharField(
        max_length=2048, blank=True, help_text='Space separated roles that give superuser status in this demo.')

    # session and logout (OpenID Connect Session Management, Front-Channel and Back-Channel Logout 1.0)
    session_max_age = models.PositiveIntegerField(
        blank=True, null=True,
        help_text='Seconds after the login at which the session in this demo ends; a silent login (Session '
                  'Management) starts it again. It also ends when the browser is closed, and after 2 weeks at the '
                  'latest (SESSION_COOKIE_AGE). Empty: only when the browser is closed. The session at the identity '
                  'provider is not affected, a new login there may not ask for the password.')
    session_management = models.BooleanField(
        default=False,
        help_text='Polls the check_session_iframe of the identity provider. Needs third-party cookies, so it does '
                  'not work reliably in Safari and Firefox.')
    frontchannel_logout = models.BooleanField(
        default=False,
        help_text='The identity provider loads the front-channel logout URI in an iframe, with iss and sid '
                  '(register the client with frontchannel_logout_session_required). Needs third-party cookies at '
                  'the identity provider, so it does not work reliably in Safari and Firefox.')
    backchannel_logout = models.BooleanField(
        default=False, help_text='The identity provider posts a logout token to the back-channel logout URI.')
    backchannel_logout_session_required = models.BooleanField(
        default=False, help_text='The logout token must contain a sid.')

    # legacy
    disable_pkce = models.BooleanField(
        'disable PKCE', default=False,
        help_text='Only for identity providers that reject the code_challenge parameter. RFC 9700 requires PKCE.')

    class Meta:
        ordering = ['identity_provider', 'name']

    def __str__(self):
        if self.name:
            return f'{self.identity_provider} - {self.name}'
        return str(self.identity_provider)

    @property
    def auth_method(self):
        if not self.client_secret:
            return self.AUTH_NONE
        return self.token_endpoint_auth_method


class ApiClient(models.Model):
    """A resource server (API) of this demo, the access tokens for it are JWTs with its client_id as audience."""
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE, related_name='api_clients')
    client_id = models.CharField(
        max_length=255,
        help_text='Expected "aud" of the access token. The g10f SSO sets the client_id of the requesting client.')
    is_active = models.BooleanField(default=True)
    require_jwt_access_token_type = models.BooleanField(
        'require typ at+jwt', default=True,
        help_text='RFC 9068, keeps ID tokens with the same aud out. Off for the g10f SSO, it doesn\'t set typ.')

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['identity_provider', 'client_id'], name='unique_api_client'),
        ]

    def __str__(self):
        return f'{self.identity_provider} - {self.client_id}'


class User(AbstractUser):
    """A user is identified by its identity provider and the "sub" claim (OpenID Connect Core 5.7)."""
    # The username is built from identity provider and sub, which can be longer than the 150 characters of Django.
    username = models.CharField(max_length=300, unique=True)
    identity_provider = models.ForeignKey(
        IdentityProvider, on_delete=models.CASCADE, null=True, blank=True, related_name='users')
    sub = models.CharField(max_length=255, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['identity_provider', 'sub'], name='unique_identity'),
        ]

    def __str__(self):
        return self.get_full_name() or self.email or self.username
