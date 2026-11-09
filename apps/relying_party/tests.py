import base64
import hashlib
import json
import tempfile
import time
from io import StringIO
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.urls import reverse
from jwt.algorithms import RSAAlgorithm

from . import browser_session, protocol
from .discovery import discovery_url, endpoints_of, fetch_discovery_document
from .errors import ProtocolError
from .models import ApiClient, Client, IdentityProvider, User

ISSUER = 'https://idp.example.com'
CLIENT_ID = 'demo-client'
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key())), 'kid': 'key-1', 'use': 'sig'}


def sign(claims, headers=None, key=PRIVATE_KEY, alg='RS256'):
    return jwt.encode(claims, key, algorithm=alg, headers={'kid': 'key-1', **(headers or {})})


def raw_jwt(header, claims):
    """A token with any header, also one PyJWT refuses to create. The signature is irrelevant here."""
    def encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()
    return f'{encode(header)}.{encode(claims)}.c2ln'


def id_token_claims(**claims):
    now = int(time.time())
    return {'iss': ISSUER, 'sub': 'user-1', 'aud': CLIENT_ID, 'iat': now, 'exp': now + 300, 'sid': 'sid-1',
            'given_name': 'Ada', 'family_name': 'Lovelace', 'email': 'ada@example.com', **claims}


def at_hash(access_token):
    digest = hashlib.sha256(access_token.encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b'=').decode()


class FakeResponse:
    def __init__(self, data, status_code=200, content_type='application/json', text=None):
        self.status_code = status_code
        self.headers = {'Content-Type': content_type}
        self._data = data
        self.text = text if text is not None else json.dumps(data)

    def json(self):
        if self._data is None:
            raise ValueError('no json')
        return self._data


class FakeIdentityProvider:
    """Answers the requests of the demo like an identity provider, the tests set the token response."""

    def __init__(self):
        self.token_responses = []
        self.token_requests = []
        self.userinfo = None
        self.userinfo_content_type = 'application/json'
        self.jwks = {'keys': [JWK]}
        self.jwks_requests = 0
        self.navigation = None
        self.navigation_requests = []
        self.discovery = {'issuer': ISSUER, 'authorization_endpoint': f'{ISSUER}/authorize',
                          'token_endpoint': f'{ISSUER}/token', 'jwks_uri': f'{ISSUER}/jwks',
                          'userinfo_endpoint': f'{ISSUER}/userinfo',
                          'authorization_response_iss_parameter_supported': True}

    def get(self, url, **kwargs):
        if url == f'{ISSUER}/jwks':
            self.jwks_requests += 1
            return FakeResponse(self.jwks)
        if url == f'{ISSUER}/picture/':
            return FakeResponse({'max_size': 1048576})
        if url == f'{ISSUER}/navigation/':
            self.navigation_requests.append(kwargs['headers'])
            return FakeResponse(self.navigation)
        if url == f'{ISSUER}/.well-known/openid-configuration':
            return FakeResponse(self.discovery)
        if url.startswith(f'{ISSUER}/userinfo'):
            if isinstance(self.userinfo, str):
                return FakeResponse(None, content_type=self.userinfo_content_type, text=self.userinfo)
            return FakeResponse(self.userinfo)
        raise AssertionError(f'unexpected GET {url}')

    def post(self, url, data=None, headers=None, **kwargs):
        self.token_requests.append({'url': url, 'data': data, 'headers': headers})
        return self.token_responses.pop(0)


class DemoTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.idp = IdentityProvider.objects.create(
            name='Example', issuer=ISSUER, authorization_endpoint=f'{ISSUER}/authorize',
            token_endpoint=f'{ISSUER}/token', jwks_uri=f'{ISSUER}/jwks', userinfo_endpoint=f'{ISSUER}/userinfo',
            end_session_endpoint=f'{ISSUER}/logout', require_iss_parameter=True)
        self.client_config = Client.objects.create(
            identity_provider=self.idp, client_id=CLIENT_ID, client_secret='secret',
            scope='openid profile email offline_access')
        self.fake = FakeIdentityProvider()
        patches = [
            mock.patch('relying_party.protocol.requests.post', side_effect=self.fake.post),
            mock.patch('relying_party.protocol.requests.get', side_effect=self.fake.get),
            mock.patch('relying_party.discovery.requests.get', side_effect=self.fake.get),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def start_login(self, client=None):
        response = self.client.get(reverse('relying_party:start_login', args=[(client or self.client_config).pk]))
        self.assertEqual(response.status_code, 302)
        return {key: values[0] for key, values in parse_qs(urlsplit(response['Location']).query).items()}

    def token_response(self, claims=None, **extra):
        data = {'access_token': 'access-1', 'token_type': 'Bearer', 'expires_in': 300, 'refresh_token': 'refresh-1',
                'id_token': sign(id_token_claims(**(claims or {}))), **extra}
        return FakeResponse(data)

    def login(self, **claims):
        request = self.start_login()
        self.fake.token_responses.append(self.token_response({'nonce': request['nonce'], **claims}))
        return self.client.get(reverse('relying_party:callback'), {'code': 'code-1', 'state': request['state'],
                                                                    'iss': ISSUER})


class AuthenticationRequestTest(DemoTestCase):
    def test_request_has_state_nonce_and_pkce(self):
        params = self.start_login()
        self.assertEqual(params['response_type'], 'code')
        self.assertEqual(params['client_id'], CLIENT_ID)
        self.assertEqual(params['redirect_uri'], 'http://testserver/oidc/callback/')
        self.assertEqual(params['code_challenge_method'], 'S256')
        self.assertIn('state', params)
        self.assertIn('nonce', params)

    def test_extra_parameters_can_not_replace_the_state(self):
        self.client_config.extra_authorization_params = '{"kc_idp_hint": "google", "state": "fixed"}'
        self.client_config.save()
        params = self.start_login()
        self.assertEqual(params['kc_idp_hint'], 'google')
        self.assertNotEqual(params['state'], 'fixed')

    def test_starting_logins_does_not_fill_the_session(self):
        for _ in range(browser_session.PENDING_MAX_COUNT + 5):
            self.start_login()
        self.assertEqual(len(self.client.session[browser_session.PENDING_KEY]), browser_session.PENDING_MAX_COUNT)


class CallbackTest(DemoTestCase):
    def test_login(self):
        response = self.login()
        self.assertRedirects(response, reverse('relying_party:tokens'), fetch_redirect_response=False)
        user = User.objects.get(identity_provider=self.idp, sub='user-1')
        self.assertEqual(user.email, 'ada@example.com')
        self.assertEqual(self.client.session['_auth_user_id'], str(user.pk))
        login = self.client.session[browser_session.LOGIN_KEY]
        self.assertEqual(login['sid'], 'sid-1')
        token_request = self.fake.token_requests[0]
        self.assertEqual(token_request['data']['grant_type'], 'authorization_code')
        self.assertIn('code_verifier', token_request['data'])
        self.assertTrue(token_request['headers']['Authorization'].startswith('Basic '))
        self.assertContains(self.client.get(reverse('relying_party:tokens')), 'The nonce is the one of')

    def test_state_is_valid_only_once(self):
        request = self.start_login()
        self.fake.token_responses.append(self.token_response({'nonce': request['nonce']}))
        params = {'code': 'code-1', 'state': request['state'], 'iss': ISSUER}
        self.client.get(reverse('relying_party:callback'), params)
        response = self.client.get(reverse('relying_party:callback'), params)
        self.assertContains(response, 'invalid_state', status_code=400)

    def test_state_of_another_browser_is_rejected(self):
        request = self.start_login()
        self.client.cookies.clear()
        response = self.client.get(reverse('relying_party:callback'),
                                   {'code': 'code-1', 'state': request['state'], 'iss': ISSUER})
        self.assertContains(response, 'invalid_state', status_code=400)

    def test_mix_up_is_detected(self):
        # RFC 9207: the answer comes from another identity provider than the one the login was started at.
        request = self.start_login()
        response = self.client.get(reverse('relying_party:callback'),
                                   {'code': 'code-1', 'state': request['state'], 'iss': 'https://evil.example.com'})
        self.assertContains(response, 'RFC 9207', status_code=400)
        self.assertEqual(self.fake.token_requests, [])

    def test_missing_iss_parameter(self):
        request = self.start_login()
        response = self.client.get(reverse('relying_party:callback'), {'code': 'code-1', 'state': request['state']})
        self.assertContains(response, 'no iss parameter', status_code=400)

    def test_error_response_is_shown(self):
        request = self.start_login()
        response = self.client.get(reverse('relying_party:callback'), {
            'error': 'access_denied', 'error_description': 'The user said no.', 'state': request['state'],
            'iss': ISSUER})
        self.assertContains(response, 'The user said no.', status_code=400)

    def test_wrong_nonce(self):
        response = self.login(nonce='other')
        self.assertContains(response, 'nonce', status_code=400)
        self.assertFalse(User.objects.filter(sub='user-1').exists())

    def test_wrong_issuer(self):
        self.assertContains(self.login(iss='https://evil.example.com'), 'issuer', status_code=400)

    def test_wrong_audience(self):
        self.assertContains(self.login(aud='other-client'), 'Audience', status_code=400)

    def test_wrong_azp(self):
        self.assertContains(self.login(aud=[CLIENT_ID, 'other'], azp='other'), 'azp', status_code=400)

    def test_expired_id_token(self):
        self.assertContains(self.login(exp=int(time.time()) - 3600), 'expired', status_code=400)

    def test_wrong_at_hash(self):
        self.assertContains(self.login(at_hash='wrong'), 'at_hash', status_code=400)

    def test_algorithm_is_not_taken_from_the_token(self):
        # An HS256 token with the public key as secret, the classic algorithm confusion attack.
        request = self.start_login()
        token = jwt.encode(id_token_claims(nonce=request['nonce']), 'secret', algorithm='HS256')
        self.fake.token_responses.append(FakeResponse({'access_token': 'a', 'token_type': 'Bearer',
                                                       'id_token': token}))
        response = self.client.get(reverse('relying_party:callback'),
                                   {'code': 'code-1', 'state': request['state'], 'iss': ISSUER})
        self.assertContains(response, "signed with &#39;HS256&#39;", status_code=400)

    def test_signature_with_another_key(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        request = self.start_login()
        token = sign(id_token_claims(nonce=request['nonce']), key=other_key)
        self.fake.token_responses.append(FakeResponse({'access_token': 'a', 'token_type': 'Bearer',
                                                       'id_token': token}))
        response = self.client.get(reverse('relying_party:callback'),
                                   {'code': 'code-1', 'state': request['state'], 'iss': ISSUER})
        self.assertContains(response, 'Signature verification failed', status_code=400)

    def test_max_age_needs_auth_time(self):
        self.client_config.max_age = 600
        self.client_config.save()
        self.assertContains(self.login(), 'auth_time', status_code=400)
        self.assertEqual(self.login(auth_time=int(time.time()) - 10).status_code, 302)

    def test_token_error(self):
        request = self.start_login()
        self.fake.token_responses.append(FakeResponse({'error': 'invalid_grant'}, status_code=400))
        response = self.client.get(reverse('relying_party:callback'),
                                   {'code': 'code-1', 'state': request['state'], 'iss': ISSUER})
        self.assertContains(response, 'invalid_grant', status_code=400)

    def test_public_client_sends_its_id(self):
        self.client_config.client_secret = ''
        self.client_config.save()
        self.login()
        self.assertEqual(self.fake.token_requests[0]['data']['client_id'], CLIENT_ID)
        self.assertNotIn('Authorization', self.fake.token_requests[0]['headers'])

    def test_next_url_of_another_site_is_ignored(self):
        response = self.client.get(reverse('relying_party:start_login', args=[self.client_config.pk]),
                                   {'next': 'https://evil.example.com/'})
        state = parse_qs(urlsplit(response['Location']).query)['state'][0]
        self.assertEqual(self.client.session[browser_session.PENDING_KEY][state]['next'],
                         reverse('relying_party:tokens'))


class RolesTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        self.client_config.roles_claim = 'roles'
        self.client_config.save()

    def test_roles_give_no_staff_status_without_configuration(self):
        self.login(roles=['Superuser'])
        self.assertFalse(User.objects.get(sub='user-1').is_superuser)

    def test_configured_roles(self):
        self.client_config.staff_roles = 'Staff'
        self.client_config.superuser_roles = 'Superuser'
        self.client_config.save()
        self.login(roles='Staff')
        user = User.objects.get(sub='user-1')
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_roles_claim_is_read_by_default(self):
        # A new client reads the claim "roles" without configuration, like the g10f SSO sends it.
        client = Client.objects.create(identity_provider=self.idp, client_id='other')
        self.assertEqual(client.roles_claim, 'roles')
        self.client_config.superuser_roles = 'Superuser'
        self.client_config.save()
        self.login(roles=['Superuser'])
        self.assertTrue(User.objects.get(sub='user-1').is_superuser)

    def test_check_roles(self):
        self.idp.check_roles = True
        self.idp.extend_access_uri = 'https://idp.example.com/access/'
        self.idp.save()
        response = self.login(roles=[])
        self.assertTrue(response['Location'].startswith('https://idp.example.com/access/?redirect_uri='))
        self.assertNotIn('_auth_user_id', self.client.session)


class RefreshAndUserInfoTest(DemoTestCase):
    def test_refresh(self):
        self.login()
        self.fake.token_responses.append(self.token_response(access_token='access-2', refresh_token=None))
        response = self.client.post(reverse('relying_party:refresh_tokens'))
        self.assertRedirects(response, reverse('relying_party:tokens'), fetch_redirect_response=False)
        login = self.client.session[browser_session.LOGIN_KEY]
        self.assertEqual(login['tokens']['access_token'], 'access-2')
        self.assertEqual(login['tokens']['refresh_token'], 'refresh-1')  # the old one is kept
        self.assertEqual(len(login['history']), 1)

    def test_refreshed_id_token_of_another_user(self):
        self.login()
        self.fake.token_responses.append(self.token_response({'sub': 'user-2'}))
        response = self.client.post(reverse('relying_party:refresh_tokens'))
        self.assertContains(response, 'sub of the refreshed ID token', status_code=400)

    def test_userinfo(self):
        self.login()
        self.fake.userinfo = {'sub': 'user-1', 'name': 'Ada', 'picture': 'https://idp.example.com/ada.png'}
        response = self.client.get(reverse('relying_party:userinfo'))
        self.assertContains(response, 'src="https://idp.example.com/ada.png"')

    def test_picture_upload_needs_the_picture_scope(self):
        self.idp.picture_endpoint = f'{ISSUER}/picture/'
        self.idp.save()
        self.login()  # the token response has no scope, so the scope of the client counts, without "picture"
        self.fake.userinfo = {'sub': 'user-1'}
        response = self.client.get(reverse('relying_party:userinfo'))
        self.assertContains(response, 'must request the scope')
        self.assertNotContains(response, 'value="upload"')

    def test_picture_upload(self):
        self.idp.picture_endpoint = f'{ISSUER}/picture/'
        self.idp.save()
        self.client_config.scope += ' picture'
        self.client_config.save()
        self.login()
        self.fake.userinfo = {'sub': 'user-1'}
        response = self.client.get(reverse('relying_party:userinfo'))
        self.assertContains(response, 'value="upload"')
        self.assertContains(response, 'max. 1.0 MiB')
        # Larger than the SSO accepts: not sent at all
        too_large = SimpleUploadedFile('big.png', b'x' * 1048577, content_type='image/png')
        with mock.patch('relying_party.protocol.requests.request') as request:
            response = self.client.post(reverse('relying_party:picture'), {'action': 'upload', 'picture': too_large},
                                        follow=True)
        self.assertContains(response, 'larger than the identity provider accepts')
        request.assert_not_called()
        image = SimpleUploadedFile('ada.png', b'png-data', content_type='image/png')
        with mock.patch('relying_party.protocol.requests.request', return_value=FakeResponse(
                {'error': 'bad_request', 'error_description': 'picture not in scope'}, status_code=403)) as request:
            response = self.client.post(reverse('relying_party:picture'), {'action': 'upload', 'picture': image})
        # The reason of the SSO is shown
        self.assertContains(response, 'picture not in scope', status_code=400)
        method, url = request.call_args.args
        self.assertEqual((method, url), ('POST', f'{ISSUER}/picture/'))
        self.assertEqual(request.call_args.kwargs['headers']['Content-Type'], 'image/png')
        self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer access-1')

    def test_picture_change_reloads_the_navigation(self):
        self.idp.picture_endpoint = f'{ISSUER}/picture/'
        self.idp.user_navigation_uri = f'{ISSUER}/navigation/'
        self.idp.save()
        self.client_config.scope += ' picture'
        self.client_config.save()
        self.login()
        self.fake.navigation = {'id': 'user-1', 'apps': []}
        self.client.get(reverse('relying_party:home'))
        self.assertIn(browser_session.NAVIGATION_KEY, self.client.session)
        with mock.patch('relying_party.protocol.requests.request', return_value=FakeResponse({}, status_code=201)):
            self.client.post(reverse('relying_party:picture'), {
                'action': 'upload', 'picture': SimpleUploadedFile('a.png', b'png', content_type='image/png')})
        self.assertNotIn(browser_session.NAVIGATION_KEY, self.client.session)

    def test_picture_size_is_cached(self):
        self.idp.picture_endpoint = f'{ISSUER}/picture/'
        self.idp.save()
        self.assertEqual(protocol.picture_max_size(self.client_config, 'token'), 1048576)
        with mock.patch('relying_party.protocol.requests.get') as get:
            self.assertEqual(protocol.picture_max_size(self.client_config, 'token'), 1048576)
        get.assert_not_called()

    def test_userinfo_of_another_user(self):
        self.login()
        self.fake.userinfo = {'sub': 'user-2'}
        self.assertContains(self.client.get(reverse('relying_party:userinfo')), 'not the sub', status_code=400)

    def test_javascript_picture_url_is_not_shown(self):
        self.login()
        self.fake.userinfo = {'sub': 'user-1', 'picture': 'javascript:alert(1)'}
        self.assertNotContains(self.client.get(reverse('relying_party:userinfo')), 'src="javascript')


class LogoutTest(DemoTestCase):
    def test_rp_initiated_logout(self):
        self.login()
        response = self.client.post(reverse('relying_party:logout'))
        url = urlsplit(response['Location'])
        params = {key: values[0] for key, values in parse_qs(url.query).items()}
        self.assertEqual(f'{url.scheme}://{url.netloc}{url.path}', f'{ISSUER}/logout')
        self.assertEqual(params['client_id'], CLIENT_ID)
        self.assertEqual(params['post_logout_redirect_uri'], 'http://testserver/oidc/logged-out/')
        self.assertIn('id_token_hint', params)
        self.assertNotIn('_auth_user_id', self.client.session)
        response = self.client.get(reverse('relying_party:logged_out'), {'state': params['state']}, follow=True)
        self.assertContains(response, 'also at the identity provider')

    def test_logout_needs_post(self):
        self.assertEqual(self.client.get(reverse('relying_party:logout')).status_code, 405)

    def logout_token(self, **claims):
        now = int(time.time())
        data = {'iss': ISSUER, 'aud': CLIENT_ID, 'iat': now, 'exp': now + 120, 'jti': 'jti-1', 'sid': 'sid-1',
                'events': {protocol.BACKCHANNEL_LOGOUT_EVENT: {}}, **claims}
        return sign(data, headers={'typ': 'logout+jwt'})

    def test_backchannel_logout(self):
        self.client_config.backchannel_logout = True
        self.client_config.save()
        self.login()
        token = self.logout_token()
        response = self.client.post(reverse('relying_party:backchannel_logout'), {'logout_token': token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Session.objects.count(), 0)
        # A logout token is only accepted once.
        response = self.client.post(reverse('relying_party:backchannel_logout'), {'logout_token': token})
        self.assertEqual(response.status_code, 400)

    def test_backchannel_logout_rejects_an_id_token(self):
        self.client_config.backchannel_logout = True
        self.client_config.save()
        self.login()
        token = self.logout_token(nonce='n')
        response = self.client.post(reverse('relying_party:backchannel_logout'), {'logout_token': token})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Session.objects.count(), 1)

    def test_backchannel_logout_of_another_session(self):
        self.client_config.backchannel_logout = True
        self.client_config.save()
        self.login()
        response = self.client.post(reverse('relying_party:backchannel_logout'),
                                    {'logout_token': self.logout_token(sid='sid-2')})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Session.objects.count(), 1)

    def test_frontchannel_logout(self):
        self.client_config.frontchannel_logout = True
        self.client_config.save()
        self.login()
        response = self.client.get(reverse('relying_party:frontchannel_logout'), {'iss': ISSUER, 'sid': 'sid-1'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('X-Frame-Options', response)
        self.assertEqual(Session.objects.count(), 0)


class DeviceFlowTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        self.idp.device_authorization_endpoint = f'{ISSUER}/device'
        self.idp.save()
        self.client_config.flow = Client.FLOW_DEVICE
        self.client_config.save()

    def test_device_flow(self):
        self.fake.token_responses.append(FakeResponse({
            'device_code': 'device-1', 'user_code': 'ABCD-EFGH', 'verification_uri': f'{ISSUER}/device',
            'expires_in': 600, 'interval': 5}))
        self.client.post(reverse('relying_party:device_start', args=[self.client_config.pk]))
        self.assertContains(self.client.get(reverse('relying_party:device')), 'ABCD-EFGH')

        poll_url = reverse('relying_party:device_poll')
        # Within the interval the identity provider is not asked.
        self.assertEqual(self.client.post(poll_url).json()['status'], 'pending')
        self.assertEqual(len(self.fake.token_requests), 1)

        with mock.patch('relying_party.views.time.time', return_value=time.time() + 6):
            self.fake.token_responses.append(FakeResponse({'error': 'slow_down'}, status_code=400))
            self.assertEqual(self.client.post(poll_url).json()['interval'], 10)
        with mock.patch('relying_party.views.time.time', return_value=time.time() + 20):
            self.fake.token_responses.append(self.token_response())
            result = self.client.post(poll_url).json()
        self.assertEqual(result['status'], 'done')
        self.assertEqual(self.fake.token_requests[-1]['data']['grant_type'], protocol.DEVICE_CODE_GRANT)
        self.assertTrue(User.objects.filter(sub='user-1').exists())


class ImplicitFlowTest(DemoTestCase):
    def test_implicit_flow(self):
        self.client_config.flow = Client.FLOW_IMPLICIT
        self.client_config.save()
        request = self.start_login()
        self.assertEqual(request['response_type'], 'id_token token')
        self.assertNotIn('code_challenge', request)
        token = sign(id_token_claims(nonce=request['nonce'], at_hash=at_hash('access-1')))
        self.fake.userinfo = {'sub': 'user-1'}
        response = self.client.post(reverse('relying_party:implicit'), {
            'state': request['state'], 'id_token': token, 'access_token': 'access-1', 'iss': ISSUER})
        self.assertContains(response, 'The access token belongs to this ID token.')

    def test_implicit_flow_needs_at_hash(self):
        self.client_config.flow = Client.FLOW_IMPLICIT
        self.client_config.save()
        request = self.start_login()
        response = self.client.post(reverse('relying_party:implicit'), {
            'state': request['state'], 'id_token': sign(id_token_claims(nonce=request['nonce'])),
            'access_token': 'access-1', 'iss': ISSUER})
        self.assertContains(response, 'at_hash', status_code=400)


class InitiateLoginTest(DemoTestCase):
    def test_third_party_initiated_login(self):
        response = self.client.get(reverse('relying_party:initiate_login'),
                                   {'iss': ISSUER, 'login_hint': 'ada', 'target_link_uri': '/oidc/userinfo/'})
        params = parse_qs(urlsplit(response['Location']).query)
        self.assertEqual(params['login_hint'], ['ada'])
        self.assertEqual(list(self.client.session[browser_session.PENDING_KEY].values())[0]['next'],
                         '/oidc/userinfo/')

    def test_unknown_issuer(self):
        response = self.client.get(reverse('relying_party:initiate_login'), {'iss': 'https://other.example.com'})
        self.assertEqual(response.status_code, 400)


class ApiTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        ApiClient.objects.create(identity_provider=self.idp, client_id='api')

    def access_token(self, typ='at+jwt', **claims):
        now = int(time.time())
        return sign({'iss': ISSUER, 'sub': 'user-1', 'aud': 'api', 'iat': now, 'exp': now + 60, **claims},
                    headers={'typ': typ})

    def test_valid_token(self):
        response = self.client.get(reverse('relying_party:api_test'),
                                   HTTP_AUTHORIZATION=f'Bearer {self.access_token()}')
        self.assertEqual(response.json()['claims']['sub'], 'user-1')

    def test_id_token_is_no_access_token(self):
        response = self.client.get(reverse('relying_party:api_test'),
                                   HTTP_AUTHORIZATION=f'Bearer {self.access_token(typ="JWT")}')
        self.assertEqual(response.status_code, 401)
        self.assertIn('invalid_token', response['WWW-Authenticate'])

    def test_token_in_query_is_ignored(self):
        response = self.client.get(reverse('relying_party:api_test'), {'access_token': self.access_token()})
        self.assertEqual(response.status_code, 401)


class DiscoveryTest(DemoTestCase):
    def test_all_fields_are_replaced(self):
        values = endpoints_of(fetch_discovery_document(discovery_url(ISSUER)))
        self.assertEqual(values['authorization_endpoint'], f'{ISSUER}/authorize')
        self.assertEqual(values['end_session_endpoint'], '')  # not in the document: emptied
        self.assertTrue(values['require_iss_parameter'])

    def test_issuer_must_match(self):
        self.fake.discovery['issuer'] = 'https://evil.example.com'
        with self.assertRaises(ProtocolError):
            fetch_discovery_document(discovery_url(ISSUER))

    def test_unknown_kid_reloads_the_keys(self):
        with self.assertRaises(ProtocolError):
            protocol.validate_id_token(self.client_config, sign(id_token_claims(), headers={'kid': 'key-2'}))


@override_settings(LOGIN_URL='/oidc/login/')
class PagesTest(DemoTestCase):
    def test_pages(self):
        for name in ('home', 'login', 'device', 'implicit'):
            self.assertEqual(self.client.get(reverse(f'relying_party:{name}')).status_code, 200, name)
        self.assertContains(self.client.get(reverse('relying_party:login')),
                            '<li><a href="/">Home</a></li>\n    <li class="active">Log in</li>')
        self.assertEqual(self.client.get(reverse('admin:login')).status_code, 200)

    def test_admin_login_with_password(self):
        User.objects.create_superuser('admin', 'admin@example.com', 'secret-password')
        response = self.client.post(reverse('admin:login'), {
            'username': 'admin', 'password': 'secret-password', 'next': reverse('admin:index')})
        self.assertRedirects(response, reverse('admin:index'), fetch_redirect_response=False)
        self.assertEqual(self.client.get(reverse('admin:index')).status_code, 200)

    def test_admin_client_page(self):
        User.objects.create_superuser('admin', 'admin@example.com', 'secret-password')
        self.client.login(username='admin', password='secret-password')
        response = self.client.get(reverse('admin:relying_party_client_change', args=[self.client_config.pk]))
        self.assertContains(response, 'data-copy="http://testserver/oidc/callback/"')
        self.assertContains(response, 'css/admin.css')
        self.assertContains(response, 'js/copy.js')

    def test_pages_with_a_password_login(self):
        # A local user (admin) has no OpenID Connect login, so no tokens; the pages send it to the login.
        User.objects.create_superuser('admin', 'admin@example.com', 'secret-password')
        self.client.login(username='admin', password='secret-password')
        for name in ('tokens', 'userinfo'):
            response = self.client.get(reverse(f'relying_party:{name}'), follow=True)
            self.assertRedirects(response, reverse('relying_party:login'))
        self.assertContains(self.client.get(reverse('relying_party:tokens'), follow=True), 'logged in with a password')

    def test_admin_login_with_password_while_logged_in_with_oidc(self):
        User.objects.create_superuser('admin', 'admin@example.com', 'secret-password')
        self.login()
        response = self.client.post(reverse('admin:login'), {
            'username': 'admin', 'password': 'secret-password', 'next': reverse('admin:index')})
        self.assertRedirects(response, reverse('admin:index'), fetch_redirect_response=False)
        self.assertEqual(self.client.get(reverse('admin:index')).status_code, 200)

    def test_pages_after_login(self):
        self.login()
        # The button of the client of the current login is shown in another color.
        self.assertContains(self.client.get(reverse('relying_party:login')), 'btn btn-success')
        response = self.client.get(reverse('relying_party:tokens'))
        self.assertContains(response, 'access-1')
        # The ID token as raw value, as link to jwt.io and its claims as table with readable times.
        id_token = self.client.session[browser_session.LOGIN_KEY]['tokens']['id_token']
        self.assertContains(response, f'https://www.jwt.io/#token={id_token}')
        self.assertContains(response, '<td><code>email</code></td>', html=False)
        self.assertRegex(response.content.decode(),
                         r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} <span class="text-body-secondary">\(\d+\)')
        self.assertContains(self.client.get(reverse('relying_party:home')), 'Log out')


class ReviewFindingsTest(DemoTestCase):
    """Cases from the review of 3.0: input of the identity provider or an attacker must not end in a server error."""

    def callback_with(self, token_response):
        request = self.start_login()
        self.fake.token_responses.append(token_response(request))
        return self.client.get(reverse('relying_party:callback'),
                               {'code': 'code-1', 'state': request['state'], 'iss': ISSUER})

    def test_alg_as_list_in_the_api(self):
        ApiClient.objects.create(identity_provider=self.idp, client_id='api')
        token = raw_jwt({'alg': [1], 'typ': 'at+jwt'}, {'iss': ISSUER, 'aud': 'api'})
        response = self.client.get(reverse('relying_party:api_test'), HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(response.status_code, 401)

    def test_alg_and_kid_as_list_in_the_logout_token(self):
        self.client_config.backchannel_logout = True
        self.client_config.save()
        for headers in ({'alg': [1]}, {'alg': 'RS256', 'kid': ['x']}):
            token = raw_jwt(headers, {'iss': ISSUER, 'aud': CLIENT_ID})
            response = self.client.post(reverse('relying_party:backchannel_logout'), {'logout_token': token})
            self.assertEqual(response.status_code, 400, headers)

    def test_empty_jwks(self):
        self.fake.jwks = {'keys': []}
        response = self.callback_with(lambda request: self.token_response({'nonce': request['nonce']}))
        self.assertContains(response, 'signing_error', status_code=400)

    def test_broken_key_in_the_jwks(self):
        self.fake.jwks = {'keys': [{'kty': 'RSA', 'kid': 'key-1', 'n': 'x'}]}
        response = self.callback_with(lambda request: self.token_response({'nonce': request['nonce']}))
        self.assertContains(response, 'signing_error', status_code=400)

    def test_rotated_key_is_found_right_after_a_reload(self):
        # The conformance suite uses a new kid for every test, also within a minute.
        protocol.validate_id_token(self.client_config, sign(id_token_claims()))
        self.fake.jwks = {'keys': [{**JWK, 'kid': 'key-2'}]}
        protocol.validate_id_token(self.client_config, sign(id_token_claims(), headers={'kid': 'key-2'}))
        self.fake.jwks = {'keys': [{**JWK, 'kid': 'key-3'}]}
        protocol.validate_id_token(self.client_config, sign(id_token_claims(), headers={'kid': 'key-3'}))
        self.assertEqual(self.fake.jwks_requests, 3)

    def test_known_kid_uses_the_cache(self):
        for _ in range(3):
            protocol.validate_id_token(self.client_config, sign(id_token_claims()))
        self.assertEqual(self.fake.jwks_requests, 1)

    def test_token_without_kid(self):
        protocol.validate_id_token(self.client_config, jwt.encode(id_token_claims(), PRIVATE_KEY, algorithm='RS256'))
        self.fake.jwks = {'keys': [JWK, {**JWK, 'kid': 'key-2'}]}
        cache.clear()
        with self.assertRaises(ProtocolError):
            protocol.validate_id_token(self.client_config,
                                       jwt.encode(id_token_claims(), PRIVATE_KEY, algorithm='RS256'))

    def test_hs256_client(self):
        self.client_config.id_token_signed_response_alg = 'HS256'
        self.client_config.save()
        response = self.callback_with(lambda request: FakeResponse({
            'access_token': 'a', 'token_type': 'Bearer',
            'id_token': jwt.encode(id_token_claims(nonce=request['nonce']), 'secret', algorithm='HS256')}))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(sub='user-1').exists())

    def test_max_age_with_old_authentication(self):
        self.client_config.max_age = 60
        self.client_config.save()
        response = self.login(auth_time=int(time.time()) - 3600)
        self.assertContains(response, 'older than max_age', status_code=400)

    def test_deactivated_user(self):
        User.objects.create(username='x', identity_provider=self.idp, sub='user-1', is_active=False)
        self.assertContains(self.login(), 'deactivated', status_code=400)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_too_long_sub(self):
        self.assertContains(self.login(sub='x' * 256), '1 to 255 characters', status_code=400)

    def test_scope_without_openid(self):
        self.client_config.scope = 'profile'
        self.client_config.save()
        response = self.callback_with(lambda request: FakeResponse({'access_token': 'a', 'token_type': 'Bearer'}))
        self.assertContains(response, 'openid', status_code=400)

    def test_unknown_state_creates_no_session(self):
        response = self.client.get(reverse('relying_party:callback'), {'code': 'c', 'state': 'unknown'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Session.objects.count(), 0)

    def test_basic_auth_is_form_encoded(self):
        self.client_config.client_secret = 'a b/c'
        self.client_config.save()
        self.login()
        header = self.fake.token_requests[0]['headers']['Authorization']
        self.assertEqual(base64.b64decode(header.split()[1]).decode(), f'{CLIENT_ID}:a+b%2Fc')

    def test_signed_userinfo(self):
        self.login()
        self.fake.userinfo_content_type = 'application/jwt'
        self.fake.userinfo = sign({'iss': ISSUER, 'aud': CLIENT_ID, 'sub': 'user-1', 'name': 'Ada'})
        self.assertContains(self.client.get(reverse('relying_party:userinfo')), 'signed JWT')
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.fake.userinfo = sign({'iss': ISSUER, 'aud': CLIENT_ID, 'sub': 'user-1'}, key=other_key)
        self.assertContains(self.client.get(reverse('relying_party:userinfo')), 'not valid', status_code=400)

    def test_silent_login_ends_the_session(self):
        # Session Management: the identity provider says the user is no longer logged in there.
        self.login()
        response = self.client.get(reverse('relying_party:start_login', args=[self.client_config.pk]),
                                   {'prompt': 'none'})
        params = parse_qs(urlsplit(response['Location']).query)
        self.assertEqual(params['prompt'], ['none'])
        self.assertIn('id_token_hint', params)
        response = self.client.get(reverse('relying_party:callback'), {
            'error': 'login_required', 'state': params['state'][0], 'iss': ISSUER})
        self.assertRedirects(response, reverse('relying_party:home'), fetch_redirect_response=False)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_initiate_login_with_foreign_target(self):
        self.client.get(reverse('relying_party:initiate_login'),
                        {'iss': ISSUER, 'target_link_uri': 'https://evil.example.com/'})
        pending = list(self.client.session[browser_session.PENDING_KEY].values())[0]
        self.assertEqual(pending['next'], reverse('relying_party:tokens'))

    def test_session_iframe_without_check_session_iframe(self):
        self.client_config.session_management = True
        self.client_config.save()
        request = self.start_login()
        self.fake.token_responses.append(self.token_response({'nonce': request['nonce']}))
        self.client.get(reverse('relying_party:callback'), {
            'code': 'c', 'state': request['state'], 'iss': ISSUER, 'session_state': 'abc'})
        self.assertContains(self.client.get(reverse('relying_party:session_iframe')), 'No session')
        self.idp.check_session_iframe = f'{ISSUER}/session'
        self.idp.save()
        self.assertContains(self.client.get(reverse('relying_party:session_iframe')),
                            f'data-op-origin="{ISSUER}"')

    def test_session_iframe_stops_after_a_silent_login(self):
        self.client_config.session_management = True
        self.client_config.save()
        self.idp.check_session_iframe = f'{ISSUER}/session'
        self.idp.save()
        request = self.start_login()
        self.fake.token_responses.append(self.token_response({'nonce': request['nonce']}))
        self.client.get(reverse('relying_party:callback'), {
            'code': 'c', 'state': request['state'], 'iss': ISSUER, 'session_state': 'abc'})
        self.assertContains(self.client.get(reverse('relying_party:session_iframe')), 'data-recently-checked="false"')
        # The silent login after a "changed" of the OP iframe
        self.client.get(reverse('relying_party:start_login', args=[self.client_config.pk]), {'prompt': 'none'})
        self.assertContains(self.client.get(reverse('relying_party:session_iframe')), 'data-recently-checked="true"')

    def test_session_checks_stay_stopped(self):
        self.client_config.session_management = True
        self.client_config.save()
        self.idp.check_session_iframe = f'{ISSUER}/session'
        self.idp.save()
        request = self.start_login()
        self.fake.token_responses.append(self.token_response({'nonce': request['nonce']}))
        self.client.get(reverse('relying_party:callback'), {
            'code': 'c', 'state': request['state'], 'iss': ISSUER, 'session_state': 'abc'})
        self.assertContains(self.client.get(reverse('relying_party:home')), 'id="op"')
        # The RP iframe reports that the OP iframe can't read its state
        self.assertEqual(self.client.post(reverse('relying_party:session_iframe')).status_code, 204)
        self.assertNotContains(self.client.get(reverse('relying_party:home')), 'id="op"')
        self.assertContains(self.client.get(reverse('relying_party:session_iframe')), 'No session')

    def test_token_pages_are_not_cached(self):
        self.login()
        self.assertIn('no-cache', self.client.get(reverse('relying_party:tokens'))['Cache-Control'])


class LogoutMatchingTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        self.client_config.backchannel_logout = True
        self.client_config.frontchannel_logout = True
        self.client_config.save()

    def logout(self, **claims):
        now = int(time.time())
        data = {'iss': ISSUER, 'aud': CLIENT_ID, 'iat': now, 'exp': now + 120, 'jti': protocol.random_value(),
                'events': {protocol.BACKCHANNEL_LOGOUT_EVENT: {}}, **claims}
        return self.client.post(reverse('relying_party:backchannel_logout'),
                                {'logout_token': sign(data, headers={'typ': 'logout+jwt'})})

    def test_sub_ends_all_sessions_of_the_user(self):
        self.login()
        self.assertEqual(self.logout(sub='user-1').status_code, 200)
        self.assertEqual(Session.objects.count(), 0)

    def test_sid_and_sub_for_a_session_without_sid(self):
        self.login(sid=None)
        self.assertEqual(self.logout(sid='sid-1', sub='user-1').status_code, 200)
        self.assertEqual(Session.objects.count(), 0)

    def test_sid_alone_for_a_session_without_sid(self):
        self.login(sid=None)
        self.logout(sid='sid-1')
        self.assertEqual(Session.objects.count(), 1)

    def test_logout_of_another_user(self):
        self.login()
        self.logout(sub='user-2')
        self.assertEqual(Session.objects.count(), 1)

    def test_frontchannel_logout_with_another_sid(self):
        self.login()
        response = self.client.get(reverse('relying_party:frontchannel_logout'), {'iss': ISSUER, 'sid': 'sid-2'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Session.objects.count(), 1)

    def test_frontchannel_logout_needs_sid(self):
        self.login()
        response = self.client.get(reverse('relying_party:frontchannel_logout'))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Session.objects.count(), 1)


class DeviceErrorsTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        self.idp.device_authorization_endpoint = f'{ISSUER}/device'
        self.idp.save()
        self.client_config.flow = Client.FLOW_DEVICE
        self.client_config.save()

    def start(self, **response):
        self.fake.token_responses.append(FakeResponse({
            'device_code': 'device-1', 'user_code': 'ABCD', 'verification_uri': f'{ISSUER}/device',
            'expires_in': 600, 'interval': 5, **response}))
        return self.client.post(reverse('relying_party:device_start', args=[self.client_config.pk]))

    def test_javascript_verification_uri(self):
        self.assertContains(self.start(verification_uri='javascript:alert(1)'), 'no http(s) url', status_code=400)
        self.assertContains(self.start(verification_uri_complete='javascript:alert(1)'), 'no http(s) url',
                            status_code=400)

    def test_end_of_the_flow(self):
        for error in ('access_denied', 'expired_token'):
            self.start()
            self.fake.token_responses.append(FakeResponse({'error': error}, status_code=400))
            with mock.patch('relying_party.views.time.time', return_value=time.time() + 6):
                result = self.client.post(reverse('relying_party:device_poll')).json()
            self.assertEqual(result['status'], 'error')
            self.assertIn(error, result['description'])
            self.assertNotIn(browser_session.DEVICE_KEY, self.client.session)


class NavigationTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        self.idp.user_navigation_uri = f'{ISSUER}/navigation/'
        self.idp.save()

    def app(self, title, href=None, global_navigation=True):
        return {'id': title, 'link': {'title': title, 'href': href or f'https://{title}.example.com/',
                                      'global_navigation': global_navigation}}

    def test_navigation_with_the_access_token(self):
        self.fake.navigation = {'id': 'user-1', 'apps': [
            self.app('wiki'), self.app('hidden', global_navigation=False), self.app('evil', 'javascript:alert(1)')]}
        self.login()
        response = self.client.get(reverse('relying_party:home'))
        self.assertContains(response, '<a class="nav-link" href="https://wiki.example.com/">wiki</a>', html=True)
        self.assertNotContains(response, 'hidden.example.com')
        self.assertNotContains(response, 'javascript:')
        self.assertEqual(self.fake.navigation_requests[0]['Authorization'], 'Bearer access-1')
        # The next page uses the navigation from the session.
        self.client.get(reverse('relying_party:home'))
        self.assertEqual(len(self.fake.navigation_requests), 1)

    def test_profile_and_picture_of_the_sso(self):
        self.fake.navigation = {'id': 'user-1', 'apps': [],
                                'profile': {'href': f'{ISSUER}/accounts/profile/', 'title': 'Ada'},
                                'picture_30x30': {'href': f'{ISSUER}/media/ada.png'}}
        self.login()
        response = self.client.get(reverse('relying_party:home'))
        self.assertContains(response, f'href="{ISSUER}/accounts/profile/"')
        self.assertContains(response, f'src="{ISSUER}/media/ada.png"')

    def test_four_applications_without_dropdown(self):
        self.fake.navigation = {'id': 'user-1', 'apps': [self.app(f'app{i}') for i in range(4)]}
        self.login()
        self.assertNotContains(self.client.get(reverse('relying_party:home')), 'dropdown-toggle')

    def test_more_than_four_applications(self):
        self.fake.navigation = {'id': 'user-1', 'apps': [self.app(f'app{i}') for i in range(5)]}
        self.login()
        response = self.client.get(reverse('relying_party:home'))
        self.assertContains(response, 'dropdown-toggle')
        self.assertContains(response, '<a class="dropdown-item" href="https://app4.example.com/">app4</a>', html=True)

    def test_navigation_of_another_user_is_not_shown(self):
        self.fake.navigation = {'id': 'user-2', 'apps': [self.app('wiki')]}
        self.login()
        self.assertNotContains(self.client.get(reverse('relying_party:home')), 'wiki.example.com')

    def test_navigation_error_does_not_break_the_page(self):
        self.login()  # self.fake.navigation is None: the answer is no JSON
        self.assertEqual(self.client.get(reverse('relying_party:home')).status_code, 200)


class SessionMaxAgeTest(DemoTestCase):
    def test_session_ends_after_session_max_age(self):
        self.client_config.session_max_age = 600
        self.client_config.save()
        self.login()
        # The cookie stays a session cookie without expiry date: the session also ends when the browser is closed.
        self.assertEqual(self.client.cookies['oidc_demo_session']['expires'], '')
        self.assertContains(self.client.get(reverse('relying_party:tokens')), 'Session ends</td><td>at ')
        with mock.patch('relying_party.middleware.time.time', return_value=time.time() + 601):
            response = self.client.get(reverse('relying_party:home'))
        self.assertContains(response, 'Your session has expired')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_session_within_session_max_age(self):
        self.client_config.session_max_age = 600
        self.client_config.save()
        self.login()
        with mock.patch('relying_party.middleware.time.time', return_value=time.time() + 300):
            self.client.get(reverse('relying_party:home'))
        self.assertIn('_auth_user_id', self.client.session)

    def test_without_session_max_age(self):
        self.login()
        with mock.patch('relying_party.middleware.time.time', return_value=time.time() + 86400 * 30):
            self.client.get(reverse('relying_party:home'))
        self.assertIn('_auth_user_id', self.client.session)


class BrandLinkTest(DemoTestCase):
    def test_brand_links_to_the_identity_provider_after_the_login(self):
        self.assertContains(self.client.get(reverse('relying_party:home')), '<a class="navbar-brand" href="/">')
        self.idp.home_uri = 'https://idp.example.com/'
        self.idp.save()
        self.login()
        response = self.client.get(reverse('relying_party:home'))
        self.assertContains(response, '<a class="navbar-brand" href="https://idp.example.com/">')


class StrongAuthenticationTest(DemoTestCase):
    SHIELD = 'bi-shield-lock'

    def test_acr_of_the_identity_provider(self):
        self.idp.strong_acr_values = '2'
        self.idp.save()
        self.login(acr='2')
        self.assertContains(self.client.get(reverse('relying_party:home')), self.SHIELD)

    def test_weak_acr(self):
        self.idp.strong_acr_values = '2'
        self.idp.save()
        self.login(acr='1')
        self.assertNotContains(self.client.get(reverse('relying_party:home')), self.SHIELD)

    def test_amr_mfa(self):
        self.login(amr=['pwd', 'otp', 'mfa'])
        self.assertContains(self.client.get(reverse('relying_party:home')), self.SHIELD)

    def test_without_configuration(self):
        self.login(acr='2')
        self.assertNotContains(self.client.get(reverse('relying_party:home')), self.SHIELD)


class TranslationTest(DemoTestCase):
    def test_german_from_the_browser_language(self):
        response = self.client.get(reverse('relying_party:login'), HTTP_ACCEPT_LANGUAGE='de')
        self.assertContains(response, '<html lang="de">')
        self.assertContains(response, 'Startseite')
        self.assertContains(response, 'Mit Example anmelden')

    def test_english_by_default(self):
        response = self.client.get(reverse('relying_party:login'))
        self.assertContains(response, '<html lang="en">')
        self.assertContains(response, 'Log in with Example')

    def test_names_in_translated_texts_are_escaped(self):
        self.idp.name = '<b>Evil</b>'
        self.idp.save()
        response = self.client.get(reverse('relying_party:login'), HTTP_ACCEPT_LANGUAGE='de')
        self.assertContains(response, 'Mit &lt;b&gt;Evil&lt;/b&gt; anmelden')
        self.assertNotContains(response, '<b>Evil</b>')

    def test_message_of_a_view(self):
        self.login()
        self.client.post(reverse('relying_party:logout'), HTTP_ACCEPT_LANGUAGE='de')
        response = self.client.get(reverse('relying_party:logged_out'), HTTP_ACCEPT_LANGUAGE='de', follow=True)
        self.assertContains(response, 'Sie sind abgemeldet')


class DiscoveryAdminTest(DemoTestCase):
    def setUp(self):
        super().setUp()
        User.objects.create_superuser('admin', 'admin@example.com', 'secret-password')
        self.client.login(username='admin', password='secret-password')

    def load(self, issuer=ISSUER):
        return self.client.get(reverse('admin:relying_party_identityprovider_discovery'), {'issuer': issuer})

    def test_load_button(self):
        response = self.client.get(reverse('admin:relying_party_identityprovider_change', args=[self.idp.pk]))
        self.assertContains(response, 'id="load-discovery"')
        self.assertContains(response, 'js/admin-discovery.js')
        fields = self.load().json()['fields']
        self.assertEqual(fields['token_endpoint'], f'{ISSUER}/token')
        self.assertTrue(fields['require_iss_parameter'])

    def test_load_with_wrong_issuer(self):
        self.fake.discovery['issuer'] = 'https://evil.example.com'
        response = self.load()
        self.assertEqual(response.status_code, 400)
        self.assertIn('evil.example.com', response.json()['error'])

    def test_load_needs_an_http_issuer(self):
        self.assertEqual(self.load('file:///etc').status_code, 400)

    def test_load_needs_staff(self):
        self.client.logout()
        self.assertEqual(self.load().status_code, 302)

    def test_load_needs_the_permission(self):
        # Staff status alone (e.g. from staff_roles) only opens the admin, not this server-side request.
        User.objects.create_user('staff', password='secret-password', is_staff=True)
        self.client.login(username='staff', password='secret-password')
        self.assertEqual(self.load().status_code, 403)

    def test_load_follows_no_redirects(self):
        with mock.patch('relying_party.discovery.requests.get',
                        return_value=FakeResponse(None, status_code=302, text='')) as get:
            response = self.load()
        self.assertEqual(response.status_code, 400)
        self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_saving_loads_nothing(self):
        response = self.client.post(reverse('admin:relying_party_identityprovider_change', args=[self.idp.pk]), {
            'name': 'Example', 'issuer': ISSUER, 'order': 0, 'is_active': 'on', 'verify_tls': 'on',
            'token_endpoint': 'https://own.example.com/token'})
        self.assertEqual(response.status_code, 302)
        self.idp.refresh_from_db()
        self.assertEqual(self.idp.token_endpoint, 'https://own.example.com/token')
        self.assertEqual(self.idp.authorization_endpoint, '')


class ImportLegacyConfigTest(TestCase):
    """The import of the 2.x configuration (management command import_legacy_config)."""

    def legacy_identity_provider(self, **fields):
        row = {
            'id': 2, 'name': 'g10f', 'issuer': 'https://sso.g10f.de', 'is_active': True, 'order': 0,
            'uri': 'https://sso.g10f.de/', 'authorization_endpoint': 'https://sso.g10f.de/oauth2/authorize/',
            'token_endpoint': 'https://sso.g10f.de/oauth2/token/', 'end_session_endpoint': '', 'revoke_uri': '',
            'userinfo_endpoint': 'https://sso.g10f.de/oauth2/userinfo/', 'picture_endpoint': '',
            'jwks_uri': 'https://sso.g10f.de/oauth2/jwks/', 'profile_uri': '', 'is_supporting_http_auth_header': False,
            'check_session_iframe': '', 'user_navigation_uri': '', 'is_secure': True, 'check_roles': False,
            'extend_access_uri': '',
        }
        return {**row, **fields}

    def legacy_client(self, **fields):
        row = {
            'id': 1, 'identity_provider_id': 2, 'name': '', 'type': 'web', 'response_type': '',
            'default_scopes': 'openid profile', 'application_id': '', 'client_id': 'web-client',
            'client_secret': 'secret', 'is_active': True, 'claims': '', 'max_age': '01:00:00',
            'max_age_seconds': 3600, 'acr_values': '', 'use_pkce': False, 'roles_claim': 'roles',
            'redirect_uri': '/oauth2/login/', 'kc_idp_hint': 'google', 'ui_locales': '', 'claims_locales': '',
            'prompt': '',
        }
        return {**row, **fields}

    def run_import(self, data, *args):
        with tempfile.NamedTemporaryFile('w', suffix='.json') as export_file:
            json.dump(data, export_file)
            export_file.flush()
            out = StringIO()
            call_command('import_legacy_config', export_file.name, *args, stdout=out)
        return out.getvalue()

    def test_import(self):
        data = {
            'identity_providers': [self.legacy_identity_provider(),
                                   self.legacy_identity_provider(id=6, name='Facebook', issuer='')],
            'clients': [self.legacy_client(),
                        self.legacy_client(id=2, type='javascript', client_id='js-client', default_scopes=''),
                        self.legacy_client(id=3, type='native', client_id='native-client'),
                        self.legacy_client(id=4, identity_provider_id=6, client_id='facebook-client')],
            'api_clients': [{'id': 1, 'identity_provider_id': 2, 'client_id': 'api', 'is_active': True}],
        }
        out = self.run_import(data)

        identity_provider = IdentityProvider.objects.get()
        self.assertEqual(identity_provider.issuer, 'https://sso.g10f.de')
        self.assertEqual(identity_provider.home_uri, 'https://sso.g10f.de/')
        self.assertTrue(identity_provider.userinfo_token_in_query)
        self.assertEqual(Client.objects.count(), 2)
        web = Client.objects.get(client_id='web-client')
        implicit = Client.objects.get(client_id='js-client')
        self.assertEqual((web.flow, web.max_age, web.disable_pkce), (Client.FLOW_CODE, 3600, False))
        self.assertEqual(json.loads(web.extra_authorization_params), {'kc_idp_hint': 'google'})
        self.assertEqual((implicit.flow, implicit.scope), (Client.FLOW_IMPLICIT, 'openid profile email'))
        self.assertFalse(ApiClient.objects.get().require_jwt_access_token_type)
        self.assertIn('client 3 (native) of g10f: skipped', out)

    def test_max_age_zero_means_none(self):
        # 2.x didn't send max_age when it was 0, 3.x would send and enforce max_age=0.
        data = {'identity_providers': [self.legacy_identity_provider()],
                'clients': [self.legacy_client(max_age='00:00:00', max_age_seconds=0)], 'api_clients': []}
        self.run_import(data)
        self.assertIsNone(Client.objects.get().max_age)

    def test_missing_field(self):
        row = self.legacy_identity_provider()
        del row['user_navigation_uri']
        data = {'identity_providers': [row], 'clients': [], 'api_clients': []}
        with self.assertRaisesMessage(CommandError, "lacks the field 'user_navigation_uri'"):
            self.run_import(data)
        self.assertFalse(IdentityProvider.objects.exists())

    def test_dry_run_and_non_empty_database(self):
        data = {'identity_providers': [self.legacy_identity_provider()], 'clients': [], 'api_clients': []}
        self.run_import(data, '--dry-run')
        self.assertFalse(IdentityProvider.objects.exists())

        self.run_import(data)
        with self.assertRaisesMessage(CommandError, 'already contains identity providers'):
            self.run_import(data)

    def test_export_file_or_from_database(self):
        with self.assertRaisesMessage(CommandError, 'Give the export file'):
            call_command('import_legacy_config', stdout=StringIO())
        with self.assertRaisesMessage(CommandError, 'not both'):
            call_command('import_legacy_config', 'legacy.json', '--from-database', stdout=StringIO())

    def run_import_from_database(self, stdin, data=None):
        connection = mock.MagicMock()
        connection.__enter__.return_value.execute.return_value.fetchone.return_value = [data]
        with mock.patch('sys.stdin', StringIO(stdin)), mock.patch('psycopg.connect', return_value=connection) as connect:
            call_command('import_legacy_config', '--from-database', stdout=StringIO())
        return connect

    def test_from_database(self):
        data = {'identity_providers': [self.legacy_identity_provider()], 'clients': [self.legacy_client()],
                'api_clients': []}
        connect = self.run_import_from_database('postgres://client:secret@db:5432/client\n', data)
        connect.assert_called_once_with('postgres://client:secret@db:5432/client', connect_timeout=10)
        self.assertTrue(connect.return_value.__enter__.return_value.read_only)
        self.assertEqual(Client.objects.get().client_id, 'web-client')

    def test_from_database_hides_the_password_of_a_broken_url(self):
        # libpq would repeat the broken percent-encoded password in its error message.
        with self.assertRaises(CommandError) as raised:
            self.run_import_from_database('postgres://client:se%ZZcret@db/client\n')
        self.assertNotIn('se%ZZcret', str(raised.exception))
        # Django style schemes like psql:// are no libpq URLs.
        with self.assertRaisesMessage(CommandError, 'must start with postgres:// or postgresql://'):
            self.run_import_from_database('psql://client:secret@db/client\n')
        with self.assertRaisesMessage(CommandError, 'stdin was empty'):
            self.run_import_from_database('')
