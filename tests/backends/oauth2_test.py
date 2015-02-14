import collections.abc
import datetime
import os
import re
import urllib.request

from flask import Flask, jsonify, request
from flask.ext.oauthlib.provider import OAuth2Provider
from werkzeug.test import EnvironBuilder
from werkzeug.urls import url_decode

from geofront.backends.oauth2 import OAuth2Team, request_resource
from geofront.identity import Identity


oauth_server = Flask(__name__)
oauth_server.config.update(
    TRAP_HTTP_EXCEPTIONS=True,
    TRAP_BAD_REQUEST_ERRORS=True,
)

oauth_provider = OAuth2Provider()
oauth_provider.init_app(oauth_server)


class AttrDict(dict):

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        try:
            del self[name]
        except KeyError:
            raise AttributeError(name)


test_provider_host = 'o2-provider-test'
test_provider_base_url = 'http://' + test_provider_host
test_consumer_base_url = 'http://o2-consumer-test'
test_consumer_callback_url = test_consumer_base_url + '/'

sample_client = AttrDict(
    client_id='geofrontoauth2testid',
    client_secret='geofrontoauth2testsecret',
    client_type='public',
    redirect_uris=[test_consumer_callback_url],
    default_redirect_uri=test_consumer_callback_url,
    default_scopes=['scope1', 'scope2'],
)

sample_user = AttrDict(
    user_id='geofrontoauth2sampleuser',
    name='Geofront User'
)


@oauth_provider.clientgetter
def load_client(client_id):
    if client_id == sample_client.client_id:
        return sample_client


grant_registry = {}


@oauth_provider.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    grant = AttrDict(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        scopes=request.scopes,
        user=sample_user,
        expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=100),
        delete=lambda: grant_registry.pop(grant.code, None) and None
    )
    grant_registry[grant.code] = grant


@oauth_provider.grantgetter
def load_grant(client_id, code):
    if client_id == sample_client.client_id:
        return grant_registry.get(code)


token_registry = {}


@oauth_provider.tokensetter
def save_token(token, request, *args, **kwargs):
    expires_in = datetime.timedelta(seconds=token['expires_in'])
    token = AttrDict(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        scopes=token['scope'].split(),
        expires=datetime.datetime.utcnow() + expires_in,
        client_id=request.client.client_id,
        user=request.user,
        delete=lambda: grant_registry.pop(token.access_token, None) and None
    )
    token_registry[token.access_token] = token
    return token


@oauth_provider.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return token_registry.get(access_token)
    elif refresh_token:
        for token in token_registry.values():
            if token.refresh_token == refresh_token:
                return token


@oauth_server.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth_provider.authorize_handler
def server_authorize(*args, **kwargs):
    if request.method == 'GET':
        return 'POST this url again'
    return True


@oauth_server.route('/oauth/token', methods=['POST'])
@oauth_provider.token_handler
def server_token():
    pass


@oauth_server.route('/oauth/revoke', methods=['POST'])
@oauth_provider.revoke_handler
def server_revoke_token():
    pass


@oauth_server.route('/user')
@oauth_provider.require_oauth(sample_client.default_scopes[0])
def user():
    return jsonify(request.oauth.user)


class TestOAuth2Team(OAuth2Team):

    AUTHORIZE_URL = test_provider_base_url + '/oauth/authorize'
    ACCESS_TOKEN_URL = test_provider_base_url + '/oauth/token'

    @property
    def required_scopes(self):
        return frozenset(sample_client.default_scopes)

    def authorize(self, identity: Identity) -> bool:
        return True

    def determine_identity(self, token_data) -> Identity:
        access_token = token_data['access_token']
        user = request_resource(access_token, test_provider_base_url + '/user')
        return Identity(type(self), user['user_id'], access_token)

    def list_groups(self, identity: Identity) -> collections.abc.Set:
        return {}


o2team = TestOAuth2Team(
    client_id=sample_client.client_id,
    client_secret=sample_client.client_secret
)


def test_oauth2_team(fx_urllib_mock):
    callback_called = False
    fx_urllib_mock.route_wsgi(test_provider_host, oauth_server)

    @fx_urllib_mock.route(test_consumer_callback_url)
    def callback(req):
        nonlocal callback_called
        callback_called = req
        return b'Callback called', 200, {}

    nonce = ''.join('{:02x}'.format(b) for b in os.urandom(10))
    url = o2team.request_authentication(
        nonce,
        test_consumer_callback_url
    )
    assert url.startswith(TestOAuth2Team.AUTHORIZE_URL + '?')
    response = urllib.request.urlopen(url)
    assert response.code == 200
    assert response.read() == b'POST this url again'
    response = urllib.request.urlopen(url, data=b'')
    assert response.code == 200
    assert response.read() == b'Callback called'
    assert callback_called
    qs = url_decode(re.search(r'\?(.+)$', callback_called.full_url).group(1))
    assert qs['state'] == nonce
    assert qs['code']
    environ_builder = EnvironBuilder(
        path=callback_called.selector,
        base_url=re.match(
            r'^https?://[^/]+',
            callback_called.full_url
        ).group(0),
        method=callback_called.get_method(),
        headers=callback_called.headers,
        data=callback_called.data
    )
    identity = o2team.authenticate(
        nonce,
        test_consumer_callback_url,
        environ_builder.get_environ()
    )
    assert identity.team_type is TestOAuth2Team
    assert identity.identifier == sample_user.user_id
    assert token_registry[identity.access_token]['user'] == sample_user
