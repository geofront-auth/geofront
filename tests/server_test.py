import collections.abc
import datetime
import os
import random
import time

from flask import json, request, url_for
from iso8601 import parse_date
from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from pytest import fail, fixture, mark, raises, skip, yield_fixture
from tsukkomi.typed import typechecked
from werkzeug.contrib.cache import (BaseCache, FileSystemCache, RedisCache,
                                    SimpleCache)
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.http import parse_options_header
from werkzeug.routing import Map, Rule
from werkzeug.urls import url_decode, url_encode

from geofront.identity import Identity
from geofront.keystore import (DuplicatePublicKeyError, KeyStore,
                               format_openssh_pubkey, get_key_fingerprint,
                               parse_openssh_pubkey)
from geofront.masterkey import MasterKeyStore
from geofront.remote import PermissionPolicy, Remote
from geofront.server import (FingerprintConverter, Token, TokenIdConverter,
                             app, get_identity, get_key_store, get_public_key,
                             get_remote_set, get_team, get_token_store,
                             remote_dict)
from geofront.team import AuthenticationContinuation, AuthenticationError, Team
from geofront.version import VERSION


@fixture
def fx_url_map():
    return Map([
        Rule('/tokens/<token_id:token_id>', endpoint='create_session'),
        Rule('/fp/<fingerprint:fingerprint>', endpoint='get_key')
    ], converters={
        'token_id': TokenIdConverter,
        'fingerprint': FingerprintConverter
    })


@mark.parametrize('sample_id', {
    'VALID_ID', 'valid.id', 'Valid1234', '1234valid', '-._-._-._'
})
def test_token_id_converter_match_success(fx_url_map: Map, sample_id):
    path = '/tokens/' + sample_id
    urls = fx_url_map.bind('example.com', path)
    endpoint, values = urls.match(path)
    assert endpoint == 'create_session'
    assert values == {'token_id': sample_id}


@mark.parametrize('sample_id', {
    'invalid', '#INVALID', '/invalid', '@invalid', 'i', ('invalid' * 15)[:101]
})
def test_token_id_converter_match_failure(fx_url_map: Map, sample_id):
    path = '/tokens/' + sample_id
    urls = fx_url_map.bind('example.com', path)
    with raises(NotFound):
        urls.match(path)


@mark.parametrize(('f_hex', 'f_bytes'), {
    ('89:6d:a8:23:18:7a:c7:c0:24:f9:20:e7:7d:75:18:1c',
     b'\x89m\xa8#\x18z\xc7\xc0$\xf9 \xe7}u\x18\x1c'),
    ('f7:08:76:37:03:56:47:5a:e6:e3:bf:44:f4:18:11:1d',
     b'\xf7\x08v7\x03VGZ\xe6\xe3\xbfD\xf4\x18\x11\x1d'),
    ('e5:68:2e:93:36:70:d5:70:66:8c:79:56:c5:f1:3c:62',
     b'\xe5h.\x936p\xd5pf\x8cyV\xc5\xf1<b')
})
def test_fingerprint_converter_match_success(fx_url_map: Map, f_hex, f_bytes):
    path = '/fp/' + f_hex
    urls = fx_url_map.bind('example.com', path)
    endpoint, values = urls.match(path)
    assert endpoint == 'get_key'
    assert values == {'fingerprint': f_bytes}


@mark.parametrize('sample_fp', {
    'invalid',
    '89:6d:a8:23:18:7a:c7:c0:24:f9:20:e7:7d:75:18:1c:00',
    '89:6d:a8:23:18:7a:c7:c0:24:f9:20:e7:7d:75:18:1c:',
    '89:6d:a8:23:18:7a:c7:c0:24:f9:20:e7:7d:75:18:',
    '89:6d:a8:23:18:7a:c7:c0:24:f9:20:e7:7d:75:18',
})
def test_fingerprint_converter_match_failure(fx_url_map: Map, sample_fp):
    path = '/fp/' + sample_fp
    urls = fx_url_map.bind('example.com', path)
    with raises(NotFound):
        urls.match(path)


def test_server_version():
    with app.test_client() as client:
        response = client.get('/')
        assert 'Geofront/' + VERSION in response.headers['Server']
        assert response.headers['X-Geofront-Version'] == VERSION


def parse_link_header(link_header):
    href, options = parse_options_header(link_header)
    assert href.startswith('<')
    assert href.endswith('>')
    assert list(options.keys()) == ['rel']
    return href[1:-1], options['rel']


def test_server_endpoint():
    with app.test_client() as client:
        assert get_url('server_endpoint') == '/'
        expected_url = get_url(
            'token',
            token_id='TOKEN_ID',
            _external=True
        ).replace('/TOKEN_ID/', '/')
        response = client.get('/')
        assert (parse_link_header(response.headers['Link']) ==
                (expected_url, 'tokens'))
        assert json.loads(response.data) == {'tokens_url': expected_url}


def test_get_token_store__no_config():
    with raises(RuntimeError):
        with app.app_context():
            get_token_store()


def test_get_token_store__invalid_type():
    app.config['TOKEN_STORE'] = 'invalid type'
    with raises(RuntimeError):
        with app.app_context():
            get_token_store()


@fixture(scope='function', params=[
    SimpleCache,
    FileSystemCache,
    RedisCache
])
def fx_token_store(request, tmpdir):
    cls = request.param
    if cls is FileSystemCache:
        cache = cls(str(tmpdir.join('token_store')))
    elif cls is RedisCache:
        getoption = request.config.getoption
        try:
            redis_host = getoption('--redis-host')
        except ValueError:
            redis_host = None
        if not redis_host:
            skip('--redis-host is not set; skipped')
        cache = cls(
            host=redis_host,
            port=getoption('--redis-port'),
            password=getoption('--redis-password'),
            db=getoption('--redis-db'),
            key_prefix='gftest_{0}_'.format(
                ''.join(map('{:02x}'.format, os.urandom(8)))
            )
        )
    else:
        cache = cls()
    return cache


def test_get_token(fx_token_store):
    app.config['TOKEN_STORE'] = fx_token_store
    with app.app_context():
        token_store = get_token_store()
        assert isinstance(token_store, BaseCache)
        token_store.add('abc', 123)
        assert fx_token_store.get('abc') == 123
        token_store.set('def', 456)
        assert fx_token_store.get('def') == 456
        token_store.inc('def')
        assert fx_token_store.get('def') == 457
        token_store.dec('abc')
        assert fx_token_store.get('abc') == 122
        token_store.delete('def')
        assert not fx_token_store.get('def')


class DummyTeam(Team):

    def __init__(self):
        self.states = []

    def request_authentication(
        self, redirect_url: str
    ) -> AuthenticationContinuation:
        auth_nonce = ''.join(map('{:02x}'.format, os.urandom(16)))
        self.states.append((auth_nonce, redirect_url))
        url = 'http://example.com/auth/?' + url_encode({
            'auth_nonce': auth_nonce,
            'redirect_url': redirect_url
        })
        return AuthenticationContinuation(url, auth_nonce)

    def authenticate(self, state, requested_redirect_url: str,
                     wsgi_environ: dict) -> Identity:
        try:
            pair = self.states.pop()
        except IndexError:
            raise AuthenticationError()
        if pair[0] != state or pair[1] != requested_redirect_url:
            raise AuthenticationError()
        return Identity(type(self), len(self.states))

    def authorize(self, identity: Identity) -> bool:
        return (issubclass(identity.team_type, type(self)) and
                identity.access_token is not False)

    def list_groups(self, identity: Identity):
        return {'odd' if identity.identifier % 2 else 'even'}


def test_get_team__no_config():
    with raises(RuntimeError):
        with app.app_context():
            get_team()


def test_get_team__invalid_type():
    app.config['TEAM'] = 'invalid type'
    with raises(RuntimeError):
        with app.app_context():
            get_team()


@fixture
def fx_team():
    return DummyTeam()


def test_get_team(fx_team):
    app.config['TEAM'] = fx_team
    with app.app_context():
        assert get_team() is fx_team


class MemoryMasterKeyStore(MasterKeyStore):

    @typechecked
    def __init__(self, master_key: PKey=None):
        if master_key is not None:
            self.save(master_key)

    @typechecked
    def load(self) -> PKey:
        return self.master_key

    @typechecked
    def save(self, master_key: PKey):
        self.master_key = master_key


@yield_fixture
def fx_app(fx_team, fx_token_store, fx_key_store, fx_master_key):
    app.config.update(
        TEAM=fx_team,
        TOKEN_STORE=fx_token_store,
        KEY_STORE=fx_key_store,
        MASTER_KEY_STORE=MemoryMasterKeyStore(fx_master_key)
    )
    yield app
    del app.config['TEAM'], \
        app.config['TOKEN_STORE'], \
        app.config['KEY_STORE'], \
        app.config['MASTER_KEY_STORE']


@fixture
def fx_token_id():
    """Random generated token id."""
    return ''.join(map('{:02x}'.format, os.urandom(random.randrange(4, 51))))


def get_url(endpoint, **values):
    with app.test_request_context():
        return url_for(endpoint, **values)


def test_create_access_token(fx_app, fx_token_id):
    url = get_url('create_access_token', token_id=fx_token_id)
    with app.test_client() as c:
        response = c.put(url)
        assert response.status_code == 202
        link = response.headers['Link']
        assert link.startswith('<http://example.com/auth/')
        assert link.endswith('>; rel=next')
        qs = url_decode(link[link.find('?') + 1:link.find('>')])
        result = json.loads(response.data)
        assert qs['redirect_url'] == get_url('authenticate',
                                             token_id=fx_token_id,
                                             _external=True)
        assert result == {'next_url': link[1:link.find('>')]}


def test_authenticate(fx_app, fx_token_store, fx_token_id):
    token_url = get_url('create_access_token', token_id=fx_token_id)
    auth_url = get_url('authenticate', token_id=fx_token_id)
    with app.test_client() as c:
        response = c.put(token_url)
        assert response.status_code == 202
        response = c.get(auth_url)
        assert response.status_code == 200
        token = fx_token_store.get(fx_token_id)
        assert isinstance(token, tuple)
        assert len(token) == 2
        assert token[0] == 'token'
        assert isinstance(token[1], Token)
        assert token[1].identity == Identity(DummyTeam, 0)


@fixture
def fx_authorized_identity(fx_token_store, fx_token_id):
    identity = Identity(DummyTeam, 1, True)
    expires_at = (datetime.datetime.now(datetime.timezone.utc) +
                  datetime.timedelta(hours=1))
    fx_token_store.set(fx_token_id, Token(identity, expires_at))
    return identity


def test_get_identity(fx_app, fx_authorized_identity, fx_token_id):
    with fx_app.test_request_context():
        identity = get_identity(fx_token_id)
        assert identity == fx_authorized_identity


def test_get_identity_403(fx_app, fx_token_store, fx_token_id):
    expires_at = (datetime.datetime.now(datetime.timezone.utc) +
                  datetime.timedelta(hours=1))
    fx_token_store.set(
        fx_token_id,
        Token(Identity(DummyTeam, 1, False), expires_at)
    )
    with fx_app.test_request_context():
        try:
            result = get_identity(fx_token_id)
        except HTTPException as e:
            response = e.get_response(request.environ)
            assert response.status_code == 403
            data = json.loads(response.data)
            assert data['error'] == 'not-authorized'
        else:
            fail('get_identity() does not raise HTTPException, but returns ' +
                 repr(result))


def test_get_identity_404(fx_app, fx_token_id):
    with fx_app.test_request_context():
        try:
            result = get_identity(fx_token_id)
        except HTTPException as e:
            response = e.get_response(request.environ)
            assert response.status_code == 404
            data = json.loads(response.data)
            assert data['error'] == 'token-not-found'
        else:
            fail('get_identity() does not raise HTTPException, but returns ' +
                 repr(result))


def test_get_identity_412(fx_app, fx_token_store, fx_token_id):
    fx_token_store.set(fx_token_id, 'nonce')
    with fx_app.test_request_context():
        try:
            result = get_identity(fx_token_id)
        except HTTPException as e:
            response = e.get_response(request.environ)
            assert response.status_code == 412
            data = json.loads(response.data)
            assert data['error'] == 'unfinished-authentication'
        else:
            fail('get_identity() does not raise HTTPException, but returns ' +
                 repr(result))


def test_token(fx_app, fx_authorized_identity, fx_token_id):
    with fx_app.test_client() as c:
        response = c.get(get_url('token', token_id=fx_token_id))
        assert response.status_code == 200
        links = dict(parse_link_header(link)[::-1]
                     for link in response.headers.getlist('Link'))
        assert links == {
            'remotes': get_url('list_remotes',
                               token_id=fx_token_id, _external=True),
            'keys': get_url('list_public_keys',
                            token_id=fx_token_id, _external=True),
            'masterkey': get_url('master_key',
                                 token_id=fx_token_id,
                                 _external=True)
        }
        t = fx_authorized_identity.team_type
        assert json.loads(response.data) == {
            'team_type': t.__module__ + '.' + t.__qualname__,
            'identifier': fx_authorized_identity.identifier,
            'remotes_url': links['remotes'],
            'keys_url': links['keys'],
            'master_key_url': links['masterkey']
        }


def test_token_412(fx_app, fx_token_store, fx_token_id):
    fx_token_store.set(fx_token_id, 'nonce')
    with fx_app.test_client() as c:
        response = c.get(get_url('token', token_id=fx_token_id))
        assert response.status_code == 412
        assert (json.loads(response.data)['error'] ==
                'unfinished-authentication')


def test_token_404(fx_app, fx_token_id):
    with fx_app.test_client() as c:
        response = c.get(get_url('token', token_id=fx_token_id))
        assert response.status_code == 404
        assert json.loads(response.data)['error'] == 'token-not-found'


def test_master_key(fx_app, fx_master_key,
                    fx_authorized_identity, fx_token_id):
    with fx_app.test_client() as c:
        response = c.get(get_url('master_key', token_id=fx_token_id))
        assert response.status_code == 200
        assert response.mimetype == 'text/plain'
        assert parse_openssh_pubkey(response.data.decode()) == fx_master_key


class DummyKeyStore(KeyStore):

    def __init__(self):
        self.keys = {}
        self.identities = {}

    def register(self, identity: Identity, public_key: PKey):
        if public_key in self.keys:
            raise DuplicatePublicKeyError()
        self.keys[public_key] = identity
        self.identities.setdefault(identity, set()).add(public_key)

    def list_keys(self, identity: Identity) -> collections.abc.Set:
        try:
            keys = self.identities[identity]
        except KeyError:
            return frozenset()
        return frozenset(keys)

    def deregister(self, identity: Identity, public_key: PKey):
        try:
            del self.keys[public_key]
            del self.identities[identity]
        except KeyError:
            pass


def test_get_key_store__no_config():
    with raises(RuntimeError):
        with app.app_context():
            get_key_store()


def test_get_key_store__invalid_type():
    app.config['KEY_STORE'] = 'invalid type'
    with raises(RuntimeError):
        with app.app_context():
            get_key_store()


@fixture
def fx_key_store():
    return DummyKeyStore()


def test_get_key_store(fx_key_store):
    app.config['KEY_STORE'] = fx_key_store
    with app.app_context():
        assert get_key_store() is fx_key_store


def test_list_public_keys(fx_app, fx_key_store,
                          fx_authorized_identity,
                          fx_token_id):
    with fx_app.test_client() as c:
        response = c.get(get_url('list_public_keys', token_id=fx_token_id))
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        assert response.data == b'{}'
    key = RSAKey.generate(1024)
    fx_key_store.register(fx_authorized_identity, key)
    with fx_app.test_client() as c:
        response = c.get(get_url('list_public_keys', token_id=fx_token_id))
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        data = {f: parse_openssh_pubkey(k)
                for f, k in json.loads(response.data).items()}
        assert data == {get_key_fingerprint(key): key}


def test_add_public_key_415(fx_app, fx_key_store,
                            fx_authorized_identity, fx_token_id):
    pkey = RSAKey.generate(1024)
    with fx_app.test_client() as c:
        response = c.post(
            get_url('add_public_key', token_id=fx_token_id),
            data={'key': format_openssh_pubkey(pkey)}
        )
        assert response.status_code == 415
        error = json.loads(response.data)
        assert error['error'] == 'unsupported-content-type'
        assert pkey not in fx_key_store.list_keys(fx_authorized_identity)


def test_add_public_key_unsupported_type(fx_app, fx_key_store,
                                         fx_authorized_identity, fx_token_id):
    pkey = RSAKey.generate(1024)
    with fx_app.test_client() as c:
        response = c.post(
            get_url('add_public_key', token_id=fx_token_id),
            content_type='text/plain',
            data=('invalid-type ' + format_openssh_pubkey(pkey)[7:]).encode()
        )
        assert response.status_code == 400
        error = json.loads(response.data)
        assert error['error'] == 'unsupported-key-type'
        assert pkey not in fx_key_store.list_keys(fx_authorized_identity)


def test_add_public_key_invalid_key(fx_app, fx_key_store,
                                    fx_authorized_identity, fx_token_id):
    with fx_app.test_client() as c:
        response = c.post(
            get_url('add_public_key', token_id=fx_token_id),
            content_type='text/plain',
            data=b'INVALID-FORMAT!!'
        )
        assert response.status_code == 400
        error = json.loads(response.data)
        assert error['error'] == 'invalid-key'


def test_add_public_key_duplicate_key(fx_app, fx_key_store,
                                      fx_authorized_identity, fx_token_id):
    pkey = RSAKey.generate(1024)
    fx_key_store.register(fx_authorized_identity, pkey)
    with fx_app.test_client() as c:
        response = c.post(
            get_url('add_public_key', token_id=fx_token_id),
            content_type='text/plain',
            data=format_openssh_pubkey(pkey).encode()
        )
        assert response.status_code == 400
        error = json.loads(response.data)
        assert error['error'] == 'duplicate-key'


def test_add_public_key(fx_app, fx_key_store,
                        fx_authorized_identity, fx_token_id):
    pkey = RSAKey.generate(1024)
    with fx_app.test_client() as c:
        response = c.post(
            get_url('add_public_key', token_id=fx_token_id),
            content_type='text/plain',
            data=format_openssh_pubkey(pkey).encode()
        )
        assert response.status_code == 201
        key_data = response.data
        assert parse_openssh_pubkey(key_data.decode()) == pkey
        assert pkey in fx_key_store.list_keys(fx_authorized_identity)
        r = c.get(response.location)
        assert r.data == key_data


def test_get_public_key(fx_app, fx_key_store,
                        fx_authorized_identity,
                        fx_token_id):
    key = RSAKey.generate(1024)
    fx_key_store.register(fx_authorized_identity, key)
    with fx_app.test_request_context():
        found = get_public_key(fx_token_id, key.get_fingerprint())
        assert found == key


def test_get_public_key_404(fx_app, fx_key_store,
                            fx_authorized_identity,
                            fx_token_id):
    with fx_app.test_request_context():
        try:
            result = get_public_key(fx_token_id, os.urandom(16))
        except HTTPException as e:
            response = e.get_response(request.environ)
            assert response.status_code == 404
            assert response.mimetype == 'application/json'
            error = json.loads(response.data.decode('utf-8'))
            assert error['error'] == 'not-found'
        else:
            fail('get_public_key() does not raise HTTPException, '
                 'but returns ' + repr(result))


def test_public_key(fx_app, fx_key_store,
                    fx_authorized_identity,
                    fx_token_id):
    key = RSAKey.generate(1024)
    fx_key_store.register(fx_authorized_identity, key)
    with fx_app.test_client() as client:
        response = client.get(
            get_url(
                'public_key',
                token_id=fx_token_id,
                fingerprint=key.get_fingerprint()
            )
        )
        assert response.status_code == 200
        assert response.mimetype == 'text/plain'
        assert parse_openssh_pubkey(response.data.decode()) == key
    with fx_app.test_client() as client:
        response = client.get(
            get_url(
                'public_key',
                token_id=fx_token_id,
                fingerprint=os.urandom(16)
            )
        )
        assert response.status_code == 404
        assert response.mimetype == 'application/json'
        error = json.loads(response.data.decode('utf-8'))
        assert error['error'] == 'not-found'


def test_delete_public_key(fx_app, fx_key_store,
                           fx_authorized_identity,
                           fx_token_id):
    key = RSAKey.generate(1024)
    fx_key_store.register(fx_authorized_identity, key)
    with fx_app.test_client() as client:
        response = client.delete(
            get_url(
                'delete_public_key',
                token_id=fx_token_id,
                fingerprint=key.get_fingerprint()
            )
        )
        assert response.status_code == 200
    assert key not in fx_key_store.list_keys(fx_authorized_identity)
    with fx_app.test_client() as client:
        response = client.delete(
            get_url(
                'delete_public_key',
                token_id=fx_token_id,
                fingerprint=key.get_fingerprint()
            )
        )
        assert response.status_code == 404
        assert response.mimetype == 'application/json'
        error = json.loads(response.data.decode('utf-8'))
        assert error['error'] == 'not-found'


def test_get_remote_set__no_config():
    with raises(RuntimeError):
        with app.app_context():
            get_remote_set()


def test_get_remote_set__invalid_type():
    app.config['REMOTE_SET'] = 'invalid type'
    with raises(RuntimeError):
        with app.app_context():
            get_remote_set()


@yield_fixture
def fx_mock_remote_set():
    remote_set = {
        'web-1': Remote('user', '192.168.0.5'),
        'web-2': Remote('user', '192.168.0.6')
    }
    app.config['REMOTE_SET'] = remote_set
    yield remote_set
    del app.config['REMOTE_SET']


def test_get_remote_set(fx_mock_remote_set):
    app.config['REMOTE_SET'] = fx_mock_remote_set
    with app.app_context():
        assert get_remote_set() == fx_mock_remote_set


def test_remote_dict():
    remote = Remote('username', '127.0.0.1', 2222)
    assert remote_dict(remote) == {
        'user': 'username',
        'host': '127.0.0.1',
        'port': 2222
    }


class DisallowAllPolicy(PermissionPolicy):

    def filter(self,
               remotes: collections.abc.Mapping,
               identity: Identity,
               groups: collections.abc.Set) -> collections.abc.Mapping:
        return {}

    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: collections.abc.Set) -> bool:
        return False


def test_list_remotes(fx_app, fx_mock_remote_set,
                      fx_authorized_identity, fx_token_id):
    with fx_app.test_client() as client:
        response = client.get(get_url('list_remotes', token_id=fx_token_id))
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        assert json.loads(response.data) == {
            alias: remote_dict(remote)
            for alias, remote in fx_mock_remote_set.items()
        }


def test_list_remotes_filtered(fx_app, fx_mock_remote_set,
                               fx_authorized_identity, fx_token_id):
    default = fx_app.config['PERMISSION_POLICY']
    try:
        fx_app.config['PERMISSION_POLICY'] = DisallowAllPolicy()
        with fx_app.test_client() as client:
            response = client.get(
                get_url('list_remotes', token_id=fx_token_id)
            )
            assert response.status_code == 200
            assert response.mimetype == 'application/json'
            assert json.loads(response.data) == {}
    finally:
        fx_app.config['PERMISSION_POLICY'] = default


@yield_fixture
def fx_authorized_remote_set(fx_authorized_servers):
    remote_set = {
        'port-' + str(port): Remote('user', '127.0.0.1', port)
        for port in fx_authorized_servers
    }
    app.config['REMOTE_SET'] = remote_set
    yield remote_set
    del app.config['REMOTE_SET']


def test_authorize_remote(fx_app, fx_authorized_servers, fx_master_key,
                          fx_authorized_remote_set, fx_authorized_identity,
                          fx_token_id, fx_key_store):
    public_key = RSAKey.generate(1024)
    fx_key_store.register(fx_authorized_identity, public_key)
    alias, remote = dict(fx_authorized_remote_set).popitem()
    with fx_app.test_client() as client:
        response = client.post(
            get_url('authorize_remote', token_id=fx_token_id, alias=alias)
        )
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        result = json.loads(response.data)
        assert result['success'] == 'authorized'
        assert result['remote'] == remote_dict(remote)
        expires_at = parse_date(result['expires_at'])
    thread, path, ev = fx_authorized_servers[remote.port]
    authorized_keys_path = path.join('.ssh', 'authorized_keys')
    with authorized_keys_path.open() as f:
        saved_keys = map(parse_openssh_pubkey, f)
        assert frozenset(saved_keys) == {fx_master_key, public_key}
    while datetime.datetime.now(datetime.timezone.utc) <= expires_at:
        time.sleep(1)
    time.sleep(1)
    with authorized_keys_path.open() as f:
        saved_keys = map(parse_openssh_pubkey, f)
        assert frozenset(saved_keys) == {fx_master_key}


def test_authorize_remote_404(fx_app, fx_mock_remote_set,
                              fx_authorized_identity, fx_token_id):
    with fx_app.test_client() as client:
        response = client.post(
            get_url('authorize_remote', token_id=fx_token_id, alias='notexist')
        )
        assert response.status_code == 404
        assert response.mimetype == 'application/json'
        result = json.loads(response.data)
        assert result['error'] == 'not-found'


def test_authorize_remote_403(fx_app, fx_mock_remote_set,
                              fx_authorized_identity, fx_token_id):
    default = fx_app.config['PERMISSION_POLICY']
    try:
        fx_app.config['PERMISSION_POLICY'] = DisallowAllPolicy()
        with fx_app.test_client() as client:
            response = client.post(
                get_url('authorize_remote',
                        token_id=fx_token_id,
                        alias='web-1')
            )
            assert response.status_code == 403
            assert response.mimetype == 'application/json'
            result = json.loads(response.data)
            assert result['error'] == 'forbidden'
    finally:
        fx_app.config['PERMISSION_POLICY'] = default
