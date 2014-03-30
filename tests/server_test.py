import os
import random

from flask import json, url_for
from pytest import fixture, mark, raises, skip, yield_fixture
from werkzeug.contrib.cache import (BaseCache, FileSystemCache, RedisCache,
                                    SimpleCache)
from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule
from werkzeug.urls import url_decode, url_encode

from geofront.identity import Identity
from geofront.server import TokenIdConverter, app, get_team, get_token_store
from geofront.team import AuthenticationError, Team


@fixture
def fx_url_map():
    return Map([
        Rule('/tokens/<token_id:token_id>', endpoint='create_session')
    ], converters={'token_id': TokenIdConverter})


@mark.parametrize('sample_id', {
    'VALID_ID', 'valid.id', 'Valid1234', '1234valid', '-._-._-._'
})
def test_token_id_converter_match_success(fx_url_map: Map, sample_id):
    urls = fx_url_map.bind('example.com', '/tokens/' + sample_id)
    endpoint, values = urls.match('/tokens/' + sample_id)
    assert endpoint == 'create_session'
    assert values == {'token_id': sample_id}


@mark.parametrize('sample_id', {
    'invalid', '#INVALID', '/invalid', '@invalid', 'i', ('invalid' * 15)[:101]
})
def test_token_id_converter_match_failure(fx_url_map: Map, sample_id):
    urls = fx_url_map.bind('example.com', '/tokens/' + sample_id)
    with raises(NotFound):
        urls.match('/tokens/' + sample_id)


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

    def request_authentication(self, auth_nonce: str, redirect_url: str) -> str:
        self.states.append((auth_nonce, redirect_url))
        return 'http://example.com/auth/?' + url_encode({
            'auth_nonce': auth_nonce,
            'redirect_url': redirect_url
        })

    def authenticate(self, auth_nonce: str, requested_redirect_url: str,
                     wsgi_environ: dict) -> Identity:
        try:
            pair = self.states.pop()
        except IndexError:
            raise AuthenticationError()
        if pair[0] != auth_nonce or pair[1] != requested_redirect_url:
            raise AuthenticationError()
        return Identity(type(self), len(self.states))

    def authorize(self, identity: Identity) -> bool:
        return False


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


@yield_fixture
def fx_app(fx_team, fx_token_store):
    app.config['TEAM'] = fx_team
    app.config['TOKEN_STORE'] = fx_token_store
    yield app
    del app.config['TEAM']
    del app.config['TOKEN_STORE']


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
        assert token == (True, Identity(DummyTeam, 0))
