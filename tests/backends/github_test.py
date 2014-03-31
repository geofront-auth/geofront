import collections.abc

from paramiko.rsakey import RSAKey
from pytest import fixture, skip, yield_fixture

from geofront.backends.github import (GitHubKeyStore, GitHubOrganization,
                                      request)
from geofront.identity import Identity
from geofront.keystore import KeyType, PublicKey


@fixture
def fx_github_access_token(request):
    try:
        token = request.config.getoption('--github-access-token')
    except ValueError:
        token = None
    if not token:
        skip('--github-access-token is not set; skipped')
    return token


_fx_github_identity_cache = None


@fixture
def fx_github_identity(fx_github_access_token):
    global _fx_github_identity_cache
    if not _fx_github_identity_cache:
        _fx_github_identity_cache = request(
            fx_github_access_token,
            'https://api.github.com/user',
            'GET'
        )
    return Identity(
        GitHubOrganization,
        _fx_github_identity_cache['login'],
        fx_github_access_token
    )


def test_request(fx_github_access_token, fx_github_identity):
    result = request(
        fx_github_access_token,
        'https://api.github.com/user',
        'GET'
    )
    assert result['type'] == 'User'
    result2 = request(
        fx_github_identity,
        'https://api.github.com/user',
        'GET'
    )
    assert result == result2


def cleanup_ssh_keys(identity):
    keys = request(identity, GitHubKeyStore.LIST_URL, 'GET')
    for key in keys:
        url = GitHubKeyStore.DEREGISTER_URL.format(**key)
        request(identity, url, 'DELETE')


@yield_fixture
def fx_github_keystore(fx_github_identity):
    cleanup_ssh_keys(fx_github_identity)
    yield GitHubKeyStore()
    cleanup_ssh_keys(fx_github_identity)


def test_github_keystore(fx_github_identity, fx_github_keystore):
    keys = fx_github_keystore.list_keys(fx_github_identity)
    assert isinstance(keys, collections.abc.Set)
    assert not keys
    rsa_key = RSAKey.generate(1024)
    key = PublicKey(KeyType(rsa_key.get_name()),
                    base64_key=rsa_key.get_base64())
    fx_github_keystore.register(fx_github_identity, key)
    keys = fx_github_keystore.list_keys(fx_github_identity)
    assert isinstance(keys, collections.abc.Set)
    assert keys == {key}
    fx_github_keystore.deregister(fx_github_identity, key)
    keys = fx_github_keystore.list_keys(fx_github_identity)
    assert isinstance(keys, collections.abc.Set)
    assert not keys
