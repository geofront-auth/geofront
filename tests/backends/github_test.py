import collections.abc

from paramiko.rsakey import RSAKey
from pytest import fixture, raises, skip, yield_fixture

from geofront.backends.github import (GitHubKeyStore, GitHubOrganization,
                                      request)
from geofront.identity import Identity
from geofront.keystore import DuplicatePublicKeyError


@fixture
def fx_github_access_token(request):
    try:
        token = request.config.getoption('--github-access-token')
    except ValueError:
        token = None
    if not token:
        skip('--github-access-token is not set; skipped')
    return token


@fixture
def fx_github_org_login(request):
    try:
        org_login = request.config.getoption('--github-org-login')
    except ValueError:
        org_login = None
    if not org_login:
        skip('--github-org-login is not provided; skipped')
    return org_login


@fixture
def fx_github_team_ids(request):
    try:
        org_login = request.config.getoption('--github-team-ids')
    except ValueError:
        org_login = None
    if not org_login:
        skip('--github-team-ids is not provided; skipped')
    return {int(team_id.strip()) for team_id in org_login.split(',')}


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


def test_authorize(fx_github_identity, fx_github_org_login):
    org = GitHubOrganization('', '', fx_github_org_login)
    assert org.authorize(fx_github_identity)


def test_list_groups(fx_github_identity, fx_github_org_login,
                     fx_github_team_ids):
    org = GitHubOrganization('', '', fx_github_org_login)
    groups = org.list_groups(fx_github_identity)
    assert groups == fx_github_team_ids


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
    # "List registered public keys of the given ``identity``."
    keys = fx_github_keystore.list_keys(fx_github_identity)
    assert isinstance(keys, collections.abc.Set)
    assert not keys
    # "Register the given ``public_key`` to the ``identity``."
    key = RSAKey.generate(1024)
    fx_github_keystore.register(fx_github_identity, key)
    keys = fx_github_keystore.list_keys(fx_github_identity)
    assert isinstance(keys, collections.abc.Set)
    assert keys == {key}
    # ":raise geofront.keystore.DuplicatePublicKeyError:
    # when the ``public_key`` is already in use"
    with raises(DuplicatePublicKeyError):
        fx_github_keystore.register(fx_github_identity, key)
    # "Remove the given ``public_key`` of the ``identity``."
    fx_github_keystore.deregister(fx_github_identity, key)
    keys = fx_github_keystore.list_keys(fx_github_identity)
    assert isinstance(keys, collections.abc.Set)
    assert not keys
    # "It silently does nothing if there isn't the given ``public_key``
    # in the store."
    fx_github_keystore.deregister(fx_github_identity, key)
