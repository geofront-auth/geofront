from pytest import fixture, skip, yield_fixture

from geofront.backends.github import (GitHubKeyStore, GitHubOrganization)
from geofront.backends.oauth2 import request_resource
from geofront.identity import Identity
from ..keystore_test import assert_keystore_compliance


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
def fx_github_team_slugs(request):
    try:
        slugs = request.config.getoption('--github-team-slugs')
    except ValueError:
        slugs = None
    if not slugs:
        skip('--github-team-slugs is not provided; skipped')
    return {slug.strip() for slug in slugs.split()}


_fx_github_identity_cache = None


@fixture
def fx_github_identity(fx_github_access_token):
    global _fx_github_identity_cache
    if not _fx_github_identity_cache:
        _fx_github_identity_cache = request_resource(
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
    result = request_resource(
        fx_github_access_token,
        'https://api.github.com/user',
        'GET'
    )
    assert result['type'] == 'User'
    result2 = request_resource(
        fx_github_identity,
        'https://api.github.com/user',
        'GET'
    )
    assert result == result2


def test_authorize(fx_github_identity, fx_github_org_login):
    org = GitHubOrganization('', '', fx_github_org_login)
    assert org.authorize(fx_github_identity)


def test_list_groups(fx_github_identity, fx_github_org_login,
                     fx_github_team_slugs):
    org = GitHubOrganization('', '', fx_github_org_login)
    groups = org.list_groups(fx_github_identity)
    assert groups == fx_github_team_slugs


def cleanup_ssh_keys(identity):
    keys = request_resource(identity, GitHubKeyStore.LIST_URL, 'GET')
    for key in keys:
        url = GitHubKeyStore.DEREGISTER_URL.format(**key)
        request_resource(identity, url, 'DELETE')


@yield_fixture
def fx_github_keystore(fx_github_identity):
    cleanup_ssh_keys(fx_github_identity)
    yield GitHubKeyStore()
    cleanup_ssh_keys(fx_github_identity)


def test_github_keystore(fx_github_identity, fx_github_keystore):
    assert_keystore_compliance(fx_github_keystore, fx_github_identity)
