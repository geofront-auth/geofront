import typing

from pytest import fixture, skip, yield_fixture

from ..keystore_test import assert_keystore_compliance
from geofront.backends.github import GitHubKeyStore, GitHubOrganization
from geofront.backends.oauth import request
from geofront.identity import Identity


@fixture(scope='session')
def fx_github_access_token(request) -> str:
    try:
        token = request.config.getoption('--github-access-token')
    except ValueError:
        token = None
    if not token:
        skip('--github-access-token is not set; skipped')
    return token


@fixture
def fx_github_org_login(request) -> str:
    try:
        org_login = request.config.getoption('--github-org-login')
    except ValueError:
        org_login = None
    if not org_login:
        skip('--github-org-login is not provided; skipped')
    return org_login


@fixture
def fx_github_team_slugs(request) -> typing.AbstractSet[str]:
    try:
        slugs = request.config.getoption('--github-team-slugs')
    except ValueError:
        slugs = None
    if not slugs:
        skip('--github-team-slugs is not provided; skipped')
    return {slug.strip() for slug in slugs.split()}


@fixture(scope='session')
def fx_github_identity(fx_github_access_token: str) -> Identity:
    resp = request(
        fx_github_access_token,
        'https://api.github.com/user',
        'GET'
    )
    return Identity(GitHubOrganization, resp['login'], fx_github_access_token)


def test_request(fx_github_access_token: str, fx_github_identity: Identity):
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


def test_authorize(fx_github_identity: Identity, fx_github_org_login: str):
    org = GitHubOrganization('', '', fx_github_org_login)
    assert org.authorize(fx_github_identity)


def test_list_groups(fx_github_identity: Identity, fx_github_org_login: str,
                     fx_github_team_slugs: typing.AbstractSet[str]):
    org = GitHubOrganization('', '', fx_github_org_login)
    groups = org.list_groups(fx_github_identity)
    assert groups == fx_github_team_slugs


def cleanup_ssh_keys(identity: Identity):
    keys = request(identity, GitHubKeyStore.list_url, 'GET')
    for key in keys:
        url = GitHubKeyStore.deregister_url.format(**key)
        request(identity, url, 'DELETE')


@yield_fixture
def fx_github_keystore(fx_github_identity: Identity):
    cleanup_ssh_keys(fx_github_identity)
    yield GitHubKeyStore()
    cleanup_ssh_keys(fx_github_identity)


def test_github_keystore(fx_github_identity: Identity,
                         fx_github_keystore: GitHubKeyStore):
    assert_keystore_compliance(fx_github_keystore, fx_github_identity)
