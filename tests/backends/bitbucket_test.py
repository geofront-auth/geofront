import typing

from pytest import fixture, skip

from geofront.backends.bitbucket import BitbucketTeam
from geofront.backends.oauth import request
from geofront.identity import Identity


@fixture(scope='session')
def fx_bitbucket_access_token(request) -> str:
    try:
        token = request.config.getoption('--bitbucket-access-token')
    except ValueError:
        token = None
    if not token:
        skip('--bitbucket-access-token is not set; skipped')
    return token


@fixture
def fx_bitbucket_team_username(request) -> str:
    try:
        org_login = request.config.getoption('--bitbucket-team-username')
    except ValueError:
        org_login = None
    if not org_login:
        skip('--bitbucket-team-username is not provided; skipped')
    return org_login


@fixture
def fx_bitbucket_group_slugs(request) -> typing.AbstractSet[str]:
    try:
        slugs = request.config.getoption('--bitbucket-group-slugs')
    except ValueError:
        slugs = None
    if not slugs:
        skip('--bitbucket-group-slugs is not provided; skipped')
    return {slug.strip() for slug in slugs.split()}


@fixture(scope='session')
def fx_bitbucket_identity(fx_bitbucket_access_token: str) -> Identity:
    resp = request(
        fx_bitbucket_access_token,
        'https://api.bitbucket.org/2.0/user',
        'GET'
    )
    return Identity(BitbucketTeam, resp['username'], fx_bitbucket_access_token)


def test_request(fx_bitbucket_access_token: str,
                 fx_bitbucket_identity: Identity):
    result = request(
        fx_bitbucket_access_token,
        'https://api.bitbucket.org/2.0/user',
        'GET'
    )
    assert result['type'] == 'user'
    result2 = request(
        fx_bitbucket_identity,
        'https://api.bitbucket.org/2.0/user',
        'GET'
    )
    assert result == result2


def test_authorize(fx_bitbucket_identity: Identity,
                   fx_bitbucket_team_username: str):
    team = BitbucketTeam('', '', fx_bitbucket_team_username)
    assert team.authorize(fx_bitbucket_identity)


def test_list_groups(fx_bitbucket_identity: Identity,
                     fx_bitbucket_team_username: str,
                     fx_bitbucket_group_slugs: typing.AbstractSet[str]):
    org = BitbucketTeam('', '', fx_bitbucket_team_username)
    groups = org.list_groups(fx_bitbucket_identity)
    assert groups == fx_bitbucket_group_slugs
