""":mod:`geofront.backends.github` --- GitHub organization and key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import collections.abc
import json
import logging
import typing
import urllib.error
import urllib.request

from paramiko.pkey import PKey
from typeguard import typechecked
from werkzeug.http import parse_options_header

from ..identity import Identity
from ..keystore import (DuplicatePublicKeyError, KeyStore,
                        format_openssh_pubkey, get_key_fingerprint,
                        parse_openssh_pubkey)
from ..team import GroupSet
from .oauth import OAuth2Team, request


__all__ = 'GitHubKeyStore', 'GitHubOrganization'


class GitHubOrganization(OAuth2Team):
    """Authenticate team membership through GitHub, and authorize to
    access GitHub key store.

    Note that group identifiers :meth:`list_groups()` method returns
    are GitHub team *slugs*.  You can find what team slugs are there in
    the organization using GitHub API:

    .. code-block:: console

       $ curl -u YourUserLogin https://api.github.com/orgs/YourOrgLogin/teams
       Enter host password for user 'YourUserLogin':
       [
         {
           "name": "Owners",
           "id": 111111,
           "slug": "owners",
           "permission": "admin",
           "url": "https://api.github.com/teams/111111",
           ...
         },
         {
           "name": "Programmers",
           "id": 222222,
           "slug": "programmers",
           "permission": "pull",
           "url": "https://api.github.com/teams/222222",
           ...
         }
       ]

    In the above example, ``owners`` and ``programmers`` are team slugs.

    :param client_id: github api client id
    :type client_id: :class:`str`
    :param client_secret: github api client secret
    :type client_secret: :class:`str`
    :param org_login: github org account name.  for example ``'spoqa'``
                      in https://github.com/spoqa
    :type org_login: :class:`str`

    """

    authorize_url = 'https://github.com/login/oauth/authorize'
    authorize_scope = 'read:org,admin:public_key'
    access_token_url = 'https://github.com/login/oauth/access_token'
    user_url = 'https://api.github.com/user'
    orgs_list_url = 'https://api.github.com/user/orgs'
    teams_list_url = 'https://api.github.com/user/teams'
    unauthorized_identity_message_format = (
        '@{identity.identifier} user is not a member of '
        '@{team.org_login} organization'
    )

    @typechecked
    def __init__(self,
                 client_id: str,
                 client_secret: str,
                 org_login: str) -> None:
        super().__init__(client_id, client_secret)
        self.org_login = org_login

    def determine_identity(self, access_token: str) -> Identity:
        user_data = request(access_token, self.user_url)
        return Identity(type(self), user_data['login'], access_token)

    def authorize(self, identity: Identity) -> bool:
        if not issubclass(identity.team_type, type(self)):
            return False
        try:
            response = request(identity, self.orgs_list_url)
        except IOError:
            return False
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return False
        return any(o['login'] == self.org_login for o in response)

    def list_groups(self, identity: Identity) -> GroupSet:
        if not issubclass(identity.team_type, type(self)):
            return frozenset()
        try:
            response = request(identity, self.teams_list_url)
        except IOError:
            return frozenset()
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return frozenset()
        return frozenset(t['slug']
                         for t in response
                         if t['organization']['login'] == self.org_login)


class GitHubKeyStore(KeyStore):
    """Use GitHub account's public keys as key store."""

    list_url = 'https://api.github.com/user/keys'
    deregister_url = list_url + '/{id}'
    logger = logging.getLogger(__name__ + '.GitHubKeyStore')

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
        logger = self.logger.getChild('register')
        title = get_key_fingerprint(public_key)
        data = json.dumps({
            'title': title,
            'key': format_openssh_pubkey(public_key)
        })
        try:
            request(identity, self.list_url, 'POST', data=data.encode())
        except urllib.error.HTTPError as e:
            if e.code != 422:
                raise
            content_type = e.headers.get('Content-Type')
            mimetype, options = parse_options_header(content_type)
            if mimetype != 'application/json':
                raise
            charset = options.get('charset', 'utf-8')
            content_body = e.read().decode(charset)
            logger.debug('response body:\n%s', content_body)
            response = json.loads(content_body)
            for error in response.get('errors', []):
                if not isinstance(error, dict):
                    continue
                elif error.get('field') != 'key':
                    continue
                message = error.get('message', '').strip().lower()
                if message != 'key is already in use':
                    continue
                raise DuplicatePublicKeyError(message)
            raise

    @typechecked
    def _list_keys(self, identity: Identity) -> typing.Iterable[PKey]:
        logger = self.logger.getChild('list_keys')
        keys = request(identity, self.list_url)
        for key in keys:
            try:
                yield parse_openssh_pubkey(key['key']), key
            except Exception as e:
                logger.exception(str(e))
                continue

    @typechecked
    def list_keys(self, identity: Identity) -> typing.AbstractSet[PKey]:
        return frozenset(pkey for pkey, _ in self._list_keys(identity))

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
        for pkey, key in self._list_keys(identity):
            if pkey == public_key:
                request(identity, self.deregister_url.format(**key), 'DELETE')
                break
