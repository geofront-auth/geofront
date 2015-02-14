""":mod:`geofront.backends.github` --- GitHub organization and key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import json
import logging
import urllib.request

import base64
import collections.abc

from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from werkzeug.http import parse_options_header

from ..identity import Identity
from ..keystore import (DuplicatePublicKeyError, KeyStore,
                        format_openssh_pubkey, get_key_fingerprint,
                        parse_openssh_pubkey)
from ..util import typed
from .oauth2 import OAuth2Team, request_resource

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

    AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
    USER_URL = 'https://api.github.com/user'
    ORGS_LIST_URL = 'https://api.github.com/user/orgs'
    TEAMS_LIST_URL = 'https://api.github.com/user/teams'

    @typed
    def __init__(self, client_id: str, client_secret: str, org_login: str):
        super().__init__(client_id, client_secret)
        self.org_login = org_login

    @property
    def required_scopes(self) -> collections.abc.Set:
        return {'read:org', 'admin:public_key'}

    @typed
    def authorize(self, identity: Identity) -> bool:
        if not issubclass(identity.team_type, type(self)):
            return False
        try:
            response = request_resource(identity, self.ORGS_LIST_URL)
        except IOError:
            return False
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return False
        return any(o['login'] == self.org_login for o in response)

    @typed
    def list_groups(self, identity: Identity):
        if not issubclass(identity.team_type, type(self)):
            return frozenset()
        try:
            response = request_resource(identity, self.TEAMS_LIST_URL)
        except IOError:
            return frozenset()
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return frozenset()
        return frozenset(t['slug']
                         for t in response
                         if t['organization']['login'] == self.org_login)

    def determine_identity(self, token_data):
        user_data = request_resource(token_data['access_token'], self.USER_URL)
        return Identity(
            type(self),
            user_data['login'],
            token_data['access_token']
        )


class GitHubKeyStore(KeyStore):
    """Use GitHub account's public keys as key store."""

    LIST_URL = 'https://api.github.com/user/keys'
    DEREGISTER_URL = 'https://api.github.com/user/keys/{id}'

    @typed
    def register(self, identity: Identity, public_key: PKey):
        title = get_key_fingerprint(public_key)
        data = json.dumps({
            'title': title,
            'key': format_openssh_pubkey(public_key)
        })
        try:
            request_resource(identity, self.LIST_URL, 'POST',
                             data=data.encode())
        except urllib.request.HTTPError as e:
            if e.code != 422:
                raise
            content_type = e.headers.get('Content-Type')
            mimetype, options = parse_options_header(content_type)
            if mimetype != 'application/json':
                raise
            charset = options.get('charset', 'utf-8')
            response = json.loads(e.read().decode(charset))
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

    @typed
    def list_keys(self, identity: Identity) -> collections.abc.Set:
        logger = logging.getLogger(__name__ + '.GitHubKeyStore.list_keys')
        keys = request_resource(identity, self.LIST_URL)
        result = set()
        for key in keys:
            try:
                pubkey = RSAKey(data=base64.b64decode(key['key'].split()[1]))
            except Exception as e:
                logger.exception(e)
                continue
            result.add(pubkey)
        return result

    @typed
    def deregister(self, identity: Identity, public_key: PKey):
        keys = request_resource(identity, self.LIST_URL)
        for key in keys:
            if parse_openssh_pubkey(key['key']) == public_key:
                request_resource(identity,
                                 self.DEREGISTER_URL.format(**key),
                                 'DELETE')
                break
