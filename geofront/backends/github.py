""":mod:`geofront.backends.github` --- GitHub organization and key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import base64
import collections
import collections.abc
import contextlib
import io
import json
import logging
import os
import typing
import urllib.request

from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from tsukkomi.typed import typechecked
from werkzeug.http import parse_options_header
from werkzeug.urls import url_encode, url_decode_stream
from werkzeug.wrappers import Request

from ..identity import Identity
from ..keystore import (DuplicatePublicKeyError, KeyStore,
                        format_openssh_pubkey, get_key_fingerprint,
                        parse_openssh_pubkey)
from ..team import AuthenticationContinuation, AuthenticationError, Team


__all__ = 'GitHubKeyStore', 'GitHubOrganization', 'request'


def request(access_token, url: str, method: str='GET', data: bytes=None):
    """Make a request to GitHub API, and then return the parsed JSON result.

    :param access_token: api access token string,
                         or :class:`~geofront.identity.Identity` instance
    :type access_token: :class:`str`, :class:`~geofront.identity.Identity`
    :param url: the api url to request
    :type url: :class:`str`
    :param method: an optional http method.  ``'GET'`` by default
    :type method: :class:`str`
    :param data: an optional content body
    :type data: :class:`bytes`

    """
    if isinstance(access_token, Identity):
        access_token = access_token.access_token
    req = urllib.request.Request(
        url,
        headers={
            'Authorization': 'token ' + access_token,
            'Accept': 'application/json'
        },
        method=method,
        data=data
    )
    with contextlib.closing(urllib.request.urlopen(req)) as response:
        content_type = response.headers.get('Content-Type')
        mimetype, options = parse_options_header(content_type)
        assert mimetype == 'application/json' or method == 'DELETE', \
            'Content-Type of {} is not application/json but {}'.format(
                url,
                content_type
            )
        charset = options.get('charset', 'utf-8')
        io_wrapper = io.TextIOWrapper(response, encoding=charset)
        logger = logging.getLogger(__name__ + '.request')
        if logger.isEnabledFor(logging.DEBUG):
            read = io_wrapper.read()
            logger.debug(
                'HTTP/%d.%d %d %s\n%s\n\n%s',
                response.version // 10,
                response.version % 10,
                response.status,
                response.reason,
                '\n'.join('{}: {}'.format(k, v)
                          for k, v in response.headers.items()),
                read
            )
            if method == 'DELETE':
                return
            return json.loads(read)
        else:
            if method == 'DELETE':
                io_wrapper.read()
                return
            return json.load(io_wrapper)


class GitHubOrganization(Team):
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

    @typechecked
    def __init__(self,
                 client_id: str,
                 client_secret: str,
                 org_login: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.org_login = org_login

    @typechecked
    def request_authentication(self,
                               redirect_url: str) -> str:
        auth_nonce = ''.join(map('{:02x}'.format, os.urandom(16)))
        query = url_encode({
            'client_id': self.client_id,
            'redirect_uri': redirect_url,
            'scope': 'read:org,admin:public_key',
            'state': auth_nonce
        })
        authorize_url = '{}?{}'.format(self.AUTHORIZE_URL, query)
        return AuthenticationContinuation(authorize_url, auth_nonce)

    @typechecked
    def authenticate(
        self,
        state,
        requested_redirect_url: str,
        wsgi_environ: typing.Mapping[str, typing.Any]
    ) -> Identity:
        req = Request(wsgi_environ, populate_request=False, shallow=True)
        try:
            code = req.args['code']
            if req.args['state'] != state:
                raise AuthenticationError()
        except KeyError:
            raise AuthenticationError()
        data = url_encode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': requested_redirect_url
        }).encode()
        response = urllib.request.urlopen(self.ACCESS_TOKEN_URL, data)
        content_type = response.headers['Content-Type']
        mimetype, options = parse_options_header(content_type)
        if mimetype == 'application/x-www-form-urlencoded':
            token_data = url_decode_stream(response)
        elif mimetype == 'application/json':
            charset = options.get('charset')
            token_data = json.load(
                io.TextIOWrapper(response, encoding=charset)
            )
        else:
            response.close()
            raise AuthenticationError(
                '{} sent unsupported content type: {}'.format(
                    self.ACCESS_TOKEN_URL,
                    content_type
                )
            )
        response.close()
        user_data = request(token_data['access_token'], self.USER_URL)
        identity = Identity(
            type(self),
            user_data['login'],
            token_data['access_token']
        )
        if self.authorize(identity):
            return identity
        raise AuthenticationError(
            '@{} user is not a member of @{} organization'.format(
                user_data['login'],
                self.org_login
            )
        )

    def authorize(self, identity: Identity) -> bool:
        if not issubclass(identity.team_type, type(self)):
            return False
        try:
            response = request(identity, self.ORGS_LIST_URL)
        except IOError:
            return False
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return False
        return any(o['login'] == self.org_login for o in response)

    def list_groups(self, identity: Identity):
        if not issubclass(identity.team_type, type(self)):
            return frozenset()
        try:
            response = request(identity, self.TEAMS_LIST_URL)
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

    LIST_URL = 'https://api.github.com/user/keys'
    DEREGISTER_URL = 'https://api.github.com/user/keys/{id}'

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
        title = get_key_fingerprint(public_key)
        data = json.dumps({
            'title': title,
            'key': format_openssh_pubkey(public_key)
        })
        try:
            request(identity, self.LIST_URL, 'POST', data=data.encode())
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

    @typechecked
    def list_keys(self, identity: Identity) -> typing.AbstractSet[PKey]:
        logger = logging.getLogger(__name__ + '.GitHubKeyStore.list_keys')
        keys = request(identity, self.LIST_URL)
        result = set()
        for key in keys:
            try:
                pubkey = RSAKey(data=base64.b64decode(key['key'].split()[1]))
            except Exception as e:
                logger.exception(e)
                continue
            result.add(pubkey)
        return result

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
        keys = request(identity, self.LIST_URL)
        for key in keys:
            if parse_openssh_pubkey(key['key']) == public_key:
                request(identity, self.DEREGISTER_URL.format(**key), 'DELETE')
                break
