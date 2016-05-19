""":mod:`geofront.backends.stash` --- Bitbucket Server team and key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 0.3.0

Provides implementations of team and key store for Atlassian's
`Bitbucket Server`_ (which was Stash).

.. note::

   Not to be confused with `Bitbucket Cloud`_.  `As from September 22,
   Atlassian Stash becomes Bitbucket Server.`__

.. _Bitbucket Server: https://bitbucket.org/product/server
.. _Bitbucket Cloud: https://bitbucket.org/
__ https://twitter.com/Atlassian/status/646357289939664896

"""
import collections.abc
import io
import json
import logging
import typing
import urllib.error
import urllib.request

from oauthlib.oauth1 import SIGNATURE_RSA, Client
from paramiko.pkey import PKey
from tsukkomi.typed import typechecked
from werkzeug.urls import url_decode_stream, url_encode
from werkzeug.wrappers import Request

from ..identity import Identity
from ..keystore import (DuplicatePublicKeyError, KeyStore,
                        format_openssh_pubkey, parse_openssh_pubkey)
from ..team import AuthenticationContinuation, AuthenticationError, Team

__all__ = 'StashKeyStore', 'StashTeam'


class StashTeam(Team):
    """Authenticate team membership through Bitbucket Server (which was
    Stash), and authorize to access Bitbucket Server key store.

    :param server_url: the base url of the bitbucket server (stash server)
    :type server_url: :class:`str`
    :param consumer_key: the consumer key (client id)
    :type consumer_key: :class:`str`

    """

    AUTHORIZE_URL = '{0.server_url}/plugins/servlet/oauth/authorize'
    REQUEST_TOKEN_URL = '{0.server_url}/plugins/servlet/oauth/request-token'
    ACCESS_TOKEN_URL = '{0.server_url}/plugins/servlet/oauth/access-token'
    USER_URL = '{0.server_url}/plugins/servlet/applinks/whoami'
    USER_PROFILE_URL = '{0.server_url}/users/{1}'

    @typechecked
    def __init__(self, server_url: str, consumer_key: str, rsa_key: str):
        self.server_url = server_url.rstrip('/')
        self.consumer_key = consumer_key
        self.rsa_key = rsa_key

    def create_client(self, **kwargs):
        return Client(
            self.consumer_key,
            signature_method=SIGNATURE_RSA,
            rsa_key=self.rsa_key,
            **kwargs
        )

    @typechecked
    def request(self, method: str, url: str, body=None, headers=None,
                **client_options):
        client = self.create_client(**client_options)
        url, headers, body = client.sign(url, method, body, headers)
        request = urllib.request.Request(url, body, headers, method=method)
        try:
            return urllib.request.urlopen(request)
        except urllib.error.HTTPError as e:
            logger = logging.getLogger(__name__ + '.StashTeam.request')
            logger.exception(
                '[%s %s] %s\nrequest headers: %r\nrequest body: %r\n'
                'client_options: %r\nresponse status: %r\n'
                'response headers: %r\nresponse body: %r',
                method, url, e, headers, body, client_options,
                e.code, dict(e.headers), e.read()
            )
            raise

    @typechecked
    def request_authentication(
        self, redirect_url: str
    ) -> AuthenticationContinuation:
        response = self.request('POST', self.REQUEST_TOKEN_URL.format(self))
        request_token = url_decode_stream(response)
        response.close()
        return AuthenticationContinuation(
            self.AUTHORIZE_URL.format(self) + '?' + url_encode({
                'oauth_token': request_token['oauth_token'],
                'oauth_callback': redirect_url
            }),
            (request_token['oauth_token'], request_token['oauth_token_secret'])
        )

    @typechecked
    def authenticate(self,
                     state,
                     requested_redirect_url: str,
                     wsgi_environ: collections.abc.Mapping) -> Identity:
        logger = logging.getLogger(__name__ + '.StashTeam.authenticate')
        logger.debug('state = %r', state)
        try:
            oauth_token, oauth_token_secret = state
        except ValueError:
            raise AuthenticationError()
        req = Request(wsgi_environ, populate_request=False, shallow=True)
        logger.debug('req.args = %r', req.args)
        if req.args.get('oauth_token') != oauth_token:
            raise AuthenticationError()
        response = self.request(
            'POST', self.ACCESS_TOKEN_URL.format(self),
            resource_owner_key=oauth_token,
            resource_owner_secret=oauth_token_secret
        )
        access_token = url_decode_stream(response)
        logger.debug('access_token = %r', access_token)
        response.close()
        response = self.request(
            'GET', self.USER_URL.format(self),
            resource_owner_key=access_token['oauth_token'],
            resource_owner_secret=access_token['oauth_token_secret']
        )
        whoami = response.read().decode('utf-8')
        return Identity(
            type(self),
            self.USER_PROFILE_URL.format(self, whoami),
            (access_token['oauth_token'], access_token['oauth_token_secret'])
        )

    def authorize(self, identity: Identity) -> bool:
        if not issubclass(identity.team_type, type(self)):
            return False
        return identity.identifier.startswith(self.server_url)

    def list_groups(self, identity: Identity):
        return frozenset()


class StashKeyStore(KeyStore):
    """Use Bitbucket Server (Stash) account's public keys as key store."""

    REGISTER_URL = '{0.server_url}/rest/ssh/1.0/keys'
    LIST_URL = '{0.server_url}/rest/ssh/1.0/keys?start={1}'
    DEREGISTER_URL = '{0.server_url}/rest/ssh/1.0/keys/{1}'

    @typechecked
    def __init__(self, team: StashTeam) -> None:
        self.team = team

    def request(self, identity, *args, **kwargs):
        token, token_secret = identity.access_token
        return self.team.request(
            *args,
            resource_owner_key=token,
            resource_owner_secret=token_secret,
            **kwargs
        )

    @typechecked
    def request_list(
        self, identity: Identity
    ) -> typing.Iterator[typing.Sequence[typing.Mapping[str, typing.Any]]]:
        if not (isinstance(self.team, identity.team_type) and
                identity.identifier.startswith(self.team.server_url)):
            return
        start = 0
        while True:
            response = self.request(
                identity,
                'GET',
                self.LIST_URL.format(self.team, start)
            )
            assert response.code == 200
            payload = json.load(io.TextIOWrapper(response, encoding='utf-8'))
            response.close()
            yield from payload['values']
            if payload['isLastPage']:
                break
            start = payload['nextPageStart']

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
        if not (isinstance(self.team, identity.team_type) and
                identity.identifier.startswith(self.team.server_url)):
            return
        data = json.dumps({
            'text': format_openssh_pubkey(public_key)
        })
        try:
            self.request(
                identity, 'POST', self.REGISTER_URL.format(self.team), data,
                headers={'Content-Type': 'application/json'}
            )
        except urllib.error.HTTPError as e:
            if e.code == 409:
                errors = json.loads(e.read().decode('utf-8'))['errors']
                raise DuplicatePublicKeyError(errors[0]['message'])
            raise

    @typechecked
    def list_keys(self, identity: Identity) -> typing.AbstractSet[PKey]:
        logger = logging.getLogger(__name__ + '.StashKeyStore.list_keys')
        keys = self.request_list(identity)
        result = set()
        for key in keys:
            try:
                pubkey = parse_openssh_pubkey(key['text'])
            except Exception as e:
                logger.exception(e)
                continue
            result.add(pubkey)
        return result

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
        keys = self.request_list(identity)
        for key in keys:
            if parse_openssh_pubkey(key['text']) == public_key:
                response = self.request(
                    identity,
                    'DELETE',
                    self.DEREGISTER_URL(self.team, key['id'])
                )
                assert response.code == 204
                break
