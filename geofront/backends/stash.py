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
import logging
import urllib.request

from oauthlib.oauth1 import SIGNATURE_RSA, Client
from werkzeug.urls import url_decode_stream, url_encode
from werkzeug.wrappers import Request

from ..identity import Identity
from ..team import AuthenticationContinuation, AuthenticationError, Team
from ..util import typed


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

    @typed
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

    @typed
    def request_authentication(
        self, redirect_url: str
    ) -> AuthenticationContinuation:
        client = self.create_client()
        uri, headers, body = client.sign(
            self.REQUEST_TOKEN_URL.format(self),
            'POST'
        )
        request = urllib.request.Request(uri, body, headers, method='POST')
        response = urllib.request.urlopen(request)
        request_token = url_decode_stream(response)
        response.close()
        return AuthenticationContinuation(
            self.AUTHORIZE_URL.format(self) + '?' + url_encode({
                'oauth_token': request_token['oauth_token'],
                'oauth_callback': redirect_url
            }),
            (request_token['oauth_token'], request_token['oauth_token_secret'])
        )

    @typed
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
        client = self.create_client(
            resource_owner_key=oauth_token,
            resource_owner_secret=oauth_token_secret
        )
        uri, headers, body = client.sign(
            self.ACCESS_TOKEN_URL.format(self),
            'POST'
        )
        request = urllib.request.Request(uri, body, headers, method='POST')
        response = urllib.request.urlopen(request)
        access_token = url_decode_stream(response)
        logger.debug('access_token = %r', access_token)
        response.close()
        client = self.create_client(
            resource_owner_key=access_token['oauth_token'],
            resource_owner_secret=access_token['oauth_token_secret']
        )
        uri, headers, body = client.sign(self.USER_URL.format(self))
        request = urllib.request.Request(uri, body, headers)
        response = urllib.request.urlopen(request)
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
