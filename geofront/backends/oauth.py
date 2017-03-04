""":mod:`geofront.backends.oauth` --- Team backend bases for OAuth
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 0.4.0

"""
import contextlib
import http.client
import io
import json
import logging
import os
import shutil
from typing import TYPE_CHECKING, IO, Mapping, cast
import urllib.error
import urllib.request

from typeguard import typechecked
from werkzeug.datastructures import ImmutableMultiDict
from werkzeug.http import parse_options_header
from werkzeug.urls import url_encode, url_decode_stream
from werkzeug.wrappers import Request

from ..identity import Identity
from ..team import AuthenticationContinuation, AuthenticationError, Team

__all__ = 'OAuth2Team', 'request'


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
    logger = logging.getLogger(__name__ + '.request')
    if isinstance(access_token, Identity):
        access_token = access_token.access_token
    logger.debug('access_token: %r', access_token)
    req = urllib.request.Request(
        url,
        headers={
            'Authorization': 'Bearer ' + access_token,
            'Accept': 'application/json'
        },
        method=method,
        data=data
    )
    try:
        with contextlib.closing(urllib.request.urlopen(req)) as response:
            assert isinstance(response, http.client.HTTPResponse), \
                'isinstance(response, {0.__module__}.{0.__qualname__})'.format(
                    type(response))
            headers = getattr(response, 'headers')  # workaround mypy
            content_type = headers.get('Content-Type')
            mimetype, options = parse_options_header(content_type)
            assert mimetype == 'application/json' or method == 'DELETE', \
                'Content-Type of {} is not application/json but {}'.format(
                    url,
                    content_type
                )
            charset = options.get('charset', 'utf-8')
            io_wrapper = io.TextIOWrapper(cast(IO[bytes], response),
                                          encoding=charset)
            if logger.isEnabledFor(logging.DEBUG):
                read = io_wrapper.read()
                if not TYPE_CHECKING:
                    logger.debug(
                        'HTTP/%d.%d %d %s\n%s\n\n%s',
                        response.version // 10,
                        response.version % 10,
                        response.code,
                        response.reason,
                        '\n'.join(
                            '{}: {}'.format(k, v)
                            for k, v in response.headers.items()
                        ),
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
    except urllib.error.HTTPError as e:
        if logger.isEnabledFor(logging.DEBUG):
            f = io.BytesIO()
            shutil.copyfileobj(e, f)
            if not TYPE_CHECKING:
                logger.debug(
                    'HTTP/%d.%d %d %s\n%s\n\n%r',
                    e.version // 10,
                    e.version % 10,
                    e.code,
                    e.reason,
                    '\n'.join(
                        '{}: {}'.format(k, v)
                        for k, v in e.headers.items()
                    ),
                    f.getvalue()
                )
            f.seek(0)
            logger.debug(str(e), exc_info=True)
            make_error = urllib.error.HTTPError  # workaround mypy
            restored = make_error(e.geturl(), e.code, e.reason, e.headers, f)
            raise restored from e
        else:
            raise


class OAuth2Team(Team):
    """Base implementation of :class:`~geofront.team.Team` for OAuth 2.
    Every subclass has to implement the following attributes and methods:

    - :attr:`authorize_url` attribute
    - :attr:`access_token_url` attribute
    - :attr:`scope` attribute
    - :meth:`determine_identity()` method
    - :meth:`~geofront.team.Team.authorize()` method

    """

    #: (:class:`str`) The OAuth 2 authorization url.
    #:
    #: .. note::
    #:
    #:    Concrete subclass has to implement this method.
    authorize_url = NotImplemented

    #: (:class:`str`) The scope string for OAuth 2 authorization.
    #:
    #: .. note::
    #:
    #:    Concrete subclass has to implement this method.
    authorize_scope = NotImplemented

    #: (:class:`str`) The url to issue an OAuth 2 access token.
    #:
    #: .. note::
    #:
    #:    Concrete subclass has to implement this method.
    access_token_url = NotImplemented

    #: (:class:`str`) The message template which is used when the authenticated
    #: identity is unauthorized.  There's a predefined default message, but
    #: it can be overridden by subclass.  The two keywords are available:
    #:
    #: ``identity``
    #:    (:class:`~geofront.identity.Identity`) The authenticated identity.
    #:
    #: ``team``
    #:    (:class:`OAuth2Team`) The actual team object.
    unauthorized_identity_message_format = \
        'identity {identity} is unauthorized'

    logger = logging.getLogger(__name__ + '.OAuth2Team')

    @typechecked
    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    def determine_identity(self, access_token: str) -> Identity:
        """Determine :class:`~geofront.identity.Identity` from the given
        access token.

        .. note::

           Concrete subclass has to implement this method.

        """
        raise NotImplementedError(
            'determine_identity() method has to be implemented'
        )

    @typechecked
    def request_authentication(
        self, redirect_url: str
    ) -> AuthenticationContinuation:
        auth_nonce = ''.join(map('{:02x}'.format, os.urandom(16)))
        query = url_encode({
            'client_id': self.client_id,
            'redirect_uri': redirect_url,
            'scope': self.authorize_scope,
            'state': auth_nonce,
            'response_type': 'code',
        })
        authorize_url = '{}?{}'.format(self.authorize_url, query)
        return AuthenticationContinuation(authorize_url, auth_nonce)

    @typechecked
    def authenticate(
        self,
        state,
        requested_redirect_url: str,
        wsgi_environ: Mapping[str, object]
    ) -> Identity:
        logger = self.logger.getChild('authenticate')
        req = Request(wsgi_environ, populate_request=False, shallow=True)
        args = cast(ImmutableMultiDict, req.args)
        try:
            code = args['code']
            if args['state'] != state:
                raise AuthenticationError()
        except KeyError:
            raise AuthenticationError()
        data = url_encode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': requested_redirect_url,
            'grant_type': 'authorization_code',
        }).encode()
        try:
            response = urllib.request.urlopen(self.access_token_url, data)
        except urllib.error.HTTPError as e:
            logger.debug('Response of POST %s (with/ %r): %s\n%s',
                         self.access_token_url, data, e.code, e.read())
            raise
        assert isinstance(response, http.client.HTTPResponse), \
            'isinstance(response, {0.__module__}.{0.__qualname__})'.format(
                type(response))
        headers = getattr(response, 'headers')  # workaround mypy
        content_type = headers['Content-Type']
        mimetype, options = parse_options_header(content_type)
        if mimetype == 'application/x-www-form-urlencoded':
            token_data = url_decode_stream(response)
        elif mimetype == 'application/json':
            charset = options.get('charset', 'utf-8')
            token_data = json.load(
                io.TextIOWrapper(cast(IO[bytes], response), encoding=charset)
            )
        else:
            response.close()
            raise AuthenticationError(
                '{} sent unsupported content type: {}'.format(
                    self.access_token_url,
                    content_type
                )
            )
        response.close()
        identity = self.determine_identity(token_data['access_token'])
        if self.authorize(identity):
            return identity
        raise AuthenticationError(
            self.unauthorized_identity_message_format.format(
                identity=identity, team=self
            )
        )
