""":mod:`geofront.backends.oauth2` --- `OAuth 2`_ team
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _OAuth 2: http://oauth.net/2/

.. versionadded:: 0.3.0

"""
import io
import json
import logging
import urllib.request
import collections.abc
import contextlib

from werkzeug.http import parse_options_header
from werkzeug.urls import url_encode, url_decode_stream
from werkzeug.wrappers import Request

from ..identity import Identity
from ..team import AuthenticationError, Team
from ..util import typed

__all__ = 'OAuth2Team', 'request_resource'


@typed
def request_resource(access_token, url: str,
                     method: str='GET', data: bytes=None):
    """Make a request to an API (protected resource),
    and then return the parsed JSON result.

    :param access_token: api access token string,
                         or :class:`~geofront.identity.Identity` instance
    :type access_token: :class:`str`, :class:`~geofront.identity.Identity`
    :param url: the api url to request
    :type url: :class:`str`
    :param method: an optional http method.  ``'GET'`` by default
    :type method: :class:`str`
    :param data: an optional content body
    :type data: :class:`bytes`
    :return: the response data (assuming its JSON)
    :rtype: :class:`collections.abc.Mapping`,
            :class:`collections.abc.Sequence`,
            :class:`numbers.Number`

    .. seealso:: :rfc:`6749#section-7` (section 7)

    .. versionchanged:: 0.3.0
       Moved from ``geofront.backend.github.request()`.

    """
    if isinstance(access_token, Identity):
        access_token = access_token.access_token
    req = urllib.request.Request(
        url,
        headers={
            'Authorization': 'bearer ' + access_token,
            'Accept': 'application/json'
        },
        method=method,
        data=data
    )
    with contextlib.closing(urllib.request.urlopen(req)) as response:
        content_type = get_content_type(response)
        mimetype, options = parse_options_header(content_type)
        assert mimetype == 'application/json' or method == 'DELETE', \
            'Content-Type of {} is not application/json but {}'.format(
                url,
                content_type
            )
        charset = options.get('charset', 'utf-8')
        response.readable = lambda: True
        response.writable = lambda: False
        response.seekable = lambda: False
        if not hasattr(response, 'closed'):
            response.closed = False
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


def get_content_type(response):
    try:
        return response.headers['content-type']
    except KeyError:
        for header_k, header_v in response.headers.items():
            if header_k.lower() == 'content-type':
                return header_v
        raise


class OAuth2Team(Team):
    """Abstract base class for :class:`~geofront.team.Team` implementations
    based on OAuth 2 authentication.  This abstracts out the details of
    2-legged OAuth 2 authentication process for the most part.

    What you have to provide are:

    - :const:`AUTHORIZE_URL` constant
    - :const:`ACCESS_TOKEN_URL` constant
    - :attr:`required_scopes` property
    - :meth:`determine_identity()` method
    - :meth:`~geofront.team.Team.authorize()` method
    - :meth:`~geofront.team.Team.list_groups()` method

    """

    #: (:class:`str`) The authorization endpoint url of the provider.
    #: For example, GitHub's is https://github.com/login/oauth/authorize.
    #:
    #: .. seealso:: :rfc:`6749#section-3.1` (section 3.1)
    AUTHORIZE_URL = NotImplemented

    #: (:class:`str`) The token endpoint url of the provider.
    #: For example, GitHub's is https://github.com/login/oauth/access_token.
    #:
    #: .. seealso:: :rfc:`6749#section-3.2` (section 3.2)
    ACCESS_TOKEN_URL = NotImplemented

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret

    @typed
    def request_authentication(self,
                               auth_nonce: str,
                               redirect_url: str) -> str:
        query = url_encode({
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_url,
            'scope': ' '.join(self.required_scopes),
            'state': auth_nonce
        })
        authorize_url = '{}?{}'.format(self.AUTHORIZE_URL, query)
        return authorize_url

    @typed
    def authenticate(self,
                     auth_nonce: str,
                     requested_redirect_url: str,
                     wsgi_environ: collections.abc.Mapping) -> Identity:
        req = Request(wsgi_environ, populate_request=False, shallow=True)
        try:
            code = req.args['code']
            if req.args['state'] != auth_nonce:
                raise AuthenticationError()
        except KeyError:
            raise AuthenticationError()
        data = url_encode({
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': requested_redirect_url
        }).encode()
        response = urllib.request.urlopen(self.ACCESS_TOKEN_URL, data)
        response.readable = lambda: True
        response.writable = lambda: False
        response.seekable = lambda: False
        if not hasattr(response, 'closed'):
            response.closed = False
        content_type = get_content_type(response)
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
        identity = self.determine_identity(token_data)
        if self.authorize(identity):
            return identity
        raise AuthenticationError('failed to authorize {!r}, which seems to '
                                  'have no enough permission'.format(identity))

    @property
    def required_scopes(self) -> collections.abc.Set:
        """(:class:`collections.abc.Set`) The set of scopes required for
        requesting protected resources (APIs).

        E.g. ``{'read:org', 'admin:public_key'}``.

        """
        raise NotImplementedError('required_scopes property has to '
                                  'be implemented')

    @typed
    def determine_identity(self, token_data) -> Identity:
        """After obtaining an access token its identity has to be determined
        using the token.  The most common way to do this is requesting
        an API which provides the information about who's the owner of
        the currently used access token.

        Some providers may provide the metadata about the token owner together
        with the access token during token obtaining phase.  In that case
        you don't have to request another API but can use the metadata
        about the token owner.  It would be included in ``token_data``.

        Some providers may has a concept of *groups*/*departments*,
        and you can make your :class:`~geofront.team.Team` implementation
        to force team members to ensure that he/she belongs to a particular
        group/department.  In that case you need to request an API which
        provides the information about teams the token owner belongs to.
        Refer the source code of :meth:`GitHubOrganization.determine_identity()
        <geofront.backends.github.GitHubOrganization.determine_identity>`.

        :param token_data: the obtained token data, returned by
                           provider's token endpoint.  it is usually
                           a mapping object, and the access token string
                           is in ``'access_token'`` key
        :return: the determined identity
        :rtype: :class:`~geofront.identity.Identity`

        """
        raise NotImplementedError('determine_identity() method has to '
                                  'be implemented')
