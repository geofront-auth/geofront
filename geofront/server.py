""":mod:`geofront.server` --- Key management service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Although Geofront provides :program:`geofront-server`, a CLI to run
the server, it also provides an interface as a WSGI application as well.
Note that there might some limitations like lack of periodical master key
renewal.

First of all, the server need a configuration, there are several ways to
configure it.

:meth:`app.config.from_pyfile() <flask.Config.from_pyfile>`
    If you can freely execute arbitrary Python code before start the server,
    the method is the most straightforward way to configure the server.
    Note that the argument should be an absolute path, because it interprets
    paths relative to the path of Geofront program, not the current
    working directory (CWD).

    There also are other methods as well:

    - :meth:`~flask.Config.from_object()`
    - :meth:`~flask.Config.from_json()`
    - :meth:`~flask.Config.from_envvar()`

:envvar:`GEOFRONT_CONFIG`
    If you can't execute any arbitrary Python code,
    set the :envvar:`GEOFRONT_CONFIG` environment variable.
    It's useful when to use a CLI frontend of the WSGI server e.g.
    :program:`gunicorn`, :program:`waitress-serve`.

    .. code-block:: console

       $ GEOFRONT_CONFIG="/etc/geofront.cfg.py" gunicorn geofront.server:app

Then you can run a Geofront server using your favorite WSGI server.
Pass the following WSGI application object to the server.  It's a documented
endpoint for WSGI:

    :data:`geofront.server:app <app>`

"""
import argparse
import collections.abc
import datetime
import logging
import os
import os.path
import re
import warnings

from flask import (Flask, Response, current_app, helpers, json, jsonify,
                   make_response, request)
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException
from tsukkomi.typed import typechecked
from waitress import serve
from waitress.adjustments import Adjustments
from werkzeug.contrib.cache import BaseCache, SimpleCache
from werkzeug.exceptions import BadRequest, Forbidden, HTTPException, NotFound
from werkzeug.routing import BaseConverter, ValidationError
from werkzeug.utils import html
from werkzeug.contrib.fixers import ProxyFix

from .identity import Identity
from .keystore import (DuplicatePublicKeyError, KeyStore, KeyTypeError,
                       format_openssh_pubkey, get_key_fingerprint,
                       parse_openssh_pubkey)
from .masterkey import MasterKeyStore, PeriodicalRenewal
from .regen import RegenError, main_parser as regen_main_parser, regenerate
from .remote import (DefaultPermissionPolicy, PermissionPolicy, Remote,
                     authorize)
from .team import AuthenticationError, Team
from .version import VERSION

__all__ = ('AUTHORIZATION_TIMEOUT',
           'FingerprintConverter', 'Token', 'TokenIdConverter',
           'add_public_key', 'app', 'authenticate', 'authorize_remote',
           'create_access_token', 'delete_public_key', 'get_identity',
           'get_key_store', 'get_master_key_store', 'get_permission_policy',
           'get_public_key', 'get_remote_set', 'get_team', 'get_token_store',
           'list_public_keys', 'main', 'main_parser', 'master_key',
           'public_key', 'remote_dict', 'server_endpoint', 'server_version',
           'token', 'url_for')


#: (:class:`datetime.timedelta`) How long does each temporary authorization
#: keep alive after it's issued.  A minute.
AUTHORIZATION_TIMEOUT = datetime.timedelta(minutes=1)


class TokenIdConverter(BaseConverter):
    """Werkzeug custom converter which accepts valid token ids."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.regex = r'[A-Za-z0-9._-]{8,100}'
        self.pattern = re.compile('^\s*({})\s*$'.format(self.regex))

    def to_python(self, value):
        match = self.pattern.match(value)
        if match:
            return match.group(1)
        raise ValidationError()

    def to_url(self, value):
        match = self.pattern.match(value)
        if match:
            return match.group(1)
        raise ValueError(repr(value) + ' is an invalid token id')


class FingerprintConverter(BaseConverter):
    """Werkzeug custom converter which accepts valid public key
    fingerprints.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.regex = r'(?:[A-Fa-f0-9]{2}:){15}[A-Fa-f0-9]{2}'
        self.pattern = re.compile('^\s*({})\s*$'.format(self.regex))

    def to_python(self, value):
        match = self.pattern.match(value)
        if match:
            return bytes(int(hex_, 16) for hex_ in match.group(1).split(':'))
        raise ValidationError()

    @typechecked
    def to_url(self, value: bytes):
        return ':'.join(map('{:02x}'.format, value))


#: (:class:`flask.Flask`) The WSGI application of the server.
app = Flask(__name__)
app.url_map.converters.update(
    token_id=TokenIdConverter,
    fingerprint=FingerprintConverter
)
app.config.update(  # Config defaults
    PERMISSION_POLICY=DefaultPermissionPolicy(),
    MASTER_KEY_BITS=2048,
    MASTER_KEY_RENEWAL=datetime.timedelta(days=1),
    TOKEN_EXPIRE=datetime.timedelta(days=7),
    ENABLE_HSTS=False,
)


@app.after_request
def server_version(response: Response) -> Response:
    """Indicate the version of Geofront server using :mailheader:`Server`
    and :mailheader:`X-Geofront-Version` headers.

    """
    headers = response.headers
    headers['Server'] = 'Geofront/' + VERSION
    headers['X-Geofront-Version'] = VERSION
    return response


@app.after_request
def http_strict_transport_security(response: Response) -> Response:
    """Enable HSTS (HTTP strict transport security).

    .. seealso::

       `HTTP Strict Transport Security`__ --- Mozilla Developer Network

    .. versionadded:: 0.2.2

    __ https://developer.mozilla.org\
/en-US/docs/Web/Security/HTTP_strict_transport_security

    """
    if current_app.config.get('ENABLE_HSTS'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


def url_for(endpoint, **kwargs):
    """The almost same to :func:`flask.url_for()` except it's sensitive
    to ``PREFERRED_URL_SCHEME`` configuration.

    """
    try:
        scheme = current_app.config['PREFERRED_URL_SCHEME']
    except KeyError:
        return helpers.url_for(endpoint, **kwargs)
    return helpers.url_for(endpoint, _scheme=scheme, **kwargs)


@app.route('/')
def server_endpoint():
    """The endpoint of HTTP API which provide the url to create a new token.

    .. code-block:: http

       GET / HTTPS/1.1
       Accept: application/json

    .. code-block:: http

       HTTP/1.0 200 OK
       Content-Type: application/json
       Link: <https://example.com/tokens/>; rel=tokens

       {
         "tokens_url": "https://example.com/tokens/"
       }

    :resheader Link: the url to create a new token.  the equivalent to
                     the response content
    :status 200: when the server is available

    .. versionadded:: 0.2.0

    """
    tokens_url = url_for(
        'token',
        token_id='TOKEN_ID',
        _external=True
    ).replace('/TOKEN_ID/', '/')  # FIXME
    response = jsonify(tokens_url=tokens_url)
    response.headers.add('Link', '<{}>'.format(tokens_url), rel='tokens')
    return response


def get_team() -> Team:
    """Get the configured team implementation, an instance of
    :class:`.team.Team`.

    It raises :exc:`RuntimeError` if ``'TEAM'`` is not configured.

    """
    try:
        team = app.config['TEAM']
    except KeyError:
        raise RuntimeError('TEAM configuration is not present')
    if isinstance(team, Team):
        return team
    raise RuntimeError(
        'TEAM configuration must be an instance of {0.__module__}.'
        '{0.__qualname__}, not {1!r}'.format(Team, team)
    )


def get_token_store() -> BaseCache:
    """Get the configured token store, an instance of
    :class:`werkzeug.contrib.cache.BaseCache`.

    It raises :exc:`RuntimeError` if ``'TOKEN_STORE'`` is not configured,
    but it just warns :exc:`RuntimeWarning` when it comes to debug mode.

    :return: the configured session store
    :rtype: :class:`werkzeug.contrib.cache.BaseCache`
    :raise RuntimeError: when ``'TOKEN_STORE'`` is not configured, or
                         the value is not an instance of
                         :class:`werkzeug.contrib.cache.BaseCache`

    .. todo::

       Change the backend system from :mod:`werzkeug.contrib.cache`
       to :mod:`dogpile.cache`.

    """
    try:
        store = app.config['TOKEN_STORE']
    except KeyError:
        if app.debug:
            warnings.warn(
                'TOKEN_STORE configuration is not present, so use '
                '{0.__module__}.{0.__qualname__} instead.  This defaulting is '
                'only for debug purpose, and you must not expect it from '
                'production mode'.format(SimpleCache),
                RuntimeWarning
            )
            store = SimpleCache()
            app.config['TOKEN_STORE'] = store
        else:
            raise RuntimeError('TOKEN_STORE configuration is not present')
    if isinstance(store, BaseCache):
        return store
    raise RuntimeError(
        'TOKEN_STORE configuration must be an instance of {0.__module__}.'
        '{0.__qualname__}, not {1!r}'.format(BaseCache, store)
    )


#: (:class:`type`) The named tuple type that stores a token.
Token = collections.namedtuple('Token', 'identity, expires_at')


@app.route('/tokens/<token_id:token_id>/', methods=['PUT'])
@typechecked
def create_access_token(token_id: str):
    """Create a new access token.

    .. code-block:: http

       PUT /tokens/0123456789abcdef/ HTTPS/1.1
       Accept: application/json
       Content-Length: 0

    .. code-block:: http

       HTTPS/1.1 202 Accepted
       Content-Type: application/json
       Date: Tue, 15 Apr 2014 03:44:43 GMT
       Expires: Tue, 15 Apr 2014 04:14:43 GMT
       Link: <https://example.com/login/page/?redirect_uri=...>; rel=next

       {
         "next_url": "https://example.com/login/page/?redirect_uri=..."
       }

    :param token_id: an arbitrary token id to create.
                     it should be enough random to avoid duplication
    :type token_id: :class:`str`
    :status 202: when the access token is prepared
    :resheader Link: the link owner's browser should redirect to

    """
    token_store = get_token_store()
    team = get_team()
    timeout = 60 * 30  # wait for 30 minutes
    cont = team.request_authentication(
        url_for('authenticate', token_id=token_id, _external=True)
    )
    token_store.set(token_id, ('auth-state', cont.state), timeout)
    response = jsonify(next_url=cont.next_url)
    assert isinstance(response, Response)
    response.status_code = 202
    response.headers.add('Link', '<{}>'.format(cont.next_url), rel='next')
    response.expires = (datetime.datetime.now(datetime.timezone.utc) +
                        datetime.timedelta(seconds=timeout))
    return response


@app.route('/tokens/<token_id:token_id>/authenticate/')
@typechecked
def authenticate(token_id: str):
    """Finalize the authentication process.  It will be shown on web browser.

    :param token_id: token id created by :func:`create_access_token()`
    :type token_id: :class:`str`
    :status 400: when authentication is failed
    :status 404: when the given ``token_id`` doesn't exist
    :status 403: when the ``token_id`` is already finalized
    :status 200: when authentication is successfully done

    """
    token_store = get_token_store()
    team = get_team()
    token_expire = app.config['TOKEN_EXPIRE']
    if not isinstance(token_expire, datetime.timedelta):
        raise RuntimeError(
            'TOKEN_EXPIRE configuration must be an instance of '
            'datetime.timedelta, not {!r}'.format(token_expire)
        )
    try:
        state = token_store.get(token_id)
        current_app.logger.debug(
            'stored AuthenticationContinuation.state: %r',
            state
        )
    except TypeError:
        raise NotFound()
    if not isinstance(state, tuple) or state[0] != 'auth-state':
        raise Forbidden()
    requested_redirect_url = url_for(
        'authenticate',
        token_id=token_id,
        _external=True
    )
    try:
        identity = team.authenticate(
            state[1],
            requested_redirect_url,
            request.environ
        )
    except AuthenticationError:
        raise BadRequest()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + token_expire
    token_store.set(token_id, ('token', Token(identity, expires_at)),
                    timeout=int(token_expire.total_seconds()))
    return '<!DOCTYPE html>\n' + html.html(
        html.head(
            html.meta(charset='utf-8'),
            html.title('Geofront: Authentication success')
        ),
        html.body(
            html.h1(html.dfn('Geofront:'), ' Authentication success'),
            html.p('You may close the browser, and go back to the CLI.')
        )
    )


@typechecked
def get_identity(token_id: str) -> Identity:
    """Get the identity object from the given ``token_id``.

    :param token_id: the token id to get the identity it holds
    :type token_id: :class:`str`
    :return: the identity the token holds
    :rtype: :class:`~.identity.Identity`
    :raise werkzeug.exceptions.HTTPException:
        :http:statuscode:`404` (``token-not-found``)
        when the token does not exist.
        :http:statuscode:`412` (``unfinished-authentication``)
        when the authentication process is not finished yet.
        :http:statuscode:`410` (``expired-token``)
        when the token was expired.
        :http:statuscode:`403` (``not-authorized``)
        when the token is not unauthorized.

    """
    store = get_token_store()
    team = get_team()
    token = store.get(token_id)
    if not token:
        response = jsonify(
            error='token-not-found',
            message='Access token {0} does not exist.'.format(token_id)
        )
        response.status_code = 404
        raise HTTPException(response=response)
    elif not (isinstance(token, Token) or  # backward compat w/ <0.3.0
              isinstance(token, tuple) and
              token[0] == 'token' and
              isinstance(token[1], Token)):
        response = jsonify(
            error='unfinished-authentication',
            message='Authentication process is not finished yet.'
        )
        response.status_code = 412  # Precondition Failed
        raise HTTPException(response=response)
    if not isinstance(token, Token):  # backward compat w/ <0.3.0
        _, token = token
    if token.expires_at < datetime.datetime.now(datetime.timezone.utc):
        response = jsonify(
            error='expired-token',
            message='Access token {0} was expired. '
                    'Please authenticate again.'.format(token_id)
        )
        response.status_code = 410  # Gone
        raise HTTPException(response=response)
    elif team.authorize(token.identity):
        return token.identity
    response = jsonify(
        error='not-authorized',
        message='Access token {0} is unauthorized.'.format(token_id)
    )
    response.status_code = 403
    raise HTTPException(response=response)


@app.route('/tokens/<token_id:token_id>/')
@typechecked
def token(token_id: str):
    """The owner identity that the given token holds if the token is
    authenticated.  Otherwise it responds :http:statuscode:`403`,
    :http:statuscode:`404`, :http:statuscode:`410`, or
    :http:statuscode:`412`.  See also :func:`get_identity()`.

    .. code-block:: http

       GET /tokens/0123456789abcdef/ HTTPS/1.1
       Accept: application/json

    .. code-block:: http

       HTTPS/1.0 200 OK
       Content-Type: application/json
       Link: <https://example.com/tokens/0123456789abcdef/remo...>; rel=remotes
       Link: <https://example.com/tokens/0123456789abcdef/keys/>; rel=keys
       Link: <https://example.com/tokens/0123456789abcdef/ma...>; rel=masterkey

       {
         "identifier": "dahlia",
         "team_type": "geofront.backends.github.GitHubOrganization",
         "remotes_url": "https://example.com/tokens/0123456789abcdef/remotes/",
         "keys_url": "https://example.com/tokens/0123456789abcdef/keys/",
         "master_key_url": "https://example.com/tokens/0123456789abcdef/mas..."
       }

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :resheader Link: the url to list remotes (``rel=remotes``), public keys
                     (``rel=keys``), and master key (``rel=masterkey``)
    :status 200: when the token is authenticated

    .. versionchanged:: 0.2.0
       The response contains ``"remotes_url"``, ``"keys_url"``, and
       ``"master_key_url"``, and equivalent three :mailheader:`Link` headers.

    """
    identity = get_identity(token_id)
    links = {
        'remotes': url_for('list_remotes', token_id=token_id, _external=True),
        'keys': url_for('list_public_keys', token_id=token_id, _external=True),
        'master_key': url_for('master_key', token_id=token_id, _external=True)
    }
    response = jsonify(
        {rel + '_url': url for rel, url in links.items()},
        team_type='{0.__module__}.{0.__qualname__}'.format(identity.team_type),
        identifier=identity.identifier,
    )
    for rel, href in links.items():
        response.headers.add('Link', '<{}>'.format(href),
                             rel=rel.replace('_', ''))
    return response


def get_master_key_store() -> MasterKeyStore:
    """Get the configured master key store implementation.

    :return: the configured master key store
    :rtype: :class:`~.masterkey.MasterKeyStore`
    :raise RuntimeError: when ``'MASTER_KEY_STORE'`` is not configured,
                         or it's not an instance of
                         :class:`~.masterkey.MasterKeyStore`

    """
    try:
        master_key_store = app.config['MASTER_KEY_STORE']
    except KeyError:
        raise RuntimeError('MASTER_KEY_STORE configuration is not present')
    if isinstance(master_key_store, MasterKeyStore):
        return master_key_store
    raise RuntimeError(
        'MASTER_KEY_STORE configuration must be an instance of {0.__module__}.'
        '{0.__qualname__}, not {1!r}'.format(MasterKeyStore, master_key_store)
    )


@app.route('/tokens/<token_id:token_id>/masterkey/')
def master_key(token_id: str):
    """Public part of the master key in OpenSSH authorized_keys
    (public key) format.

    .. code-block:: http

       GET /tokens/0123456789abcdef/masterkey/ HTTPS/1.1
       Accept: text/plain

    .. code-block:: http

       HTTPS/1.1 200 OK
       Content-Type: text/plain

       ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDAEMUvjBcX.../MuLLzC/m8Q==

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :status 200: when the master key is available
    :status 500: when the master key is unavailable

    """
    get_identity(token_id)
    master_key_store = get_master_key_store()
    return format_openssh_pubkey(master_key_store.load()), 200, {
        'Content-Type': 'text/plain'
    }


def get_key_store() -> KeyStore:
    """Get the configured key store implementation.

    :return: the configured key store
    :rtype: :class:`~.keystore.KeyStore`
    :raise RuntimeError: when ``'KEY_STORE'`` is not configured, or
                         it's not an instance of :class:`~.keystore.KeyStore`

    """
    try:
        key_store = app.config['KEY_STORE']
    except KeyError:
        raise RuntimeError('KEY_STORE configuration is not present')
    if isinstance(key_store, KeyStore):
        return key_store
    raise RuntimeError(
        'KEY_STORE configuration must be an instance of {0.__module__}.'
        '{0.__qualname__}, not {1!r}'.format(KeyStore, key_store)
    )


@app.route('/tokens/<token_id:token_id>/keys/')
@typechecked
def list_public_keys(token_id: str):
    """List registered keys to the token owner.

    .. code-block:: http

       GET /tokens/0123456789abcdef/keys/ HTTPS/1.1
       Accept: application/json

    .. code-block:: http

       HTTPS/1.1 200 OK
       Content-Type: application/json

       {
         "50:5a:9a:12:75:8b:b0:88:7d:7a:8d:66:29:63:d0:47":
           "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDAEMUvjBcX.../MuLLzC/m8Q== ",
         "72:00:60:24:66:e8:2d:4d:2a:2a:a2:0e:7b:7f:fc:af":
           "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCom2CDLekY...5CeYsvSdrTWA5 ",
         "78:8a:09:c8:c1:24:5c:89:76:92:b0:1e:93:95:5d:48":
           "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA16iSKKjFHOgj...kD62SYXNKY9c= ",
         "ab:3a:fb:30:44:e3:5e:1e:10:a0:c9:9a:86:f4:67:59":
           "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzzF8c07pzgKk...r+b6Q9VnWWQ== "
       }

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :status 200: when listing is successful, even if there are no keys

    """
    identity = get_identity(token_id)
    key_store = get_key_store()
    keys = key_store.list_keys(identity)
    data = json.dumps({
        get_key_fingerprint(key): format_openssh_pubkey(key) for key in keys
    })
    return data, 200, {'Content-Type': 'application/json'}


@app.route('/tokens/<token_id:token_id>/keys/', methods=['POST'])
@typechecked
def add_public_key(token_id: str):
    """Register a public key to the token.  It takes an OpenSSH public key
    line through the request content body.

    .. code-block:: http

       POST /tokens/0123456789abcdef/keys/ HTTPS/1.1
       Accept: application/json
       Content-Type: text/plain

       ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDAEMUvjBcX.../MuLLzC/m8Q==

    .. code-block:: http

       HTTPS/1.1 201 Created
       Content-Type: text/plain
       Location: /tokens/0123456789abcdef/keys/\
50:5a:9a:12:75:8b:b0:88:7d:7a:8d:66:29:63:d0:47

       ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDAEMUvjBcX.../MuLLzC/m8Q==

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :status 201: when key registration is successful
    :status 400: (``unsupported-key-type``) when the key type is unsupported,
                 or (``invalid-key``) the key format is invalid,
                 or (``deuplicate-key``) the key is already used
    :status 415: (``unsupported-content-type``) when the
                 :mailheader:`Content-Type` is not :mimetype:`text/plain`

    """
    identity = get_identity(token_id)
    key_store = get_key_store()
    if request.mimetype != 'text/plain':
        response = jsonify(
            error='unsupported-content-type',
            message='it accepts only text/plain which is an OpenSSH '
                    'public key line'
        )
        response.status_code = 415  # Unsupported Media Type
        return response
    request_body = request.get_data(as_text=True)
    try:
        pkey = parse_openssh_pubkey(request_body)
    except KeyTypeError as e:
        response = jsonify(
            error='unsupported-key-type',
            message=str(e)
        )
        response.status_code = 400  # Bad Request
        return response
    except ValueError:
        response = jsonify(
            error='invalid-key',
            message='failed to parse the key'
        )
        response.status_code = 400
        return response
    try:
        key_store.register(identity, pkey)
    except DuplicatePublicKeyError:
        response = jsonify(
            error='duplicate-key',
            message='the given key is already used'
        )
        response.status_code = 400
        return response
    response = make_response(
        public_key(token_id=token_id, fingerprint=pkey.get_fingerprint())
    )
    response.status_code = 201  # Created
    response.location = url_for('public_key',
                                token_id=token_id,
                                fingerprint=pkey.get_fingerprint(),
                                _external=True)
    return response


@typechecked
def get_public_key(token_id: str, fingerprint: bytes) -> PKey:
    """Internal function to find the public key by its ``fingerprint``.

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :param fingerprint: the fingerprint of a public key to find
    :type fingerprint: :class:`bytes`
    :return: the found public key
    :rtype: :class:`paramiko.pkey.PKey`
    :raise werkzeug.exceptions.HTTPException: (``not-found``) when there's
                                              no such public key

    """
    identity = get_identity(token_id)
    key_store = get_key_store()
    keys = key_store.list_keys(identity)
    for key in keys:
        if key.get_fingerprint() == fingerprint:
            return key
    response = jsonify(
        error='not-found',
        message='No such public key: {}.'.format(
            ':'.join(map('{:02x}'.format, fingerprint))
        )
    )
    response.status_code = 404
    raise HTTPException(response=response)


@app.route('/tokens/<token_id:token_id>/keys/<fingerprint:fingerprint>/')
def public_key(token_id: str, fingerprint: bytes):
    """Find the public key by its ``fingerprint`` if it's registered.

    .. code-block:: http

       GET /tokens/0123456789abcdef/keys/\
50:5a:9a:12:75:8b:b0:88:7d:7a:8d:66:29:63:d0:47/ HTTPS/1.1
       Accept: text/plain

    .. code-block:: http

       HTTPS/1.1 200 OK
       Content-Type: text/plain

       ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDAEMUvjBcX.../MuLLzC/m8Q==

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :param fingerprint: the fingerprint of a public key to find
    :type fingerprint: :class:`bytes`
    :status 200: when the public key is registered
    :status 404: (``not-found``) when there's no such public key

    """
    key = get_public_key(token_id, fingerprint)
    return format_openssh_pubkey(key), 200, {'Content-Type': 'text/plain'}


@app.route('/tokens/<token_id:token_id>/keys/<fingerprint:fingerprint>/',
           methods=['DELETE'])
def delete_public_key(token_id: str, fingerprint: bytes):
    """Delete a public key.

    .. code-block:: http

       DELETE /tokens/0123456789abcdef/keys/\
50:5a:9a:12:75:8b:b0:88:7d:7a:8d:66:29:63:d0:47/ HTTPS/1.1
       Accept: application/json

    .. code-block:: http

       HTTPS/1.1 200 OK
       Content-Type: application/json

       {
         "72:00:60:24:66:e8:2d:4d:2a:2a:a2:0e:7b:7f:fc:af":
           "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCom2CDLekY...5CeYsvSdrTWA5 ",
         "78:8a:09:c8:c1:24:5c:89:76:92:b0:1e:93:95:5d:48":
           "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA16iSKKjFHOgj...kD62SYXNKY9c= ",
         "ab:3a:fb:30:44:e3:5e:1e:10:a0:c9:9a:86:f4:67:59":
           "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzzF8c07pzgKk...r+b6Q9VnWWQ== "
       }

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :param fingerprint: the fingerprint of a public key to delete
    :type fingerprint: :class:`bytes`
    :status 200: when the public key is successfully deleted
    :status 404: (``not-found``) when there's no such public key

    """
    key = get_public_key(token_id, fingerprint)
    get_key_store().deregister(get_identity(token_id), key)
    return make_response(list_public_keys(token_id))


def get_remote_set() -> collections.abc.Mapping:
    """Get the configured remote set.

    :return: the configured remote set
    :rtype: :class:`collections.abc.Mapping`
    :raise RuntimeError: if ``'REMOTE_SET'`` is not configured,
                         or it's not a mapping object

    """
    try:
        set_ = app.config['REMOTE_SET']
    except KeyError:
        raise RuntimeError('REMOTE_SET configuration is not present')
    if isinstance(set_, collections.abc.Mapping):
        return set_
    raise RuntimeError(
        'REMOTE_SET configuration must be an instance of {0.__module__}.'
        '{0.__qualname__}, not {1!r}'.format(collections.abc.Mapping, set_)
    )


def get_permission_policy() -> PermissionPolicy:
    """Get the configured permission policy.

    :return: the configured permission policy
    :rtype: :class:`~.remote.PermissionPolicy`
    :raise RuntimeError: if ``'PERMISSION_POLICY'`` is not configured,
                         or it's not an instance of
                         :class:`~.remote.PermissionPolicy`

    .. versionadded:: 0.2.0

    """
    try:
        policy = app.config['PERMISSION_POLICY']
    except KeyError:
        raise RuntimeError('PERMISSION_POLICY configuration is not present')
    if isinstance(policy, PermissionPolicy):
        return policy
    raise RuntimeError(
        'PERMISSION_POLICY configuration must be an instance of {0.__module__}'
        '.{0.__qualname__}, not {1!r}'.format(PermissionPolicy, policy)
    )


def remote_dict(remote: Remote) -> collections.abc.Mapping:
    """Convert a ``remote`` to a simple dictionary that can be serialized
    to JSON.

    :param remote: a remote instance to serialize
    :type remote: :class:`~.remote.Remote`
    :return: the converted dictionary
    :rtype: :class:`collections.abc.Mapping`

    """
    return {'user': remote.user, 'host': remote.host, 'port': remote.port}


@app.route('/tokens/<token_id:token_id>/remotes/')
def list_remotes(token_id: str):
    """List all available remotes and their aliases.

    .. code-block:: http

       GET /tokens/0123456789abcdef/remotes/ HTTPS/1.1
       Accept: application/json

    .. code-block:: http

       HTTPS/1.1 200 OK
       Content-Type: application/json

       {
         "web-1": {"user": "ubuntu", "host": "192.168.0.5", "port": 22},
         "web-2": {"user": "ubuntu", "host": "192.168.0.6", "port": 22},
         "web-3": {"user": "ubuntu", "host": "192.168.0.7", "port": 22},
         "worker-1": {"user": "ubuntu", "host": "192.168.0.25", "port": 22},
         "worker-2": {"user": "ubuntu", "host": "192.168.0.26", "port": 22},
         "db-1": {"user": "ubuntu", "host": "192.168.0.50", "port": 22},
         "db-2": {"user": "ubuntu", "host": "192.168.0.51", "port": 22}
       }

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :status 200: when listing is successful, even if there are no remotes

    .. todo:: Filter by query string.

    """
    team = get_team()
    identity = get_identity(token_id)  # 404/410 if not authenticated
    groups = team.list_groups(identity)
    policy = get_permission_policy()
    remotes = policy.filter(get_remote_set(), identity, groups)
    return jsonify(
        {alias: remote_dict(remote) for alias, remote in remotes.items()}
    )


@app.route('/tokens/<token_id:token_id>/remotes/<alias>/', methods=['POST'])
def authorize_remote(token_id: str, alias: str):
    """Temporarily authorize the token owner to access a remote.
    A made authorization keeps alive in a minute, and then will be expired.

    .. code-block:: http

       POST /tokens/0123456789abcdef/remotes/web-1/ HTTPS/1.1
       Accept: application/json
       Content-Length: 0

    .. code-block:: http

       HTTPS/1.1 200 OK
       Content-Type: application/json

       {
         "success": "authorized",
         "remote": {"user": "ubuntu", "host": "192.168.0.5", "port": 22},
         "expires_at": "2014-04-14T14:57:49.822844+00:00"
       }

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :param alias: the alias of the remote to access
    :type alias: :class:`str`
    :status 200: when successfully granted a temporary authorization
    :status 404: (``not-found``) when there's no such remote

    """
    team = get_team()
    identity = get_identity(token_id)
    key_store = get_key_store()
    master_key_store = get_master_key_store()
    remotes = get_remote_set()
    policy = get_permission_policy()
    try:
        remote = remotes[alias]
    except KeyError:
        response = jsonify(
            error='not-found',
            message='No such remote alias: {}.'.format(alias)
        )
        response.status_code = 404
        return response
    if not policy.permit(remote, identity, team.list_groups(identity)):
        response = jsonify(
            error='forbidden',
            message='Remote {0} is disallowed.  Contact the system '
                    'administrator.'.format(alias)
        )
        response.status_code = 403
        return response
    public_keys = key_store.list_keys(identity)
    master_key = master_key_store.load()
    remote_mapping = remote_dict(remote)
    try:
        expires_at = authorize(public_keys, master_key, remote,
                               AUTHORIZATION_TIMEOUT)
    except SSHException as e:
        response = jsonify(
            error='connection-failure',
            remote=remote_mapping,
            message=str(e)
        )
        response.status_code = 500
        return response
    return jsonify(
        success='authorized',
        remote=remote_mapping,
        expires_at=expires_at.isoformat()
    )


def main_parser() -> argparse.ArgumentParser:  # pragma: no cover
    """Create an :class:`~argparse.ArgumentParser` object for
    :program:`geofront-server` CLI program.  It also is used for
    documentation through `sphinxcontrib-autoprogram`__.

    :return: a properly configured :class:`~argparse.ArgumentParser`
    :rtype: :class:`argparse.ArgumentParser`

    __ https://pythonhosted.org/sphinxcontrib-autoprogram/

    """
    parser = argparse.ArgumentParser(
        description='Simple SSH key management service'
    )
    parser = regen_main_parser(parser)
    parser.add_argument('-H', '--host',
                        default='0.0.0.0',
                        help='host to bind [%(default)s]')
    parser.add_argument('-p', '--port',
                        default=5000,
                        help='port to bind [%(default)s]')
    parser.add_argument('--renew-master-key',
                        action='store_true',
                        help='renew the master key before the server starts. '
                             'implies --create-master-key option')
    parser.add_argument('--trusted-proxy',
                        action='store_true',
                        help='IP address of a client allowed to override '
                             'url_scheme via the X-Forwarded-Proto header. '
                             'useful when it runs behind reverse proxy. '
                             '-d/--debug option disables this option')
    parser.add_argument('--force-https',
                        action='store_true',
                        help='enable HSTS (HTTP strict transport security) '
                             'and set PREFERRED_URL_SCHEME to "https"')
    return parser


def main():  # pragma: no cover
    """The main function for :program:`geofront-server` CLI program."""
    parser = main_parser()
    args = parser.parse_args()
    try:
        app.config.from_pyfile(os.path.abspath(args.config), silent=False)
    except FileNotFoundError:
        parser.error('unable to load configuration file: ' + args.config)
    logger = logging.getLogger('geofront')
    handler = logging.StreamHandler()
    level = logging.DEBUG if args.debug else logging.INFO
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.setLevel(level)
    master_key_store = get_master_key_store()
    remote_set = get_remote_set()
    servers = frozenset(remote_set.values())
    master_key_bits = app.config['MASTER_KEY_BITS']
    if not isinstance(master_key_bits, int):
        parser.error('MASTER_KEYS_BITS configuration must be an integer, '
                     'not ' + repr(master_key_bits))
    elif master_key_bits < 1024:
        parser.error('MASTER_KEY_BITS has to be 1024 at least.')
    elif master_key_bits % 256:
        parser.error('MASTER_KEY_BITS has to be a multiple of 256.')
    try:
        regenerate(
            master_key_store,
            remote_set,
            master_key_bits,
            create_if_empty=args.create_master_key or args.renew_master_key,
            renew_unless_empty=(args.renew_master_key and
                                not os.environ.get('WERKZEUG_RUN_MAIN'))
        )
    except RegenError as e:
        parser.error(str(e))
    master_key_renewal_interval = app.config['MASTER_KEY_RENEWAL']
    if not (master_key_renewal_interval is None or
            isinstance(master_key_renewal_interval, datetime.timedelta)):
        raise RuntimeError(
            'MASTER_KEY_RENEWAL configuration must be an instance of '
            'datetime.timedelta, not {!r}'.format(master_key_renewal_interval)
        )
    if master_key_renewal_interval is not None:
        master_key_renewal = PeriodicalRenewal(
            servers,
            master_key_store,
            master_key_renewal_interval,
            master_key_bits
        )
    waitress_options = {}
    if args.trusted_proxy:
        if hasattr(Adjustments, 'trusted_proxy'):
            # > 0.8.8
            # https://github.com/Pylons/waitress/pull/42
            waitress_options['trusted_proxy'] = True
        else:
            # <= 0.8.8
            app.wsgi_app = ProxyFix(app.wsgi_app)
    if args.force_https:
        app.config.update(
            PREFERRED_URL_SCHEME='https',
            ENABLE_HSTS=True
        )
    try:
        if args.debug:
            app.run(args.host, int(args.port), debug=True)
        else:
            serve(app, host=args.host, port=args.port, asyncore_use_poll=True,
                  **waitress_options)
    finally:
        if master_key_renewal_interval is not None:
            master_key_renewal.terminate()


# If there is ``GEOFRONT_CONFIG`` environment variable, implicitly load
# the configuration file.  It's useful for using custom WSGI server e.g.::
#
#     $ GEOFRONT_CONFIG="/etc/geofront.cfg.py" gunicorn geofront.server:app
if 'GEOFRONT_CONFIG' in os.environ:  # pragma: no cover
    app.config.from_pyfile(
        os.path.abspath(os.environ['GEOFRONT_CONFIG']),
        silent=False
    )
