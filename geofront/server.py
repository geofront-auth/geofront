""":mod:`geofront.server` --- Key management service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import argparse
import collections.abc
import logging
import os
import os.path
import re
import warnings

from flask import Flask, Response, current_app, json, jsonify, request, url_for
from paramiko.rsakey import RSAKey
from waitress import serve
from werkzeug.contrib.cache import BaseCache, SimpleCache
from werkzeug.exceptions import BadRequest, Forbidden, HTTPException, NotFound
from werkzeug.routing import BaseConverter, ValidationError

from .identity import Identity
from .keystore import KeyStore, format_openssh_pubkey, get_key_fingerprint
from .masterkey import EmptyStoreError, MasterKeyStore, TwoPhaseRenewal
from .team import AuthenticationError, Team
from .util import typed
from .version import VERSION

__all__ = ('TokenIdConverter', 'app', 'authenticate', 'create_access_token',
           'get_identity', 'get_key_store', 'get_master_key_store',
           'get_remote_set', 'get_team', 'get_token_store', 'list_keys',
           'main', 'main_parser', 'server_version')


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


#: (:class:`flask.Flask`) The WSGI application of the server.
app = Flask(__name__)
app.url_map.converters['token_id'] = TokenIdConverter


@app.after_request
def server_version(response: Response) -> Response:
    """Indicate the version of Geofront server using :mailheader:`Server`
    and :mailheader:`X-Geofront-Version` headers.

    """
    headers = response.headers
    headers['Server'] = 'Geofront/' + VERSION
    headers['X-Geofront-Version'] = VERSION
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


@app.route('/tokens/<token_id:token_id>/', methods=['PUT'])
@typed
def create_access_token(token_id: str):
    """Create a new access token.

    :param token_id: an arbitrary token id to create.
                     it should be enough random to avoid duplication
    :type token_id: :class:`str`
    :status 202: when the access token is prepared
    :resheader Link: the link owner's browser should redirect to

    .. todo:: Token should be expired.

    """
    token_store = get_token_store()
    team = get_team()
    auth_nonce = ''.join(map('{:02x}'.format, os.urandom(16)))
    current_app.logger.debug('created auth_nonce: %r', auth_nonce)
    token_store.set(token_id, (False, auth_nonce))
    next_url = team.request_authentication(
        auth_nonce,
        url_for('authenticate', token_id=token_id, _external=True)
    )
    response = jsonify(next_url=next_url)
    assert isinstance(response, Response)
    response.status_code = 202
    response.headers['Link'] = '<{0}>; rel=next'.format(next_url)
    return response


@app.route('/tokens/<token_id:token_id>/authenticate/')
@typed
def authenticate(token_id: str):
    """Finalize the authentication process.

    :param token_id: token id created by :func:`create_access_token()`
    :type token_id: :class:`str`
    :status 400: when authentication is failed
    :status 404: when the given ``token_id`` doesn't exist
    :status 403: when the ``token_id`` is already finalized
    :status 200: when authentication is successfully done

    """
    token_store = get_token_store()
    team = get_team()
    try:
        finished, auth_nonce = token_store.get(token_id)
        current_app.logger.debug('stored auth_nonce: %r', auth_nonce)
    except TypeError:
        raise NotFound()
    if finished:
        raise Forbidden()
    requested_redirect_url = url_for(
        'authenticate',
        token_id=token_id,
        _external=True
    )
    try:
        identity = team.authenticate(
            auth_nonce,
            requested_redirect_url,
            request.environ
        )
    except AuthenticationError:
        raise BadRequest()
    token_store.set(token_id, (True, identity))
    return 'Authentication success: close the browser tab, and back to CLI'


@typed
def get_identity(token_id: str) -> Identity:
    """Get the identity object from the given ``token_id``.

    :param token_id: the token id to get the identity it holds
    :type token_id: :class:`str`
    :return: the identity the token holds
    :rtype: :class:`~.identity.Identity`
    :raise werkzeug.exceptions.HTTPException:
        :http:statuscode:`404` when the token does not exist.
        :http:statuscode:`412` when the authentication process is not
        finished yet.
        :http:statuscode:`403` when the token is not unauthorized

    """
    store = get_token_store()
    team = get_team()
    pair = store.get(token_id)
    if not pair:
        response = jsonify(
            error='token-not-found',
            message='Access token {0} does not exist.'.format(token_id)
        )
        response.status_code = 404
        raise HTTPException(response=response)
    finished, identity = pair
    if not finished:
        response = jsonify(
            error='unfinished-authentication',
            message='Authentication process is not finished yet.'
        )
        response.status_code = 412  # Precondition Failed
        raise HTTPException(response=response)
    if team.authorize(identity):
        return identity
    response = jsonify(
        error='not-authorized',
        message='Access token {0} is unauthorized.'.format(token_id)
    )
    response.status_code = 403
    raise HTTPException(response=response)


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
@typed
def list_keys(token_id: str):
    """List registered keys to the token owner.

    :param token_id: the token id that holds the identity
    :type token_id: :class:`str`
    :status 200: when listing is successful, even if there are no keys

    """
    identity = get_identity(token_id)
    key_store = get_key_store()
    keys = key_store.list_keys(identity)
    data = json.dumps([format_openssh_pubkey(key) for key in keys])
    return data, 200, {'Content-Type': 'application/json'}


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


def main_parser() -> argparse.ArgumentParser:
    """Create an :class:`~argparse.ArgumentParser` object for
    :program:`geofront-server` CLI program.

    :return: a properly configured :class:`~argparse.ArgumentParser`
    :rtype: :class:`argparse.ArgumentParser`

    """
    parser = argparse.ArgumentParser(
        description='Simple SSH key management service'
    )
    parser.add_argument('config',
                        metavar='FILE',
                        help='geofront configuration file (Python script)')
    parser.add_argument('-H', '--host',
                        default='0.0.0.0',
                        help='host to bind [%(default)s]')
    parser.add_argument('-p', '--port',
                        default=5000,
                        help='port to bind [%(default)s]')
    parser.add_argument('--create-master-key',
                        action='store_true',
                        help='create a new master key if no master key yet')
    parser.add_argument('--renew-master-key',
                        action='store_true',
                        help='renew the master key before the server starts. '
                             'implies --create-master-key option')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='debug mode.  note that this option may make '
                             'slowdown')
    parser.add_argument('-v', '--version',
                        action='version',
                        version='%(prog)s ' + VERSION)
    return parser


def main():
    """The main function for :program:`geofront-server` CLI program."""
    parser = main_parser()
    args = parser.parse_args()
    try:
        app.config.from_pyfile(os.path.abspath(args.config), silent=False)
    except FileNotFoundError:
        parser.error('unable to load configuration file: ' + args.config)
    main_logger = logging.getLogger(__name__ + '.main')
    handler = logging.StreamHandler()
    if args.debug:
        logger = logging.getLogger('geofront')
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    else:
        main_logger.addHandler(handler)
        handler.setLevel(logging.INFO)
        main_logger.setLevel(logging.INFO)
    master_key_store = get_master_key_store()
    try:
        key = master_key_store.load()
    except EmptyStoreError:
        if args.create_master_key or args.renew_master_key:
            main_logger.warn('no master key;  create one...')
            key = RSAKey.generate(1024)
            master_key_store.save(key)
            main_logger.info('created new master key: %s',
                             get_key_fingerprint(key))
        else:
            parser.error('no master key;  try --create-master-key option '
                         'if you want to create one')
    else:
        if args.renew_master_key and not os.environ.get('WERKZEUG_RUN_MAIN'):
            main_logger.info('renew the master key...')
            main_logger.info('the existing master key: %s',
                             get_key_fingerprint(key))
            new_key = RSAKey.generate(1024)
            main_logger.info('created new master key: %s',
                             get_key_fingerprint(new_key))
            servers = frozenset(get_remote_set().values())
            main_logger.info('authorize the new master key...')
            with TwoPhaseRenewal(servers, key, new_key):
                main_logger.info('the new master key is authorized; '
                                 'update the key store...')
                master_key_store.save(new_key)
                main_logger.info('master key store is successfully updated; '
                                 'deauthorize the existing master key...')
            main_logger.info('master key renewal has finished')
    if args.debug:
        app.run(args.host, args.port, debug=True)
    else:
        serve(app, host=args.host, port=args.port, asyncore_use_poll=True)


# If there is ``GEOFRONT_CONFIG`` environment variable, implicitly load
# the configuration file.  It's useful for using custom WSGI server e.g.::
#
#     $ GEOFRONT_CONFIG="/etc/geofront.cfg.py" gunicorn geofront.server:app
if 'GEOFRONT_CONFIG' in os.environ:
    app.config.from_pyfile(
        os.path.abspath(os.environ['GEOFRONT_CONFIG']),
        silent=False
    )
