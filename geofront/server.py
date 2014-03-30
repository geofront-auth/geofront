""":mod:`geofront.server` --- Key management service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import argparse
import logging
import os
import os.path
import re
import warnings

from flask import Flask, Response, current_app, jsonify, request, url_for
from werkzeug.contrib.cache import BaseCache, SimpleCache
from werkzeug.exceptions import BadRequest, Forbidden, NotFound
from werkzeug.routing import BaseConverter, ValidationError

from .team import AuthenticationError, Team
from .util import typed

__all__ = {'TokenIdConverter', 'app', 'authenticate', 'create_access_token',
           'get_team', 'get_token_store', 'main', 'main_parser'}


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


def get_team() -> Team:
    """Get the configured team implementation, an instance of
    :class:`.team.Team`.

    It raises :exc:`RuntimeError` if ``'TEAM'`` is not configured.

    """
    try:
        team = current_app.config['TEAM']
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
        store = current_app.config['TOKEN_STORE']
    except KeyError:
        if current_app.debug:
            warnings.warn(
                'TOKEN_STORE configuration is not present, so use '
                '{0.__module__}.{0.__qualname__} instead.  This defaulting is '
                'only for debug purpose, and you must not expect it from '
                'production mode'.format(SimpleCache),
                RuntimeWarning
            )
            store = SimpleCache()
            current_app.config['TOKEN_STORE'] = store
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
    parser.add_argument('-d', '--debug', action='store_true', help='debug mode')
    return parser


def main():
    """The main function for :program:`geofront-server` CLI program."""
    parser = main_parser()
    args = parser.parse_args()
    try:
        app.config.from_pyfile(os.path.abspath(args.config), silent=False)
    except FileNotFoundError:
        parser.error('unable to load configuration file: ' + args.config)
    if args.debug:
        logger = logging.getLogger('geofront')
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(app.debug_log_format))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    app.run(args.host, args.port, debug=args.debug)


# If there is ``GEOFRONT_CONFIG`` environment variable, implicitly load
# the configuration file.  It's useful for using custom WSGI server e.g.::
#
#     $ GEOFRONT_CONFIG="/etc/geofront.cfg.py" gunicorn geofront.server:app
if 'GEOFRONT_CONFIG' in os.environ:
    app.config.from_pyfile(
        os.path.abspath(os.environ['GEOFRONT_CONFIG']),
        silent=False
    )
