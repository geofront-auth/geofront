""":mod:`geofront.regen` --- Regen master key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 0.2.0

"""
import argparse
import logging
import os.path
from typing import Mapping, Optional, Tuple, Type

from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from typeguard import typechecked

from .keystore import get_key_fingerprint
from .masterkey import (EmptyStoreError, KeyGenerationError, MasterKeyStore,
                        generate_key, renew_master_key)
from .remote import RemoteSet
from .version import VERSION

__all__ = 'main', 'main_parser', 'get_regen_options', 'regenerate'


@typechecked
def main_parser(
    parser: argparse.ArgumentParser=None
) -> argparse.ArgumentParser:  # pragma: no cover
    """Create an :class:`~argparse.ArgumentParser` object for
    :program:`geofront-key-regen` CLI program.  It also is used for
    documentation through `sphinxcontrib-autoprogram`__.

    :return: a properly configured :class:`~argparse.ArgumentParser`
    :rtype: :class:`argparse.ArgumentParser`

    __ https://pythonhosted.org/sphinxcontrib-autoprogram/

    """
    parser = parser or argparse.ArgumentParser(
        description='Regen the Geofront master key'
    )
    parser.add_argument('config',
                        metavar='FILE',
                        help='geofront configuration file (Python script)')
    parser.add_argument('--create-master-key',
                        action='store_true',
                        help='create a new master key if no master key yet')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='debug mode')
    parser.add_argument('-v', '--version',
                        action='version',
                        version='%(prog)s ' + VERSION)
    return parser


@typechecked
def regenerate(master_key_store: MasterKeyStore,
               remote_set: RemoteSet,
               key_type: Type[PKey]=RSAKey,
               bits: Optional[int]=None,
               *,
               create_if_empty: bool,
               renew_unless_empty: bool) -> None:
    """Regenerate or create the master key."""
    logger = logging.getLogger(__name__ + '.regenerate')
    try:
        key = master_key_store.load()
    except EmptyStoreError:
        if create_if_empty:
            logger.warn('no master key;  create one...')
            key = generate_key(key_type, bits)
            master_key_store.save(key)
            logger.info('created new master key: %s', get_key_fingerprint(key))
        else:
            raise RegenError('no master key;  try --create-master-key option '
                             'if you want to create one')
    else:
        if renew_unless_empty:
            renew_master_key(frozenset(remote_set.values()),
                             master_key_store,
                             key_type, bits)


class RegenError(Exception):
    """Error raised by :func:`regenerate()`."""


def get_regen_options(config: Mapping[str, object]) -> Tuple[Type[PKey],
                                                             Optional[int]]:
    key_type = config.get('MASTER_KEY_TYPE', RSAKey)
    if not isinstance(key_type, type):
        raise RegenOptionError('MASTER_KEY_TYPE configuration must be a type, '
                               'not ' + repr(key_type))
    elif not issubclass(key_type, PKey):
        raise RegenOptionError(
            'MASTER_KEY_TYPE configuration must be a subclass of '
            '{0.__module__}.{0.__qualname__}, but {1.__module__}.'
            '{1.__qualname__} is not'.format(PKey, key_type)
        )
    bits = config['MASTER_KEY_BITS']
    if bits is not None and not isinstance(bits, int):
        raise RegenOptionError('MASTER_KEY_BITS configuration must be an '
                               'integer, not ' + repr(bits))
    return RSAKey, bits


class RegenOptionError(RegenError):
    """Error raised by :func:`get_regen_options()`."""


def main():  # pragma: no cover
    """The main function of :program:`geofront-key-regen` CLI program."""
    from .server import app, get_master_key_store, get_remote_set
    parser = main_parser()
    args = parser.parse_args()
    try:
        app.config.from_pyfile(os.path.abspath(args.config), silent=False)
    except FileNotFoundError:
        parser.error('unable to load configuration file: ' + args.config)
    logger = logging.getLogger('geofront.masterkey')
    handler = logging.StreamHandler()
    level = logging.DEBUG if args.debug else logging.INFO
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.setLevel(level)
    try:
        regenerate(
            get_master_key_store(),
            get_remote_set(),
            *get_regen_options(app.config),
            create_if_empty=args.create_master_key,
            renew_unless_empty=True
        )
    except KeyGenerationError as e:
        parser.error(str(e))
    except RegenError as e:
        parser.error(str(e))
