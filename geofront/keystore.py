""":mod:`geofront.keystore` --- Public key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import base64
import collections.abc
import enum

from paramiko.dsskey import DSSKey
from paramiko.rsakey import RSAKey
from paramiko.pkey import PKey

from .identity import Identity
from .util import typed

__all__ = {'KEY_TYPES', 'AuthorizationError', 'DuplicatePublicKeyError',
           'KeyStore', 'KeyStoreError', 'format_openssh_pubkey',
           'parse_openssh_pubkey'}


#: (:class:`collections.Mapping`) The mapping of supported key types.
KEY_TYPES = {
    'ssh-rsa': RSAKey,
    'ssh-dss': DSSKey
}


@typed
def parse_openssh_pubkey(line: str) -> PKey:
    """Parse an OpenSSH public key line, used by :file:`authorized_keys`,
    :file:`id_rsa.pub`, etc.

    :param line: a line of public key
    :type line: :class:`str`
    :return: the parsed public key
    :rtype: :class:`paramiko.pkey.PKey`
    :raise ValueError: when the given ``line`` is an invalid format,
                       or it's an unsupported key type

    """
    keytype, b64, *_ = line.split()
    try:
        cls = KEY_TYPES[keytype]
    except KeyError:
        raise ValueError('unsupported key type: ' + repr(keytype))
    return cls(data=base64.b64decode(b64))


@typed
def format_openssh_pubkey(key: PKey) -> str:
    """Format the given ``key`` to an OpenSSH public key line, used by
    :file:`authorized_keys`, :file:`id_rsa.pub`, etc.

    :param key: the key object to format
    :type key: :class:`paramiko.pkey.PKey`
    :return: a formatted openssh public key line
    :rtype: :class:`str`

    """
    return '{} {} '.format(key.get_name(), key.get_base64())


class KeyStore:
    """The key store backend interface.  Every key store has to guarantee
    that public keys are unique for all identities i.e. the same public key
    can't be registered across more than an identity.

    """

    @typed
    def register(self, identity: Identity, public_key: PKey):
        """Register the given ``public_key`` to the ``identity``.

        :param ientity: the owner identity
        :type identity: :class:`~.identity.Identity`
        :param public_key: the public key to register
        :type public_key: :class:`paramiko.pkey.PKey`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store
        :raise geofront.keystore.DuplicatePublicKeyError:
            when the ``public_key`` is already in use


        """
        raise NotImplementedError('register() has to be implemented')

    @typed
    def list_keys(self, identity: Identity) -> collections.abc.Set:
        """List registered public keys of the given ``identity``.

        :param identity: the owner of keys to list
        :type identity: :class:`~.identity.Identity`
        :return: the set of :class:`paramiko.pkey.PKey`
                 owned by the ``identity``
        :rtype: :class:`collections.abc.Set`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('list_keys() has to be implemented')

    @typed
    def deregister(self, identity: Identity, public_key: PKey):
        """Remove the given ``public_key`` of the ``identity``.
        It silently does nothing if there isn't the given ``public_key``
        in the store.

        :param ientity: the owner identity
        :type identity: :class:`~.identity.Identity`
        :param public_key: the public key to remove
        :type public_key: :class:`paramiko.pkey.PKey`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('deregister() has to be implemented')


class KeyStoreError(Exception):
    """Exceptions related to :class:`KeyStore` are an instance of this."""


class AuthorizationError(KeyStoreError):
    """Authorization exception that rise when the given identity has
    no required permission to the key store.

    """


class DuplicatePublicKeyError(KeyStoreError):
    """Exception that rise when the given public key is already registered."""
