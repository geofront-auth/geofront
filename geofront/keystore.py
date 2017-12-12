""":mod:`geofront.keystore` --- Public key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import base64
from typing import TYPE_CHECKING, AbstractSet

from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from typeguard import typechecked

from .identity import Identity

if TYPE_CHECKING:
    from typing import Mapping, Type  # noqa: F401

__all__ = ('KEY_TYPES', 'AuthorizationError', 'DuplicatePublicKeyError',
           'KeyStore', 'KeyStoreError', 'KeyTypeError',
           'format_openssh_pubkey', 'get_key_fingerprint',
           'parse_openssh_pubkey')


#: (:class:`~typing.Mapping`\ [:class:`str`,
#: :class:`~typing.Type`\ [:class:`~paramiko.pkey.Pkey`]])
#: The mapping of supported key types.
#:
#: .. versionadded:: 0.4.0
#:    Added ``ecdsa-sha2-nistp256``, ``ecdsa-sha2-nistp384``, and
#:    ``ecdsa-sha2-nistp521`` (:class:`~paramiko.ecdsakey.ECDSAKey`) support.
#:
#: .. versionadded:: 0.4.1
#:    Added ``ssh-ed25519`` (:class:`~paramiko.ed25519key.Ed25519Key`) support.
KEY_TYPES = {
    'ssh-rsa': RSAKey,
    'ssh-dss': DSSKey,
    'ssh-ed25519': Ed25519Key,
    'ecdsa-sha2-nistp256': ECDSAKey,
    'ecdsa-sha2-nistp384': ECDSAKey,
    'ecdsa-sha2-nistp521': ECDSAKey,
}  # type: Mapping[str, Type[PKey]]


@typechecked
def parse_openssh_pubkey(line: str) -> PKey:
    """Parse an OpenSSH public key line, used by :file:`authorized_keys`,
    :file:`id_rsa.pub`, etc.

    :param line: a line of public key
    :type line: :class:`str`
    :return: the parsed public key
    :rtype: :class:`paramiko.pkey.PKey`
    :raise ValueError: when the given ``line`` is an invalid format
    :raise KeyTypeError: when it's an unsupported key type

    .. versionchanged:: 0.4.0
       Added ``ecdsa-sha2-nistp256``, ``ecdsa-sha2-nistp384``, and
       ``ecdsa-sha2-nistp521`` (:class:`~paramiko.ecdsakey.ECDSAKey`)
       support.

    """
    keytype, b64, *_ = line.split()
    try:
        cls = KEY_TYPES[keytype]
    except KeyError:
        raise KeyTypeError('unsupported key type: ' + repr(keytype))
    return cls(data=base64.b64decode(b64))


@typechecked
def format_openssh_pubkey(key: PKey) -> str:
    """Format the given ``key`` to an OpenSSH public key line, used by
    :file:`authorized_keys`, :file:`id_rsa.pub`, etc.

    :param key: the key object to format
    :type key: :class:`paramiko.pkey.PKey`
    :return: a formatted openssh public key line
    :rtype: :class:`str`

    """
    return '{} {} '.format(key.get_name(), key.get_base64())


@typechecked
def get_key_fingerprint(key: PKey, glue: str=':') -> str:
    """Get the hexadecimal fingerprint string of the ``key``.

    :param key: the key to get fingerprint
    :type key: :class:`paramiko.pkey.PKey`
    :param glue: glue character to be placed between bytes.
                 ``':'`` by default
    :type glue: :class:`str`
    :return: the fingerprint string
    :rtype: :class:`str`

    """
    return glue.join(map('{:02x}'.format, key.get_fingerprint()))


class KeyStore:
    """The key store backend interface.  Every key store has to guarantee
    that public keys are unique for all identities i.e. the same public key
    can't be registered across more than an identity.

    """

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
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

    @typechecked
    def list_keys(self, identity: Identity) -> AbstractSet[PKey]:
        """List registered public keys of the given ``identity``.

        :param identity: the owner of keys to list
        :type identity: :class:`~.identity.Identity`
        :return: the set of :class:`paramiko.pkey.PKey`
                 owned by the ``identity``
        :rtype: :class:`~typing.AbstractSet`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('list_keys() has to be implemented')

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
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


class KeyTypeError(ValueError):
    """Unsupported public key type raise this type of error."""
