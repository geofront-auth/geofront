""":mod:`geofront.keystore` --- Public key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import base64
import collections.abc
import enum

from .identity import Identity
from .util import typed

__all__ = {'KeyStore', 'KeyType', 'PublicKey'}


class KeyType(enum.Enum):
    """SSH key types."""

    #: (:class:`KeyType`) ECDSA NIST P-256.
    ecdsa_ssh2_nistp256 = 'ecdsa-sha2-nistp256'

    #: (:class:`KeyType`) ECDSA NIST P-384.
    ecdsa_ssh2_nistp384 = 'ecdsa-sha2-nistp384'

    #: (:class:`KeyType`) ECDSA NIST P-521.
    ecdsa_ssh2_nistp521 = 'ecdsa-sha2-nistp521'

    #: (:class:`KeyType`) DSA.
    ssh_dss = 'ssh-dss'

    #: (:class:`KeyType`) RSA.
    ssh_rsa = 'ssh-rsa'

    def __repr__(self):
        return '{0.__module__}.{0.__qualname__}.{1}'.format(
            type(self),
            self.name
        )


class PublicKey:
    """Public key for SSH.

    :param keytype: the keytype
    :type keytype: :class:`KeyType`
    :param key: keyword-only parameter.  the raw :class:`bytes` of the key.
                it cannot be used together with ``base64_key`` parameter
    :type key: :class:`bytes`
    :param base64_key: keyword-only parameter.  the base64-encoded form
                       of the key.  it cannot be used together with ``key``
                       parameter
    :type base64_key: :class:`str`
    :param comment: keyword-only parameter.  an optional comment
    :type comment: :class:`str`

    """

    #: (:class:`KeyType`) The keytype.
    keytype = None

    #: (:class:`bytes`) The raw :class:`bytes` of the key.
    key = None

    #: (:class:`str`) Optional comment.  Note that this is ignored when
    #: it's compared to other public key (using :token:`==` or :token`!=`),
    #: or hashed (using :func:`hash()` function).
    comment = None

    @classmethod
    def parse_line(cls, line):
        """Parse a line of ``authorized_keys`` list.

        :param line: a line of ``authorized_keys`` list
        :type line: :class:`bytes`, :class:`str`
        :return: the parsed public key
        :rtype: :class:`PublicKey`
        :raise ValueError: when the given ``line`` is invalid

        """
        if isinstance(line, bytes):
            line = line.decode()
        elif not isinstance(line, str):
            raise TypeError('line must be str or bytes, not ' + repr(line))
        tup = line.split()
        if len(tup) == 2:
            keytype, key = tup
            comment = None
        elif len(tup) == 3:
            keytype, key, comment = tup
        else:
            raise ValueError('line should consist of two or three columns')
        return cls(KeyType(keytype), base64_key=key, comment=comment)

    @typed
    def __init__(self, keytype: KeyType, *,
                 key: bytes=None, base64_key: str=None, comment: str=None):
        self.keytype = keytype
        if key and base64_key:
            raise TypeError('key and base64_key arguments cannot be set '
                            'at a time')
        elif key:
            self.key = key
        elif base64_key:
            self.base64_key = base64_key
        else:
            raise TypeError('key or base64_key must be filled')
        self.comment = comment if comment and comment.strip() else None

    @property
    def base64_key(self):
        """(:class:`str`) Base64-encoded form of :attr:`key`."""
        return base64.b64encode(self.key).decode()

    @base64_key.setter
    @typed
    def base64_key(self, base64_key: str):
        self.key = base64.b64decode(base64_key)

    def __eq__(self, other):
        return (isinstance(other, type(self)) and
                self.keytype == other.keytype and
                self.key == other.key)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.keytype, self.key))

    def __str__(self):
        return '{} {} {}'.format(
            self.keytype.value,
            self.base64_key,
            self.comment
        )

    def __bytes__(self):
        return str(self).encode()

    def __repr__(self):
        fmt = '{0.__module__}.{0.__qualname__}({1!r}, key={2!r}, comment={3!r})'
        return fmt.format(type(self), self.keytype, self.key, self.comment)


class KeyStore:
    """The key store backend interface."""

    @typed
    def register(self, identity: Identity, public_key: PublicKey):
        """Register the given ``public_key`` to the ``identity``.

        :param ientity: the owner identity
        :type identity: :class:`~.identity.Identity`
        :param public_key: the public key to register
        :type public_key: :class:`PublicKey`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store


        """
        raise NotImplementedError('register() has to be implemented')

    @typed
    def list_keys(self, identity: Identity) -> collections.abc.Set:
        """List registered public keys of the given ``identity``.

        :param identity: the owner of keys to list
        :type identity: :class:`~.identity.Identity`
        :return: the set of :class:`PublicKey` owned by the ``identity``
        :rtype: :class:`collections.abc.Set`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('lookup() has to be implemented')

    @typed
    def deregister(self, identity: Identity, public_key: PublicKey):
        """Remove the given ``public_key`` of the ``identity``.
        It silently does nothing if there isn't the given ``public_key``
        in the store.

        :param ientity: the owner identity
        :type identity: :class:`~.identity.Identity`
        :param public_key: the public key to remove
        :type public_key: :class:`PublicKey`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('deregister() has to be implemented')


class AuthorizationError(Exception):
    """Authorization exception that rise when the given identity has
    no required permission to the key store.

    """