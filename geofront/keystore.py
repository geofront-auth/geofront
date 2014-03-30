""":mod:`geofront.keystore` --- Public key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import base64
import enum

from .util import typed

__all__ = {'KeyType', 'PublicKey'}


class KeyType(enum.Enum):
    """SSH key types."""

    ecdsa_ssh2_nistp256 = 'ecdsa-sha2-nistp256'
    ecdsa_ssh2_nistp384 = 'ecdsa-sha2-nistp384'
    ecdsa_ssh2_nistp521 = 'ecdsa-sha2-nistp521'
    ssh_dss = 'ssh-dss'
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
        keytype, key, comment = line.split()
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
    def base64_key(self, base64_key):
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
