""":mod:`geofront.remote` --- Remote sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every remote set is represented as a mapping (which is immutable, or mutable)
of alias :class:`str` to :class:`Remote` object e.g.::

    {
        'web-1': Remote('ubuntu', '192.168.0.5'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.25'),
        'worker-2': Remote('ubuntu', '192.168.0.26'),
        'db-1': Remote('ubuntu', '192.168.0.50'),
        'db-2': Remote('ubuntu', '192.168.0.51')
    }

However, in the age of the cloud, you don't have to manage the remote set
since the most of cloud providers offer their API to list provisioned
remote nodes.

Geofront provides builtin :class:`~.backends.cloud.CloudRemoteSet`,
a subtype of :class:`collections.abc.Mapping`, that proxies to the list
dynamically made by cloud providers.

.. versionchanged:: group
   ``CloudRemoteSet`` is moved from this module to
   :mod:`geofront.backends.cloud`.
   See :class:`~.backends.cloud.CloudRemoteSet`.

"""
import collections.abc
import datetime
import io
import itertools
import numbers
import threading
import time

from paramiko.pkey import PKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport

from .keystore import format_openssh_pubkey, parse_openssh_pubkey
from .util import typed

__all__ = 'AuthorizedKeyList', 'Remote', 'authorize'


class Remote:
    """Remote node to SSH.

    :param user: the username to :program:`ssh`
    :type user: :class:`str`
    :param host: the host to access
    :type host: :class:`str`
    :param port: the port number to :program:`ssh`.
                 the default is 22 which is the default :program:`ssh` port
    :type port: :class:`numbers.Integral`
    :param metadata: optional metadata mapping.  keys and values have to
                     be all strings.  empty by default
    :type metadata: :class:`collections.abc.Mapping`

    .. versionchanged:: group
       Added optional ``metadata`` parameter.

    """

    #: (:class:`str`) The username to SSH.
    user = None

    #: (:class:`Address`) The hostname to access.
    host = None

    #: (:class:`numbers.Integral`) The port number to SSH.
    port = None

    #: (:class:`collections.abc.Mapping`) The additional metadata.
    #: Note that it won't affect to :func:`hash()` of the object,
    #: nor :token:`==`/:token:`!=` comparison of the object.
    #:
    #: .. versionadded:: group
    metadata = None

    @typed
    def __init__(self, user: str, host: str, port: numbers.Integral=22,
                 metadata: collections.abc.Mapping={}):
        self.user = user
        self.host = host
        self.port = port
        self.metadata = dict(metadata)

    def __eq__(self, other):
        return (isinstance(other, type(self)) and
                self.user == other.user and
                self.host == other.host and
                self.port == other.port)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.user, self.host, self.port))

    def __str__(self):  # pragma: no cover
        return '{}@{}:{}'.format(self.user, self.host, self.port)

    def __repr__(self):
        return '{0.__module__}.{0.__qualname__}{1!r}'.format(
            type(self), (self.user, self.host, self.port, self.metadata)
        )


class AuthorizedKeyList(collections.abc.MutableSequence):
    """List-like abstraction for remote :file:`authorized_keys`.

    Note that the contents are all lazily evaluated, so in order to
    pretend heavy duplicate communications over SFTP use :func:`list()`
    to eagerly evaluate e.g.::

        lazy_list = AuthorizedKeyList(sftp_client)
        eager_list = list(lazy_list)
        # ... some modifications on eager_list ...
        lazy_list[:] = eager_list

    :param sftp_client: the remote sftp connection to access
                        :file:`authorized_keys`
    :type sftp_client: :class:`paramiko.sftp_client.SFTPClient`

    """

    #: (:class:`str`) The path of :file:`authorized_keys` file.
    FILE_PATH = '.ssh/authorized_keys'

    @typed
    def __init__(self, sftp_client: SFTPClient):
        self.sftp_client = sftp_client

    def _iterate_lines(self):
        with io.BytesIO() as fo:
            self.sftp_client.getfo(self.FILE_PATH, fo)
            fo.seek(0)
            for line in fo:
                line = line.decode().strip()
                if line:
                    yield line

    def _save(self, authorized_keys: str):
        with io.BytesIO(authorized_keys.encode()) as fo:
            self.sftp_client.putfo(fo, self.FILE_PATH)

    def __iter__(self):
        for line in self._iterate_lines():
            line = line.strip()
            if line:
                yield parse_openssh_pubkey(line)

    def __len__(self):
        i = 0
        for _ in self._iterate_lines():
            i += 1
        return i

    def __getitem__(self, index):
        if isinstance(index, slice):
            lines = list(self._iterate_lines())
            return list(map(parse_openssh_pubkey, lines[index]))
        elif isinstance(index, numbers.Integral):
            if index >= 0:
                for i, line in enumerate(self._iterate_lines()):
                    if i == index:
                        return parse_openssh_pubkey(line)
            else:
                lines = list(self._iterate_lines())
                line = lines[index]
                return parse_openssh_pubkey(line)
            raise IndexError('authorized_keys out of range: ' + repr(index))
        raise TypeError(
            'authorized_keys indices must be integers, not '
            '{0.__module__}.{0.__qualname__}'.format(type(index))
        )

    def __setitem__(self, index, value):
        lines = list(self._iterate_lines())
        if isinstance(index, slice):
            lines[index] = map(format_openssh_pubkey, value)
        elif isinstance(index, numbers.Integral):
            lines[index] = format_openssh_pubkey(value)
        else:
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        self._save('\n'.join(lines))

    def insert(self, index, value):
        if not isinstance(index, numbers.Integral):
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        lines = list(self._iterate_lines())
        lines.insert(index, format_openssh_pubkey(value))
        self._save('\n'.join(lines))

    def extend(self, values):
        lines = itertools.chain(
            self._iterate_lines(),
            map(format_openssh_pubkey, values)
        )
        self._save('\n'.join(lines))

    def __delitem__(self, index):
        if not isinstance(index, (numbers.Integral, slice)):
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        lines = list(self._iterate_lines())
        del lines[index]
        self._save('\n'.join(lines))


@typed
def authorize(public_keys: collections.abc.Set,
              master_key: PKey,
              remote: Remote,
              timeout: datetime.timedelta) -> datetime.datetime:
    """Make an one-time authorization to the ``remote``, and then revokes
    it when ``timeout`` reaches soon.

    :param public_keys: the set of public keys (:class:`paramiko.pkey.PKey`)
                        to authorize
    :type public_keys: :class:`collections.abc.Set`
    :param master_key: the master key (*not owner's key*)
    :type master_key: :class:`paramiko.pkey.PKey`
    :param remote: a remote to grant access permission
    :type remote: :class:`~.remote.Remote`
    :param timeout: the time an authorization keeps alive
    :type timeout: :class:`datetime.timedelta`
    :return: the expiration time
    :rtype: :class:`datetime.datetime`

    """
    transport = Transport((remote.host, remote.port))
    transport.connect(username=remote.user, pkey=master_key)
    try:
        sftp_client = SFTPClient.from_transport(transport)
        try:
            authorized_keys = AuthorizedKeyList(sftp_client)
            authorized_keys.extend(public_keys)
        except:
            sftp_client.close()
            raise
    except:
        transport.close()
        raise

    def rollback():
        time.sleep(timeout.total_seconds())
        authorized_keys[:] = [master_key]
        sftp_client.close()
        transport.close()
    timer = threading.Thread(target=rollback)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + timeout
    timer.start()
    return expires_at
