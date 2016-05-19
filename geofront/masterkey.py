""":mod:`geofront.masterkey` --- Master key management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Master key renewal process:

1. Create a new master key without updating the master key store.
2. Update every :file:`authorized_keys` to authorize both the previous
   and the new master keys.
3. Store the new master key to the master key store,
   and remove the previous master key.
4. Update very :file:`authorized_keys` to authorize only
   the new master key.

For more details, see also :class:`TwoPhaseRenewal`.

.. versionchanged:: 0.2.0
   ``CloudMasterKeyStore`` is moved from this module to
   :mod:`geofront.backends.cloud`.
   See :class:`~.backends.cloud.CloudMasterKeyStore`.

"""
import datetime
import io
import logging
import os.path
import socket
import threading
import typing

from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from paramiko.sftp_client import SFTPClient
from paramiko.ssh_exception import SSHException
from paramiko.transport import Transport
from tsukkomi.typed import typechecked

from .keystore import get_key_fingerprint
from .remote import AuthorizedKeyList, Remote

__all__ = ('EmptyStoreError', 'FileSystemMasterKeyStore', 'MasterKeyStore',
           'PeriodicalRenewal', 'TwoPhaseRenewal',
           'read_private_key_file', 'renew_master_key')


class MasterKeyStore:
    """The master key store backend interface.  It can have only one
    master key at the most.

    """

    @typechecked
    def load(self) -> PKey:
        """Load the stored master key.

        :return: the stored master key
        :rtype: :class:`paramiko.pkey.PKey`
        :raise geofront.masterkey.EmptyStoreError:
            when there's no master key yet in the store

        """
        raise NotImplementedError('load() has to be implemented')

    @typechecked
    def save(self, master_key: PKey) -> None:
        """Remove the stored master key, and then save the new master key.
        The operation should be atomic.

        :param master_key: the new master key to replace the existing
                           master key
        :type master_key: :class:`paramiko.pkey.PKey`

        """
        raise NotImplementedError('save() has to be implemented')


class EmptyStoreError(Exception):
    """Exception that rises when there's no master key yet in the store."""


def read_private_key_file(file_: io.IOBase) -> PKey:
    """Read a private key file.  Similar to :meth:`PKey.from_private_key()
    <paramiko.pkey.PKey.from_private_key>` except it guess the key type.

    :param file_: a stream of the private key to read
    :type file_: :class:`io.IOBase`
    :return: the read private key
    :rtype: :class:`paramiko.pkey.PKery`
    :raise paramiko.ssh_exception.SSHException: when something goes wrong

    """
    classes = PKey.__subclasses__()
    last = len(classes) + 1
    for i, cls in enumerate(classes):
        try:
            return cls.from_private_key(file_)
        except SSHException:
            if i == last:
                raise
            file_.seek(0)
            continue


class TwoPhaseRenewal:
    """Renew the master key for the given ``servers``.  It's a context
    manager for :keyword:`with` statement.

    ::

        # State: servers allow only old_key;
        #        old_key is in the master_key_store
        with TwoPhaseRenewal(servers, old_key, new_key):
            # State: *servers allow both old_key and new_key;*
            #        old_key is in the master_key_store
            master_key_store.save(new_key)
            # State: servers allow both old_key and new_key;
            #        *new_key is in the master_key_store.*
        # State: *servers allow only new_key;*
        #        new_key is in the master_key_store

    :param servers: the set of :class:`~.remote.Remote` servers
                    to renew their master key
    :type servers: :class:`typing.AbstractSet`[:class:`~.remote.Remote`]
    :param old_key: the previous master key to expire
    :type old_key: :class:`paramiko.pkey.PKey`
    :param new_key: the new master key to replace ``old_key``
    :type new_key: :class:`paramiko.pkey.PKey`

    """

    def __init__(self,
                 servers: typing.AbstractSet[Remote],
                 old_key: PKey,
                 new_key: PKey) -> None:
        for server in servers:
            if not isinstance(server, Remote):
                raise TypeError('{0!r} is not an instance of {1.__module__}.'
                                '{1.__qualname__}'.format(server, Remote))
        self.servers = servers
        self.old_key = old_key
        self.new_key = new_key
        self.sftp_clients = None

    def __enter__(self) -> typing.AbstractSet[Remote]:
        assert self.sftp_clients is None, 'the context is already started'
        sftp_clients = {}
        for server in self.servers:
            try:
                transport = Transport((server.host, server.port))
                transport.connect(username=server.user, pkey=self.old_key)
            except (OSError, SSHException) as e:
                for t, _, __ in sftp_clients.values():
                    t.close()
                l = logging.getLogger(__name__ + '.TwoPhaseRenewal.__enter__')
                l.exception(
                    'An exception rise during master key renewal '
                    '(%s -> %s, server: %s@%s:%d): %s',
                    get_key_fingerprint(self.old_key),
                    get_key_fingerprint(self.new_key),
                    server.user, server.host, server.port, str(e)
                )
                raise
            except socket.gaierror as e:
                raise ConnectionError(
                    'failed to connect: {0!s}\n{1!s}'.format(server, e)
                ) from e
            sftp_client = SFTPClient.from_transport(transport)
            authorized_keys = AuthorizedKeyList(sftp_client)
            sftp_clients[server] = transport, sftp_client, authorized_keys
            authorized_keys.append(self.new_key)
        self.sftp_clients = sftp_clients
        return self.servers

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        assert self.sftp_clients is not None, 'the context is not started yet'
        for transport, client, authorized_keys in self.sftp_clients.values():
            if exc_val is None:
                authorized_keys[:] = [self.new_key]
            client.close()
            transport.close()
        self.sftp_clients = None


@typechecked
def renew_master_key(servers: typing.AbstractSet[Remote],
                     key_store: MasterKeyStore,
                     bits: int=2048) -> PKey:
    """Renew the master key.  It creates a new master key, makes ``servers``
    to authorize the new key, replaces the existing master key with the
    new key in the ``key_store``, and then makes ``servers`` to deauthorize
    the old key.  All these operations are done in a two-phase renewal
    transaction.

    :param servers: servers to renew the master key.
                    every element has to be an instance of
                    :class:`~.remote.Remote`
    :type servers: :class:`typing.AbstractSet`[:class:`~.remote.Remote`]
    :param key_store: the master key store to update
    :type key_store: :class:`MasterKeyStore`
    :param bits: the number of bits the generated key should be.
                 it has to be 1024 at least, and a multiple of 256.
                 2048 by default
    :type bits: :class:`int`
    :returns: the created new master key
    :rtype: :class:`paramiko.pkey.PKey`

    .. versionadded:: 0.2.0
       The ``bits`` optional parameter.

    """
    logger = logging.getLogger(__name__ + '.renew_master_key')
    logger.info('renew the master key...')
    old_key = key_store.load()
    logger.info('the existing master key: %s', get_key_fingerprint(old_key))
    new_key = RSAKey.generate(bits)
    logger.info('created new master key: %s', get_key_fingerprint(new_key))
    logger.info('authorize the new master key...')
    with TwoPhaseRenewal(servers, old_key, new_key):
        logger.info('the new master key is authorized; '
                    'update the key store...')
        key_store.save(new_key)
        logger.info('master key store is successfully updated; '
                    'deauthorize the existing master key...')
    logger.info('master key renewal has finished')
    return new_key


class PeriodicalRenewal(threading.Thread):
    """Periodically renew the master key in the separated background thread.

    :param servers: servers to renew the master key.
                    every element has to be an instance of
                    :class:`~.remote.Remote`
    :type servers: :class:`typing.AbstractSet`[:class:`~.remote.Remote`]
    :param key_store: the master key store to update
    :type key_store: :class:`MasterKeyStore`
    :param interval: the interval to renew
    :type interval: :class:`datetime.timedelta`
    :param bits: the number of bits the generated key should be.
                 it has to be 1024 at least, and a multiple of 256.
                 2048 by default
    :type bits: :class:`int`
    :param start: whether to start the background thread immediately.
                  :const:`True` by default
    :type start: :class:`bool`

    .. versionadded:: 0.2.0
       The ``bits`` optional parameter.

    """

    @typechecked
    def __init__(self,
                 servers: typing.AbstractSet[Remote],
                 key_store: MasterKeyStore,
                 interval: datetime.timedelta,
                 bits: int=2048,
                 start: bool=True):
        super().__init__()
        self.servers = servers
        self.key_store = key_store
        self.interval = interval
        self.bits = bits
        self.terminated = threading.Event()
        if self.start:
            self.start()

    def run(self):
        seconds = self.interval.total_seconds()
        terminated = self.terminated
        while not terminated.is_set():
            terminated.wait(seconds)
            if terminated.is_set():
                break
            renew_master_key(self.servers, self.key_store, self.bits)

    def terminate(self):
        """Graceful termination."""
        self.terminated.set()
        self.join(5)


class FileSystemMasterKeyStore(MasterKeyStore):
    """Store the master key into the file system.  Although not that secure,
    but it might help you to evaluate Geofront.

    :param path: the path to save file.  it has to end with the filename
    :type path: :class:`str`
    :raise OSError: when the ``path`` is not writable

    """

    @typechecked
    def __init__(self, path: str) -> None:
        dirname = os.path.dirname(path)
        if not os.path.isdir(dirname):
            raise NotADirectoryError(dirname + ' is not a directory')
        elif os.path.isdir(path):
            raise IsADirectoryError(path + ' is not a file, but a directory')
        self.path = path

    @typechecked
    def load(self) -> PKey:
        if os.path.isfile(self.path):
            classes = PKey.__subclasses__()
            last = len(classes) + 1
            for i, cls in enumerate(classes):
                try:
                    return cls.from_private_key_file(self.path)
                except SSHException:
                    if i == last:
                        raise
                    continue
        raise EmptyStoreError()

    @typechecked
    def save(self, master_key: PKey) -> None:
        master_key.write_private_key_file(self.path)
