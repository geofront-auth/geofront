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

"""
import collections.abc
import datetime
import io
import logging
import os.path
import threading

from libcloud.storage.base import Container, StorageDriver
from libcloud.storage.types import ObjectDoesNotExistError
from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from paramiko.sftp_client import SFTPClient
from paramiko.ssh_exception import SSHException
from paramiko.transport import Transport

from .keystore import get_key_fingerprint
from .remote import AuthorizedKeyList, Remote
from .util import typed

__all__ = ('CloudMasterKeyStore', 'EmptyStoreError',
           'FileSystemMasterKeyStore', 'MasterKeyStore',
           'PeriodicalRenewal', 'TwoPhaseRenewal',
           'read_private_key_file', 'renew_master_key')


class MasterKeyStore:
    """The master key store backend interface.  It can have only one
    master key at the most.

    """

    @typed
    def load(self) -> PKey:
        """Load the stored master key.

        :return: the stored master key
        :rtype: :class:`paramiko.pkey.PKey`
        :raise geofront.masterkey.EmptyStoreError:
            when there's no master key yet in the store

        """
        raise NotImplementedError('load() has to be implemented')

    @typed
    def save(self, master_key: PKey):
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

    :param servers: the set of :class:`~geofront.remote.Remote` servers
                    to renew their master key
    :type servers: :class:`collections.abc.Set`
    :param old_key: the previous master key to expire
    :type old_key: :class:`paramiko.pkey.PKey`
    :param new_key: the new master key to replace ``old_key``
    :type new_key: :class:`paramiko.pkey.PKey`

    """

    def __init__(self,
                 servers: collections.abc.Set,
                 old_key: PKey,
                 new_key: PKey):
        for server in servers:
            if not isinstance(server, Remote):
                raise TypeError('{0!r} is not an instance of {1.__module__}.'
                                '{1.__qualname__}'.format(server, Remote))
        self.servers = servers
        self.old_key = old_key
        self.new_key = new_key
        self.sftp_clients = None

    def __enter__(self):
        assert self.sftp_clients is None, 'the context is already started'
        sftp_clients = {}
        for server in self.servers:
            try:
                transport = Transport((server.host, server.port))
                transport.connect(pkey=self.old_key)
            except SSHException:
                for t, _, __ in sftp_clients.values():
                    t.close()
                raise
            sftp_client = SFTPClient.from_transport(transport)
            authorized_keys = AuthorizedKeyList(sftp_client)
            sftp_clients[server] = transport, sftp_client, authorized_keys
            authorized_keys.append(self.new_key)
        self.sftp_clients = sftp_clients
        return self.servers

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self.sftp_clients is not None, 'the context is not started yet'
        for transport, client, authorized_keys in self.sftp_clients.values():
            if exc_val is None:
                authorized_keys[:] = [self.new_key]
            client.close()
            transport.close()
        self.sftp_clients = None


def renew_master_key(servers: collections.abc.Set,
                     key_store: MasterKeyStore) -> PKey:
    """Renew the master key.  It creates a new master key, makes ``servers``
    to authorize the new key, replaces the existing master key with the
    new key in the ``key_store``, and then makes ``servers`` to deauthorize
    the old key.  All these operations are done in a two-phase renewal
    transaction.

    :param servers: servers to renew the master key.
                    every element has to be an instance of
                    :class:`~.remote.Remote`
    :type servers: :class:`collections.abc.Set`
    :param key_store: the master key store to update
    :type key_store: :class:`MasterKeyStore`
    :returns: the created new master key
    :rtype: :class:`paramiko.pkey.PKey`

    """
    logger = logging.getLogger(__name__ + '.renew_master_key')
    logger.info('renew the master key...')
    old_key = key_store.load()
    logger.info('the existing master key: %s', get_key_fingerprint(old_key))
    new_key = RSAKey.generate(1024)
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
    :type servers: :class:`collections.abc.Set`
    :param key_store: the master key store to update
    :type key_store: :class:`MasterKeyStore`
    :param interval: the interval to renew
    :type interval: :class:`datetime.timedelta`
    :param start: whether to start the background thread immediately.
                  :const:`True` by default
    :type start: :class:`bool`

    """

    @typed
    def __init__(self,
                 servers: collections.abc.Set,
                 key_store: MasterKeyStore,
                 interval: datetime.timedelta,
                 start: bool=True):
        super().__init__()
        self.servers = servers
        self.key_store = key_store
        self.interval = interval
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
            renew_master_key(self.servers, self.key_store)

    def terminate(self):
        """Graceful termination."""
        self.terminated.set()
        self.join(5)


class FileSystemMasterKeyStore(MasterKeyStore):
    """Store the master key into the file system.  Although not that secure,
    but it might help you to try out Geofront.

    :param path: the path to save file.  it has to end with the filename
    :type path: :class:`str`
    :raise OSError: when the ``path`` is not writable

    """

    @typed
    def __init__(self, path: str):
        dirname = os.path.dirname(path)
        if not os.path.isdir(dirname):
            raise NotADirectoryError(dirname + ' is not a directory')
        elif os.path.isdir(path):
            raise IsADirectoryError(path + ' is not a file, but a directory')
        self.path = path

    @typed
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

    @typed
    def save(self, master_key: PKey):
        master_key.write_private_key_file(self.path)


class CloudMasterKeyStore(MasterKeyStore):
    """Store the master key into the cloud object storage e.g. AWS S3_.
    It supports more than 20 cloud providers through the efforts of Libcloud_.
    ::

        from geofront.masterkey import CloudMasterKeyStore
        from libcloud.storage.types import Provider
        from libcloud.storage.providers import get_driver

        driver_cls = get_driver(Provider.S3)
        driver = driver_cls('api key', 'api secret key')
        container = driver.get_container(container_name='my-master-key-bucket')
        MASTER_KEY_STORE = CloudMasterKeyStore(container)

    :param driver: the libcloud storage driver
    :type driver: :class:`libcloud.storage.base.StorageDriver`
    :param container: the block storage container
    :type container: :class:`libcloud.storage.base.Container`
    :param object_name: the object name to use
    :type object_name: :class:`str`

    .. seealso::

       `Object Storage`__ --- Libcloud
          Storage API allows you to manage cloud object storage and
          services such as Amazon S3, Rackspace CloudFiles,
          Google Storage and others.

    .. _S3: http://aws.amazon.com/s3/
    .. _Libcloud: http://libcloud.apache.org/
    __ https://libcloud.readthedocs.org/en/latest/storage/

    """

    @typed
    def __init__(self,
                 driver: StorageDriver,
                 container: Container,
                 object_name: str):
        self.driver = driver
        self.container = container
        self.object_name = object_name

    @typed
    def load(self) -> PKey:
        try:
            obj = self.driver.get_object(self.container.name, self.object_name)
        except ObjectDoesNotExistError:
            raise EmptyStoreError()
        with io.BytesIO() as buffer_:
            for chunk in self.driver.download_object_as_stream(obj):
                if isinstance(chunk, str):  # DummyDriver yields str, not bytes
                    chunk = chunk.encode()
                buffer_.write(chunk)
            buffer_.seek(0)
            with io.TextIOWrapper(buffer_) as tio:
                return read_private_key_file(tio)

    @typed
    def save(self, master_key: PKey):
        with io.StringIO() as buffer_:
            master_key.write_private_key(buffer_)
            pem = buffer_.getvalue()
        self.driver.upload_object_via_stream(
            self._countable_iterator([pem]),
            self.container,
            self.object_name,
            {'content_type': 'application/x-pem-key'}
        )

    class _countable_iterator:
        """libcloud's storage driver takes an iterator as stream,
        but some drivers e.g. dummy driver try calling :func:`len()`
        to the iterator.  This adapter workarounds the situation.

        """

        @typed
        def __init__(self, sequence: collections.abc.Sequence):
            self.iterator = iter(sequence)
            self.length = len(sequence)

        def __len__(self):
            return self.length

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.iterator)