""":mod:`geofront.masterkey` --- Master key management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import io
import os.path

from libcloud.storage.base import Container, StorageDriver
from libcloud.storage.types import ObjectDoesNotExistError
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException

from .util import typed

__all__ = ('CloudMasterKeyStore', 'EmptyStoreError',
           'FileSystemMasterKeyStore', 'MasterKeyStore',
           'read_private_key_file')


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
        with io.StringIO() as buffer_:
            for chunk in self.driver.download_object_as_stream(obj):
                buffer_.write(chunk)
            buffer_.seek(0)
            return read_private_key_file(buffer_)

    @typed
    def save(self, master_key: PKey):
        with io.StringIO() as buffer_:
            master_key.write_private_key(buffer_)
            pem = buffer_.getvalue()
        self.driver.upload_object_via_stream(
            [pem],
            self.container,
            self.object_name,
            {'content_type': 'application/x-pem-key'}
        )
