""":mod:`geofront.masterkey` --- Master key management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import os.path

from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException

from .util import typed

__all__ = {'EmptyStoreError', 'FileSystemMasterKeyStore', 'MasterKeyStore'}


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
