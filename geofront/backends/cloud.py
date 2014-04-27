""":mod:`geofront.backends.cloud` --- Libcloud_-backed implementations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides built-in implementations of Geofront's some core
interfaces through libcloud.  Libcloud_ is "a library for interacting
with many of the popular cloud service providers using unified API."

.. versionadded:: 0.2.0

.. _Libcloud: http://libcloud.apache.org/

"""
import collections.abc
try:
    from functools import singledispatch
except ImportError:
    from singledispatch import singledispatch
import io
import numbers

from libcloud.compute.base import Node, NodeDriver
from libcloud.compute.drivers.gce import GCENodeDriver
from libcloud.storage.base import Container, StorageDriver
from libcloud.storage.types import ObjectDoesNotExistError
from paramiko.pkey import PKey

from ..masterkey import EmptyStoreError, MasterKeyStore, read_private_key_file
from ..remote import Remote
from ..util import typed

__all__ = 'CloudMasterKeyStore', 'CloudRemoteSet'


class CloudRemoteSet(collections.abc.Mapping):
    """Libcloud_-backed remote set.  It supports more than 20 cloud providers
    through the efforts of Libcloud_. ::

        from geofront.remote import CloudRemoteSet
        from libcloud.compute.types import Provider
        from libcloud.compute.providers import get_driver

        driver_cls = get_driver(Provider.EC2_US_WEST)
        driver = driver_cls('access id', 'secret key')
        REMOTE_SET = CloudRemoteSet(driver)

    If the given ``driver`` supports metadata feature (for example,
    AWS EC2, Google Compute Engine, and OpenStack support it)
    the resulted :class:`~geofront.remote.Remote` objects will
    fill their :attr:`~geofront.remote.Remote.metadata` as well.

    :param driver: libcloud compute driver
    :type driver: :class:`libcloud.compute.base.NodeDriver`
    :param user: the username to :program:`ssh`.
                 the default is ``'ec2-user'`` which is the default user
                 of amazon linux ami
    :type user: :class:`str`
    :param port: the port number to :program:`ssh`.
                the default is 22 which is the default :program:`ssh` port
    :type port: :class:`numbers.Integral`

    .. seealso::

       `Compute`__ --- Libcloud
          The compute component of libcloud allows you to manage
          cloud and virtual servers offered by different providers,
          more than 20 in total.

    .. _Libcloud: http://libcloud.apache.org/
    __ https://libcloud.readthedocs.org/en/latest/compute/

    .. versionchanged:: 0.2.0
       It fills :attr:`~geofront.remote.Remote.metadata` of the resulted
       :class:`~geofront.remote.Remote` objects if the ``driver`` supports.

    """

    @typed
    def __init__(self,
                 driver: NodeDriver,
                 user: str='ec2-user',
                 port: numbers.Integral=22):
        self.driver = driver
        self.user = user
        self.port = port
        self._nodes = None
        self._metadata = {} if supports_metadata(driver) else None

    def _get_nodes(self, refresh: bool=False) -> dict:
        if refresh or self._nodes is None:
            self._nodes = {node.name: node
                           for node in self.driver.list_nodes()
                           if node.public_ips}
            if self._metadata is not None:
                self._metadata.clear()
        return self._nodes

    def __len__(self) -> int:
        return len(self._get_nodes())

    def __iter__(self) -> collections.abc.Iterator:
        return iter(self._get_nodes(True))

    def __getitem__(self, alias: str) -> Remote:
        node = self._get_nodes()[alias]
        if self._metadata is None:
            metadata = {}
        else:
            try:
                metadata = self._metadata[alias]
            except KeyError:
                metadata = get_metadata(self.driver, node)
                self._metadata[alias] = metadata
        return Remote(self.user, node.public_ips[0], self.port, metadata)


@singledispatch
def supports_metadata(driver: NodeDriver) -> bool:
    """Whether this drive type supports metadata?"""
    return callable(getattr(driver, 'ex_get_metadata', None))


@singledispatch
def get_metadata(driver: NodeDriver, node: Node) -> collections.abc.Mapping:
    return driver.ex_get_metadata(node)


@supports_metadata.register(GCENodeDriver)
def gce_supports_metadata(driver: GCENodeDriver) -> bool:
    return True


@get_metadata.register(GCENodeDriver)
def gce_get_metadata(driver: GCENodeDriver,
                     node: Node) -> collections.abc.Mapping:
    return node.extra['metadata']


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
