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
    from singledispatch import singledispatch  # type: ignore
import io
import os.path
import re
import tempfile
from typing import (TYPE_CHECKING,
                    AbstractSet, Callable, Iterator, Mapping, Sequence)
from typing.re import Pattern  # type: ignore  # noqa: I901
import xml.etree.ElementTree

from libcloud.common.types import MalformedResponseError
from libcloud.compute.base import Node, NodeDriver
from libcloud.compute.drivers.ec2 import EC2NodeDriver
from libcloud.compute.drivers.gce import GCENodeDriver
from libcloud.compute.types import KeyPairDoesNotExistError
from libcloud.storage.base import Container, StorageDriver
from libcloud.storage.drivers.s3 import S3StorageDriver
from libcloud.storage.types import ObjectDoesNotExistError
from paramiko.ecdsakey import ECDSAKey
from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from typeguard import typechecked

from ..identity import Identity
from ..keystore import (DuplicatePublicKeyError, KeyStore,
                        format_openssh_pubkey, get_key_fingerprint,
                        parse_openssh_pubkey)
from ..masterkey import EmptyStoreError, MasterKeyStore, read_private_key_file
from ..remote import Remote

if TYPE_CHECKING:
    from typing import MutableMapping, Optional  # noqa: F401

__all__ = ('CloudKeyStore', 'CloudMasterKeyStore', 'CloudMasterPublicKeyStore',
           'CloudRemoteSet')


class CloudRemoteSet(collections.abc.Mapping):
    """Libcloud_-backed remote set.  It supports more than 20 cloud providers
    through the efforts of Libcloud_. ::

        from geofront.backends.cloud import CloudRemoteSet
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
    :type port: :class:`int`
    :param alias_namer: A function to name an alias for the given node.
                        :attr:`Node.name <libcloud.compute.base.Node.name>`
                        is used by default.
    :type alias_nameer:
        :class:`~typing.Callable`\ [[:class:`libcloud.compute.base.Node`],
                                    :class:`str`]

    .. seealso::

       `Compute`__ --- Libcloud
          The compute component of libcloud allows you to manage
          cloud and virtual servers offered by different providers,
          more than 20 in total.

    .. _Libcloud: http://libcloud.apache.org/
    __ https://libcloud.readthedocs.org/en/latest/compute/

    .. versionadded:: 0.4.0

    .. versionchanged:: 0.2.0
       It fills :attr:`~geofront.remote.Remote.metadata` of the resulted
       :class:`~geofront.remote.Remote` objects if the ``driver`` supports.

    """

    @typechecked
    def __init__(
        self,
        driver: NodeDriver,
        user: str='ec2-user',
        port: int=22,
        alias_namer: Callable[[Node], str]=lambda node: node.name
    ) -> None:
        self.driver = driver
        self.user = user
        self.port = port
        self.alias_namer = alias_namer
        self._nodes = None  # type: Optional[Mapping[str, Node]]
        self._metadata = {} if supports_metadata(driver) else None  \
            # type: Optional[MutableMapping[str, object]]

    def _get_nodes(self, refresh: bool=False) -> Mapping[str, Node]:
        if refresh or self._nodes is None:
            make_alias = self.alias_namer
            self._nodes = {make_alias(node): node
                           for node in self.driver.list_nodes()
                           if node.public_ips}
            if self._metadata is not None:
                self._metadata.clear()
        return self._nodes

    def __len__(self) -> int:
        return len(self._get_nodes())

    def __iter__(self) -> Iterator[str]:
        return iter(self._get_nodes(True))

    def __getitem__(self, alias: str) -> Remote:
        node = self._get_nodes()[alias]
        if self._metadata is None:
            metadata = {}  # type: object
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
def get_metadata(driver: NodeDriver, node: Node) -> Mapping[str, object]:
    return driver.ex_get_metadata(node)


@supports_metadata.register(GCENodeDriver)
def gce_supports_metadata(driver: GCENodeDriver) -> bool:
    return True


@get_metadata.register(GCENodeDriver)
def gce_get_metadata(driver: GCENodeDriver,
                     node: Node) -> Mapping[str, object]:
    return node.extra['metadata']


class CloudMasterKeyStore(MasterKeyStore):
    """Store the master key into the cloud object storage e.g. AWS S3_.
    It supports more than 20 cloud providers through the efforts of Libcloud_.
    ::

        from geofront.backends.cloud import CloudMasterKeyStore
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

    @typechecked
    def __init__(self,
                 driver: StorageDriver,
                 container: Container,
                 object_name: str) -> None:
        self.driver = driver
        self.container = container
        self.object_name = object_name

    @typechecked
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

    @typechecked
    def save(self, master_key: PKey) -> None:
        extra = {'content_type': 'application/x-pem-key'}
        if isinstance(self.driver, S3StorageDriver):
            # On some cases (altough unknown condition), S3 driver failed to
            # match signature when it uploads object through stream.
            # This is workaround to upload the master key without stream.
            with tempfile.NamedTemporaryFile('w+', encoding='utf-8') as f:
                master_key.write_private_key(f)
                getattr(f, 'file').flush()  # workaround mypy
                self.driver.upload_object(
                    f.name, self.container, self.object_name, extra
                )
            return
        with io.StringIO() as buffer_:
            master_key.write_private_key(buffer_)
            pem = getattr(buffer_, 'getvalue')()  # workaround mypy
        self.driver.upload_object_via_stream(
            type(self)._countable_iterator([pem]),
            self.container,
            self.object_name,
            extra
        )

    class _countable_iterator:
        """libcloud's storage driver takes an iterator as stream,
        but some drivers e.g. dummy driver try calling :func:`len()`
        to the iterator.  This adapter workarounds the situation.

        """

        @typechecked
        def __init__(self, sequence: Sequence[object]) -> None:
            self.iterator = iter(sequence)
            self.length = len(sequence)

        def __len__(self):
            return self.length

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.iterator)


class CloudKeyStore(KeyStore):
    """Store public keys into the cloud provider's key pair service.
    Note that not all providers support key pair service.  For example,
    Amazon EC2, and Rackspace (Next Gen) support it.  ::

        from geofront.backends.cloud import CloudKeyStore
        from libcloud.compute.types import Provider
        from libcloud.compute.providers import get_driver

        driver_cls = get_driver(Provider.EC2)
        driver = driver_cls('api key', 'api secret key')
        KEY_STORE = CloudKeyStore(driver)

    :param driver: libcloud compute driver
    :type driver: :class:`libcloud.compute.base.NodeDriver`
    :param key_name_format: the format which determines each key's name
                            used for the key pair service.
                            default is :const:`DEFAULT_KEY_NAME_FORMAT`
    :type key_name_format: :class:`str`

    """

    #: (:class:`str`) The default ``key_name_format``.  The type name of
    #: team followed by identifier, and then key fingerprint follows e.g.
    #: ``'geofront.backends.github.GitHubOrganization dahlia 00:11:22:..:ff'``.
    DEFAULT_KEY_NAME_FORMAT = ('{identity.team_type.__module__}.'
                               '{identity.team_type.__qualname__} '
                               '{identity.identifier} {fingerprint}')

    _sample_keys = None  # type: Optional[RSAKey]

    @typechecked
    def __init__(self, driver: NodeDriver, key_name_format: str=None) -> None:
        self.driver = driver
        self.key_name_format = key_name_format or self.DEFAULT_KEY_NAME_FORMAT

    def _get_key_name(self, identity: Identity, public_key: PKey) -> str:
        return self.key_name_format.format(
            identity=identity,
            public_key=public_key,
            fingerprint=get_key_fingerprint(public_key)
        )

    def _get_key_name_pattern(self,
                              identity: Identity) -> Pattern[str]:
        """Make the regex pattern from the format string.  Put two different
        random keys, compare two outputs, and then replace the difference
        with wildcard.

        """
        cls = type(self)
        sample_keys = cls._sample_keys
        if sample_keys is None:
            sample_keys = (RSAKey.generate(bits=512),
                           RSAKey.generate(bits=512),
                           ECDSAKey.generate(bits=256),
                           ECDSAKey.generate(bits=256))
            cls._sample_keys = sample_keys
        sample_names = [self._get_key_name(identity, k) for k in sample_keys]
        if len(frozenset(sample_names)) < 2:
            return re.compile('^' + re.escape(sample_names[0]) + '$')
        prefix = os.path.commonprefix(sample_names)
        postfix = os.path.commonprefix([n[::-1] for n in sample_names])[::-1]
        return re.compile(
            '^{}.+?{}$'.format(re.escape(prefix), re.escape(postfix))
        )

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
        name = self._get_key_name(identity, public_key)
        driver = self.driver
        try:
            driver.get_key_pair(name)
        except KeyPairDoesNotExistError:
            driver.import_key_pair_from_string(
                name,
                format_openssh_pubkey(public_key)
            )
        else:
            raise DuplicatePublicKeyError()

    @typechecked
    def list_keys(self, identity: Identity) -> AbstractSet[PKey]:
        pattern = self._get_key_name_pattern(identity)
        return frozenset(
            parse_openssh_pubkey(key_pair.public_key)
            for key_pair in self.driver.list_key_pairs()
            if pattern.match(key_pair.name)
        )

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
        try:
            key_pair = self.driver.get_key_pair(
                self._get_key_name(identity, public_key)
            )
        except KeyPairDoesNotExistError:
            return
        self.driver.delete_key_pair(key_pair)


class CloudMasterPublicKeyStore(MasterKeyStore):
    """It doesn't store the whole master key, but stores only public part of
    the master key into cloud provider's key pair registry.  So it requires
    the actual ``master_key_store`` to store the whole master key which is
    not only public part but also private part.

    It helps to create compute instances (e.g. Amazon EC2) that are already
    colonized.

    :param driver: libcloud compute driver
    :type driver: :class:`libcloud.compute.base.NodeDriver`
    :param key_pair_name: the name for cloud provider's key pair registry
    :type key_pair_name: :class:`str`
    :param master_key_store: "actual" master key store to store the whole
                             master key
    :type master_key_store: :class:`~geofront.masterkey.MasterKeyStore`

    .. versionadded:: 0.2.0

    """

    @typechecked
    def __init__(self,
                 driver: NodeDriver,
                 key_pair_name: str,
                 master_key_store: MasterKeyStore) -> None:
        self.driver = driver
        self.key_pair_name = key_pair_name
        self.master_key_store = master_key_store

    @typechecked
    def load(self) -> PKey:
        return self.master_key_store.load()

    @typechecked
    def save(self, master_key: PKey) -> None:
        public_key = format_openssh_pubkey(master_key)
        driver = self.driver
        try:
            key_pair = driver.get_key_pair(self.key_pair_name)
        except KeyPairDoesNotExistError:
            pass
        except MalformedResponseError as e:
            # FIXME: EC2 driver seems to raise MalformedResponseError
            # instead of KeyPairDoesNotExistError.
            if not issubclass(e.driver, EC2NodeDriver):
                raise
            tree = xml.etree.ElementTree.fromstring(e.body)
            if not (tree.tag == 'Response' and
                    getattr(tree.find('Errors/Error/Code'), 'text', None) ==
                    'InvalidKeyPair.NotFound'):
                raise
        else:
            driver.delete_key_pair(key_pair)
        driver.import_key_pair_from_string(self.key_pair_name, public_key)
        self.master_key_store.save(master_key)
