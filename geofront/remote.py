""":mod:`geofront.remote` --- Remote sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every remote set is represented as a mapping (which is immutable, or mutable)
of alias :class:`str` to :class:`Remote` object e.g.::

    {
        'web-1': Remote('ubuntu', ipaddress.ip_address('192.168.0.5')),
        'web-2': Remote('ubuntu', ipaddress.ip_address('192.168.0.6')),
        'web-3': Remote('ubuntu', ipaddress.ip_address('192.168.0.7')),
        'worker-1': Remote('ubuntu', ipaddress.ip_address('192.168.0.25')),
        'worker-2': Remote('ubuntu', ipaddress.ip_address('192.168.0.26')),
        'db-1': Remote('ubuntu', ipaddress.ip_address('192.168.0.50')),
        'db-2': Remote('ubuntu', ipaddress.ip_address('192.168.0.51'))
    }

However, in the age of the cloud, you don't have to manage the remote set
since the most of cloud providers offer their API to list provisioned
remote nodes.

This module provides :class:`CloudRemoteSet`, a subtype of
:class:`collections.abc.Mapping`, that proxies to the list dynamically made by
cloud providers.

"""
import collections.abc
import datetime
import io
import ipaddress
import itertools
import numbers
import threading
import time

from libcloud.compute.base import NodeDriver
from paramiko.pkey import PKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport

from .keystore import format_openssh_pubkey, parse_openssh_pubkey
from .util import typed

__all__ = ('Address', 'AuthorizedKeyList', 'CloudRemoteSet', 'Remote',
           'authorize')


#: (:class:`type`) Alias of :class:`ipaddress._BaseAddress`.
#:
#: What is this alias for?  :class:`ipaddress._BaseAddress` is an undocumented
#: API, so we can't guarantee it will not be gone.  When it's gone we can
#: make this alias an actual ABC for two concrete classes:
#:
#: - :class:`ipaddress.IPv4Address`
#: - :class:`ipaddress.IPv6Address`
Address = ipaddress._BaseAddress


class Remote:
    """Remote node to SSH.

    :param user: the username to :program:`ssh`
    :type user: :class:`str`
    :param address: the adress, already resolved, to access
    :type address: :class:`Address`
    :param port: the port number to :program:`ssh`.
                 the default is 22 which is the default :program:`ssh` port
    :type port: :class:`numbers.Integral`

    """

    #: (:class:`str`) The username to SSH.
    user = None

    #: (:class:`Address`) The address, already resolved, to access.
    address = None

    #: (:class:`numbers.Integral`) The port number to SSH.
    port = None

    @typed
    def __init__(self, user: str, address: Address, port: numbers.Integral=22):
        self.user = user
        self.address = address
        self.port = port

    def __eq__(self, other):
        return (isinstance(other, type(self)) and
                self.user == other.user and
                self.address == other.address and
                self.port == other.port)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.user, self.address, self.port))

    def __str__(self):  # pragma: no cover
        return '{}@{}:{}'.format(self.user, self.address, self.port)

    def __repr__(self):
        return '{0.__module__}.{0.__qualname__}({1!r}, {2!r}, {3!r})'.format(
            type(self), self.user, self.address, self.port
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


class CloudRemoteSet(collections.abc.Mapping):
    """Libcloud_-backed remote set.  It supports more than 20 cloud providers
    through the efforts of Libcloud_. ::

        from geofront.remote import CloudRemoteSet
        from libcloud.compute.types import Provider
        from libcloud.compute.providers import get_driver

        driver_cls = get_driver(Provider.EC2_US_WEST)
        driver = driver_cls('access id', 'secret key')
        REMOTE_SET = CloudRemoteSet(driver)

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

    def _get_nodes(self, refresh: bool=False) -> dict:
        if refresh or self._nodes is None:
            self._nodes = {node.name: node
                           for node in self.driver.list_nodes()
                           if node.public_ips}
        return self._nodes

    def __len__(self) -> int:
        return len(self._get_nodes())

    def __iter__(self) -> collections.abc.Iterator:
        return iter(self._get_nodes(True))

    def __getitem__(self, alias: str) -> Remote:
        node = self._get_nodes()[alias]
        address = ipaddress.ip_address(node.public_ips[0])
        return Remote(self.user, address, self.port)


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
    transport = Transport((str(remote.address), remote.port))
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
