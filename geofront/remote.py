""":mod:`geofront.remote` --- Remote sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every remote set is represented as a mapping (which is immutable, or mutable)
of alias :class:`str` to :class:`Address` object e.g.::

    {
        'web-1': ipaddress.ip_address('192.168.0.5'),
        'web-2': ipaddress.ip_address('192.168.0.6'),
        'web-3': ipaddress.ip_address('192.168.0.7'),
        'worker-1': ipaddress.ip_address('192.168.0.25'),
        'worker-2': ipaddress.ip_address('192.168.0.26'),
        'db-1': ipaddress.ip_address('192.168.0.50'),
        'db-2': ipaddress.ip_address('192.168.0.51')
    }

However, in the age of the cloud, you don't have to manage the remote set
since the most of cloud providers offer their API to list provisioned
remote nodes.

This module provides :class:`CloudRemoteSet`, a subtype of
:class:`collections.abc.Set`, that proxies to the list dynamically made by
cloud providers.

"""
import collections.abc
import ipaddress

from libcloud.compute.base import NodeDriver

from .util import typed

__all__ = {'Address', 'CloudRemoteSet'}


#: (:class:`type`) Alias of :class:`ipaddress._BaseAddress`.
#:
#: What is this alias for?  :class:`ipaddress._BaseAddress` is an undocumented
#: API, so we can't guarantee it will not be gone.  When it's gone we can
#: make this alias an actual ABC for two concrete classes:
#:
#: - :class:`ipaddress.IPv4Address`
#: - :class:`ipaddress.IPv6Address`
Address = ipaddress._BaseAddress


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

    .. seealso::

       `Compute`__ --- Libcloud
          The compute component of libcloud allows you to manage
          cloud and virtual servers offered by different providers,
          more than 20 in total.

    .. _Libcloud: http://libcloud.apache.org/
    __ https://libcloud.readthedocs.org/en/latest/compute/

    """

    @typed
    def __init__(self, driver: NodeDriver):
        self.driver = driver
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

    def __getitem__(self, alias: str) -> Address:
        node = self._get_nodes()[alias]
        return ipaddress.ip_address(node.public_ips[0])
