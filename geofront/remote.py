""":mod:`geofront.remote` --- Remote sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import ipaddress

__all__ = {'Address'}


#: (:class:`type`) Alias of :class:`ipaddress._BaseAddress`.
#:
#: What is this alias for?  :class:`ipaddress._BaseAddress` is an undocumented
#: API, so we can't guarantee it will not be gone.  When it's gone we can
#: make this alias an actual ABC for two concrete classes:
#:
#: - :class:`ipaddress.IPv4Address`
#: - :class:`ipaddress.IPv6Address`
Address = ipaddress._BaseAddress