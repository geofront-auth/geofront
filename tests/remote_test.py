import ipaddress

from geofront.remote import Address


def test_address():
    assert isinstance(ipaddress.ip_address('192.168.0.1'), Address)
    assert isinstance(ipaddress.ip_address('2001:db8::'), Address)
