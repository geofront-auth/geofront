import ipaddress

from libcloud.compute.drivers.dummy import DummyNodeDriver

from geofront.remote import Address, CloudRemoteSet


def test_address():
    assert isinstance(ipaddress.ip_address('192.168.0.1'), Address)
    assert isinstance(ipaddress.ip_address('2001:db8::'), Address)


def test_cloud_remote_set():
    driver = DummyNodeDriver('')
    set_ = CloudRemoteSet(driver)
    assert dict(set_) == {
        'dummy-1': ipaddress.ip_address('127.0.0.1'),
        'dummy-2': ipaddress.ip_address('127.0.0.1')
    }