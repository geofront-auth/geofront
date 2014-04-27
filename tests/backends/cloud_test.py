import io

from libcloud.compute.base import Node
from libcloud.compute.drivers.dummy import DummyNodeDriver
from libcloud.storage.drivers import dummy
from libcloud.storage.drivers.dummy import DummyStorageDriver
from paramiko.rsakey import RSAKey
from pytest import raises

from geofront.backends.cloud import (CloudMasterKeyStore, CloudRemoteSet,
                                     get_metadata, supports_metadata)
from geofront.masterkey import EmptyStoreError
from geofront.remote import Remote


@supports_metadata.register(DummyNodeDriver)
def dummy_supports_metadata(driver: DummyNodeDriver):
    return True


@get_metadata.register(DummyNodeDriver)
def dummy_get_metadata(driver: DummyNodeDriver, node: Node):
    return {'dummy': 'test'}


def test_cloud_remote_set():
    driver = DummyNodeDriver('')
    set_ = CloudRemoteSet(driver)
    assert len(set_) == 2
    assert set_['dummy-1'] == Remote('ec2-user', '127.0.0.1')
    assert set_['dummy-1'].metadata == {'dummy': 'test'}
    assert set_['dummy-2'] == Remote('ec2-user', '127.0.0.1')
    assert set_['dummy-2'].metadata == {'dummy': 'test'}


def test_cloud_master_key_store():
    driver = DummyStorageDriver('', '')
    container = driver.create_container('geofront-test')
    s = CloudMasterKeyStore(driver, container, 'test_id_rsa')
    with raises(EmptyStoreError):
        s.load()
    key = RSAKey.generate(1024)
    s.save(key)
    driver.get_object(container.name, 'test_id_rsa')  # assert object exists
    # Mocking implementation
    with io.StringIO() as mock:
        key.write_private_key(mock)
        mock.seek(0)
        dummy.DummyFileObject = lambda *a, **k: mock
        stored_key = s.load()
        assert isinstance(stored_key, RSAKey)
        assert stored_key.get_base64() == stored_key.get_base64()
