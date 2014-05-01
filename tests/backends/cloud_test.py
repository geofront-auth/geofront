import hashlib
import io
import os

from libcloud.compute.base import Node, KeyPair
from libcloud.compute.drivers.dummy import DummyNodeDriver
from libcloud.compute.types import KeyPairDoesNotExistError
from libcloud.storage.drivers import dummy
from libcloud.storage.drivers.dummy import DummyStorageDriver
from paramiko.rsakey import RSAKey
from pytest import raises

from geofront.backends.cloud import (CloudKeyStore, CloudMasterKeyStore,
                                     CloudRemoteSet,
                                     get_metadata, supports_metadata)
from geofront.identity import Identity
from geofront.keystore import (format_openssh_pubkey, get_key_fingerprint,
                               parse_openssh_pubkey)
from geofront.masterkey import EmptyStoreError
from geofront.remote import Remote
from ..keystore_test import assert_keystore_compliance
from ..server_test import DummyTeam


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


class KeyPairSupportedDummyNodeDriver(DummyNodeDriver):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_pairs = {}

    def get_key_pair(self, name):
        try:
            key_material = self.key_pairs[name]
        except KeyError:
            raise KeyPairDoesNotExistError(name, self)
        return KeyPair(name,
                       key_material,
                       get_key_fingerprint(parse_openssh_pubkey(key_material)),
                       self)

    def list_key_pairs(self):
        return [self.get_key_pair(name) for name in self.key_pairs]

    def import_key_pair_from_string(self, name, key_material):
        self.key_pairs[name] = key_material

    def delete_key_pair(self, key_pair):
        del self.key_pairs[key_pair.name]

    def import_key_pair_from_file(self, name, key_file_path):
        with open(key_file_path) as f:
            self.import_key_pair_from_string(name, f.read())

    def create_key_pair(self, name):
        self.import_key_pair_from_string(
            name,
            format_openssh_pubkey(RSAKey.generate(1024))
        )


def test_cloud_key_store():
    driver = KeyPairSupportedDummyNodeDriver('')
    keystore = CloudKeyStore(driver)
    identity = Identity(DummyTeam, 'abcd')
    assert_keystore_compliance(keystore, identity)
    identity2 = Identity(DummyTeam, 'efg')
    assert_keystore_compliance(keystore, identity2)


def test_cloud_key_store_get_key_name_pattern():
    driver = KeyPairSupportedDummyNodeDriver('')
    keystore = CloudKeyStore(driver)
    identity = Identity(DummyTeam, 'abcd')
    pattern = keystore._get_key_name_pattern(identity)
    random_fp = lambda: ':'.join(
        map('{:02x}'.format, hashlib.md5(os.urandom(100)).digest())
    )
    actual = {
        'tests.server_test.DummyTeam abcd ' + random_fp()
        for _ in range(5)
    }
    result = filter(pattern.match, actual | {
        'tests.server_test.DummyTeam defg ' + random_fp(),
        'tests.server_test.OtherTeam abcd ' + random_fp(),
        'tests.server_test.DummyTeam abcd ',
        'junk'
    })
    assert frozenset(result) == actual
