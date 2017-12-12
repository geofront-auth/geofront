import hashlib
import io
import os

from libcloud.compute.base import KeyPair, Node
from libcloud.compute.drivers.dummy import DummyNodeDriver
from libcloud.compute.types import KeyPairDoesNotExistError
from libcloud.storage.drivers import dummy
from libcloud.storage.drivers.dummy import DummyStorageDriver
from libcloud.storage.providers import get_driver
from libcloud.storage.types import ObjectDoesNotExistError, Provider
from paramiko.rsakey import RSAKey
from pytest import raises, skip

from ..keystore_test import assert_keystore_compliance
from ..server_test import DummyTeam, MemoryMasterKeyStore
from geofront.backends.cloud import (CloudKeyStore, CloudMasterKeyStore,
                                     CloudMasterPublicKeyStore, CloudRemoteSet,
                                     get_metadata, supports_metadata)
from geofront.identity import Identity
from geofront.keystore import (format_openssh_pubkey, get_key_fingerprint,
                               parse_openssh_pubkey)
from geofront.masterkey import EmptyStoreError, read_private_key_file
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
    id_set = CloudRemoteSet(driver, alias_namer=lambda n: 'id-' + n.id)
    assert frozenset(id_set) == {'id-1', 'id-2'}
    assert id_set['id-1'] == set_['dummy-1']
    assert id_set['id-2'] == set_['dummy-2']


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


def test_cloud_master_key_store_s3(request, tmpdir):
    try:
        access_key = request.config.getoption('--aws-access-key')
        secret_key = request.config.getoption('--aws-secret-key')
        bucket_name = request.config.getoption('--aws-s3-bucket')
    except ValueError:
        access_key = secret_key = bucket_name = None
    if access_key is None or secret_key is None or bucket_name is None:
        skip(
            '--aws-access-key/--aws-secret-key/--aws-s3-bucket are not '
            'provided; skipped'
        )
    driver_cls = get_driver(Provider.S3)
    driver = driver_cls(access_key, secret_key)
    container = driver.get_container(container_name=bucket_name)
    tmpname = ''.join(map('{:02x}'.format, os.urandom(16)))
    s = CloudMasterKeyStore(driver, container, tmpname)
    key = RSAKey.generate(1024)
    # load() -- when not exists
    with raises(EmptyStoreError):
        s.load()
    try:
        # save()
        s.save(key)
        obj = driver.get_object(container.name, tmpname)
        dest = tmpdir / tmpname
        obj.download(str(dest))
        saved = read_private_key_file(dest.open())
        assert isinstance(saved, RSAKey)
        assert saved.get_base64() == key.get_base64()
        # load() -- when exists
        loaded = s.load()
        assert isinstance(loaded, RSAKey)
        assert loaded.get_base64() == key.get_base64()
    finally:
        try:
            o = driver.get_object(container.name, tmpname)
        except ObjectDoesNotExistError:
            pass
        else:
            o.delete()


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
    for i in range(100):
        CloudKeyStore._sample_keys = None
        # repeat for better reproducibility

        driver = KeyPairSupportedDummyNodeDriver('')
        keystore = CloudKeyStore(driver)
        identity = Identity(DummyTeam, 'abcd')
        pattern = keystore._get_key_name_pattern(identity)
        print('Cached CloudKeyStore._sample_keys:', CloudKeyStore._sample_keys)
        print('Cached CloudKeyStore._sample_keys (as names):',
              tuple(keystore._get_key_name(identity, k)
                    for k in CloudKeyStore._sample_keys))
        print('Generated pattern:', pattern.pattern)

        def random_fp():
            return ':'.join(
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
        result = frozenset(result)
        assert result == actual


def test_cloud_master_public_key_store():
    driver = KeyPairSupportedDummyNodeDriver('')
    actual_store = MemoryMasterKeyStore()
    store = CloudMasterPublicKeyStore(driver,
                                      'geofront-masterkey',
                                      actual_store)
    for _ in range(2):
        master_key = RSAKey.generate(1024)
        store.save(master_key)
        assert actual_store.load() == store.load() == master_key
        assert parse_openssh_pubkey(
            driver.get_key_pair('geofront-masterkey').public_key
        ) == master_key
