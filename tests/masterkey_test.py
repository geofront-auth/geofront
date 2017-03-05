import datetime
import os.path
import time
from typing import Type

from paramiko.ecdsakey import ECDSAKey
from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from pytest import mark, raises

from geofront.keystore import parse_openssh_pubkey
from geofront.masterkey import (EmptyStoreError, FileSystemMasterKeyStore,
                                KeyGenerationError, PeriodicalRenewal,
                                TwoPhaseRenewal,
                                generate_key, read_private_key_file,
                                renew_master_key)
from geofront.remote import Remote


def test_fs_master_key_store_load():
    path = os.path.join(os.path.dirname(__file__), 'test_id_rsa')
    s = FileSystemMasterKeyStore(path)
    key = s.load()
    assert isinstance(key, RSAKey)
    assert key.get_base64() == (
        'AAAAB3NzaC1yc2EAAAADAQABAAABAQC7+fDpQ9sQKIdzXvqT3TzrPp2OpUCOJtUW3k0oi'
        'trqqHe1XiCke++DSpAv56poCppTj9qo3N1HyhZhSv/jH7/ejZ8NZdtvLIZGOCQZVdKNy0'
        'cg7jlimrWA2s8X201Yn3hYpUrYJYbhAAuQM5flvbyBtn5/miONQ8NVimgjG6UVANVqX4W'
        'H9kqdr4SBf45/+BAdenf2j5DC3xceOOW8wZfe2rOJpQ0msVxMeXExGqF9DS2E3bqOwE1C'
        'MPEGYr5KZCx7IeJ/4udBuKc/gOXb8tPiTTNxtYXEBcqhBdCa/M6pEdW5LiHxxoF5b6xY9'
        'q0nmi7Rn0weXK0SufhGgKrpSH+B'
    )


def test_fs_master_key_store_save(tmpdir):
    path = tmpdir.join('id_rsa')
    s = FileSystemMasterKeyStore(str(path))
    with raises(EmptyStoreError):
        s.load()
    key = RSAKey.generate(1024)
    s.save(key)
    stored_key = s.load()
    assert isinstance(stored_key, RSAKey)
    assert stored_key.get_base64() == stored_key.get_base64()


def test_read_private_key_file():
    path = os.path.join(os.path.dirname(__file__), 'test_id_rsa')
    with open(path) as f:
        key = read_private_key_file(f)
    assert isinstance(key, RSAKey)
    assert key.get_base64() == (
        'AAAAB3NzaC1yc2EAAAADAQABAAABAQC7+fDpQ9sQKIdzXvqT3TzrPp2OpUCOJtUW3k0oi'
        'trqqHe1XiCke++DSpAv56poCppTj9qo3N1HyhZhSv/jH7/ejZ8NZdtvLIZGOCQZVdKNy0'
        'cg7jlimrWA2s8X201Yn3hYpUrYJYbhAAuQM5flvbyBtn5/miONQ8NVimgjG6UVANVqX4W'
        'H9kqdr4SBf45/+BAdenf2j5DC3xceOOW8wZfe2rOJpQ0msVxMeXExGqF9DS2E3bqOwE1C'
        'MPEGYr5KZCx7IeJ/4udBuKc/gOXb8tPiTTNxtYXEBcqhBdCa/M6pEdW5LiHxxoF5b6xY9'
        'q0nmi7Rn0weXK0SufhGgKrpSH+B'
    )


def authorized_key_set(path):
    dotssh = path.join('.ssh')
    if not dotssh.isdir():
        dotssh = path.mkdir('.ssh')
    with dotssh.join('authorized_keys').open() as f:
        return {parse_openssh_pubkey(line.strip()) for line in f}


def test_two_phase_renewal(fx_authorized_servers, fx_master_key):
    remote_set = {
        Remote('user', '127.0.0.1', port)
        for port in fx_authorized_servers
    }
    old_key = fx_master_key
    new_key = RSAKey.generate(1024)
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {old_key}
    with TwoPhaseRenewal(remote_set, old_key, new_key):
        for t, path, ev in fx_authorized_servers.values():
            assert authorized_key_set(path) == {old_key, new_key}
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {new_key}


def test_two_phase_renewal_stop(fx_authorized_servers, fx_master_key):
    remote_set = {
        Remote('user', '127.0.0.1', port)
        for port in fx_authorized_servers
    }
    old_key = fx_master_key
    new_key = RSAKey.generate(1024)
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {old_key}
    SomeException = type('SomeException', (Exception,), {})
    with raises(SomeException):
        with TwoPhaseRenewal(remote_set, old_key, new_key):
            for t, path, ev in fx_authorized_servers.values():
                assert authorized_key_set(path) == {old_key, new_key}
            raise SomeException('something went wrong')
    for t, path, ev in fx_authorized_servers.values():
        assert old_key in authorized_key_set(path)


@mark.parametrize('key_type, bits', [
    (RSAKey, None),
    (RSAKey, 1024),
    (RSAKey, 2048),
    (ECDSAKey, None),
    (ECDSAKey, 256),
    (ECDSAKey, 384),
])
def test_renew_master_key(fx_authorized_servers, fx_master_key, tmpdir,
                          key_type: Type[PKey], bits: int):
    remote_set = {
        Remote('user', '127.0.0.1', port)
        for port in fx_authorized_servers
    }
    store = FileSystemMasterKeyStore(str(tmpdir.join('id_rsa')))
    store.save(fx_master_key)
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {fx_master_key}
    new_key = renew_master_key(remote_set, store, key_type, bits)
    assert new_key.get_bits() == bits or bits is None
    assert isinstance(new_key, key_type)
    assert new_key != fx_master_key
    assert store.load() == new_key
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {new_key}


class FailureTestMasterKeyStore(FileSystemMasterKeyStore):

    def save(self, master_key: PKey):
        try:
            self.load()
        except EmptyStoreError:
            super().save(master_key)
        else:
            raise RenewalFailure()


class RenewalFailure(Exception):

    pass


def test_renew_master_key_fail(fx_authorized_servers, fx_master_key, tmpdir):
    remote_set = {
        Remote('user', '127.0.0.1', port)
        for port in fx_authorized_servers
    }
    store = FailureTestMasterKeyStore(str(tmpdir.join('id_rsa')))
    store.save(fx_master_key)
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {fx_master_key}
    with raises(RenewalFailure):
        renew_master_key(remote_set, store)
    assert store.load() == fx_master_key
    for t, path, ev in fx_authorized_servers.values():
        assert fx_master_key in authorized_key_set(path)


def wait_for(seconds: int, condition):
    for _ in range(seconds * 2):
        if condition():
            break
        time.sleep(0.5)
    else:
        raise TimeoutError(
            'failed to satisfy condition during {0} seconds'.format(seconds)
        )


def test_periodical_renewal(request, fx_authorized_servers, fx_master_key,
                            tmpdir):
    timeout = request.config.getoption('--sshd-state-timeout')
    remote_set = {
        Remote('user', '127.0.0.1', port)
        for port in fx_authorized_servers
    }
    store = FileSystemMasterKeyStore(str(tmpdir.join('id_rsa')))
    store.save(fx_master_key)
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {fx_master_key}
    p = PeriodicalRenewal(remote_set, store, datetime.timedelta(seconds=3))
    assert store.load() == fx_master_key
    for t, path, ev in fx_authorized_servers.values():
        assert fx_master_key in authorized_key_set(path)
    wait_for(timeout, lambda: store.load() != fx_master_key)
    second_key = store.load()
    assert second_key != fx_master_key
    for t, path, ev in fx_authorized_servers.values():
        key_set = authorized_key_set(path)
        assert second_key in key_set
    wait_for(timeout, lambda: store.load() != second_key)
    third_key = store.load()
    assert third_key != fx_master_key
    assert third_key != second_key
    for t, path, ev in fx_authorized_servers.values():
        key_set = authorized_key_set(path)
        assert third_key in key_set
    p.terminate()
    last_key = store.load()
    time.sleep(10)
    assert store.load() == last_key
    for t, path, ev in fx_authorized_servers.values():
        assert authorized_key_set(path) == {last_key}


def test_generate_key():
    default_default = generate_key()
    assert isinstance(default_default, RSAKey)
    assert default_default.get_bits() == 1024
    rsa_default = generate_key(RSAKey)
    assert rsa_default.get_bits() == 1024
    assert isinstance(rsa_default, RSAKey)
    rsa_2048 = generate_key(RSAKey, 2048)
    assert isinstance(rsa_2048, RSAKey)
    assert rsa_2048.get_bits() == 2048
    ecdsa_default = generate_key(ECDSAKey)
    assert isinstance(ecdsa_default, ECDSAKey)
    assert ecdsa_default.get_bits() == 256
    ecdsa_256 = generate_key(ECDSAKey, 256)
    assert isinstance(ecdsa_256, ECDSAKey)
    assert ecdsa_256.get_bits() == 256
    ecdsa_384 = generate_key(ECDSAKey, 384)
    assert isinstance(ecdsa_384, ECDSAKey)
    assert ecdsa_384.get_bits() == 384
    ecdsa_521 = generate_key(ECDSAKey, 521)
    assert isinstance(ecdsa_521, ECDSAKey)
    assert ecdsa_521.get_bits() == 521
    with raises(KeyGenerationError):
        generate_key(RSAKey, 256)
    with raises(KeyGenerationError):
        generate_key(ECDSAKey, 1024)
