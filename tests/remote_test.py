import datetime
import time

from paramiko.rsakey import RSAKey
from pytest import mark, raises

from geofront.keystore import format_openssh_pubkey, parse_openssh_pubkey
from geofront.remote import AuthorizedKeyList,  Remote, authorize


@mark.parametrize(('b', 'equal'), [
    (Remote('a', '192.168.0.1', 22), True),
    (Remote('a', '192.168.0.1', 2222), False),
    (Remote('b', '192.168.0.1', 22), False),
    (Remote('b', '192.168.0.1', 2222), False),
    (Remote('a', '192.168.0.2', 22), False),
    (Remote('b', '192.168.0.2', 22), False),
    (Remote('a', '192.168.0.2', 2222), False),
    (Remote('b', '192.168.0.2', 2222), False),
    (Remote('a', '192.168.0.1', 22, {'a': 1}), True),
    (Remote('a', '192.168.0.1', 2222, {'a': 1}), False),
    (Remote('b', '192.168.0.1', 22, {'a': 1}), False),
    (Remote('b', '192.168.0.1', 2222, {'a': 1}), False),
    (Remote('a', '192.168.0.2', 22, {'a': 1}), False),
    (Remote('b', '192.168.0.2', 22, {'a': 1}), False),
    (Remote('a', '192.168.0.2', 2222, {'a': 1}), False),
    (Remote('b', '192.168.0.2', 2222, {'a': 1}), False)
])
def test_remote(b, equal):
    a = Remote('a', '192.168.0.1')
    assert (a == b) is equal
    assert (a != b) is (not equal)
    assert (hash(a) == hash(b)) is equal


def test_authorized_keys_list_iter(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    it = iter(key_list)
    assert next(it) == keys[0]
    assert next(it) == keys[1]
    assert next(it) == keys[2]
    assert next(it) == keys[3]
    assert next(it) == keys[4]
    assert next(it) == keys[5]
    with raises(StopIteration):
        next(it)
    # It's lazily evaluated; changes should reflect
    with path.join('.ssh', 'authorized_keys').open('w') as f:
        f.write(format_openssh_pubkey(keys[0]))
    it = iter(key_list)
    assert next(it) == keys[0]
    with raises(StopIteration):
        next(it)


def test_authorized_keys_list_len(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    assert len(key_list) == 6
    # It's lazily evaluated; changes should reflect
    with path.join('.ssh', 'authorized_keys').open('w') as f:
        f.write(format_openssh_pubkey(keys[0]))
    assert len(key_list) == 1


def test_authorized_keys_list_getitem(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    for i in range(-6, 6):
        assert key_list[i] == keys[i]
        assert key_list[i:] == keys[i:]
        assert key_list[:i] == keys[:i]
        assert key_list[i:i + 3] == keys[i:i + 3]
    with raises(IndexError):
        assert key_list[-7]
    with raises(IndexError):
        assert key_list[6]
    with raises(TypeError):
        key_list['key']
    # It's lazily evaluated; changes should reflect
    with path.join('.ssh', 'authorized_keys').open('w') as f:
        f.write(format_openssh_pubkey(keys[0]))
    assert key_list[0] == key_list[-1] == keys[0]
    with raises(IndexError):
        key_list[1]
    with raises(IndexError):
        key_list[-2]


def test_authorized_keys_list_setitem(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    # Slice assignment
    key_list[3:] = []
    with path.join('.ssh', 'authorized_keys').open() as f:
        for i in range(3):
            assert parse_openssh_pubkey(f.readline().strip()) == keys[i]
        assert not f.readline().strip()
    # Positive index
    key_list[2] = keys[3]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(f.readline().strip()) == keys[0]
        assert parse_openssh_pubkey(f.readline().strip()) == keys[1]
        assert parse_openssh_pubkey(f.readline().strip()) == keys[3]
        assert not f.readline().strip()
    # Negative index
    key_list[-1] = keys[4]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(f.readline().strip()) == keys[0]
        assert parse_openssh_pubkey(f.readline().strip()) == keys[1]
        assert parse_openssh_pubkey(f.readline().strip()) == keys[4]
        assert not f.readline().strip()


def test_authorized_keys_list_insert(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    new_key = RSAKey.generate(1024)
    key_list.insert(2, new_key)
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(f.readline().strip()) == keys[0]
        assert parse_openssh_pubkey(f.readline().strip()) == keys[1]
        assert parse_openssh_pubkey(f.readline().strip()) == new_key
        for i in range(2, 6):
            assert parse_openssh_pubkey(f.readline().strip()) == keys[i]
        assert not f.readline().strip()


def test_authorized_keys_list_extend(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    new_keys = [RSAKey.generate(1024) for _ in range(3)]
    key_list.extend(new_keys)
    with path.join('.ssh', 'authorized_keys').open() as f:
        for i in range(6):
            assert parse_openssh_pubkey(f.readline().strip()) == keys[i]
        for i in range(3):
            assert parse_openssh_pubkey(f.readline().strip()) == new_keys[i]
        assert not f.readline().strip()


def test_authorized_keys_list_delitem(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    # Slice deletion
    del key_list[3:]
    with path.join('.ssh', 'authorized_keys').open() as f:
        for i in range(3):
            assert parse_openssh_pubkey(f.readline().strip()) == keys[i]
        assert not f.readline().strip()
    # Positive index
    del key_list[2]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(f.readline().strip()) == keys[0]
        assert parse_openssh_pubkey(f.readline().strip()) == keys[1]
        assert not f.readline().strip()
    # Negative index
    del key_list[-1]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(f.readline().strip()) == keys[0]
        assert not f.readline().strip()


def test_authorize(fx_sftpd):
    port, (thread, path, ev) = fx_sftpd.popitem()
    thread.start()
    master_key = RSAKey.generate(1024)
    public_keys = {RSAKey.generate(1024), RSAKey.generate(1024)}
    authorized_keys_path = path.mkdir('.ssh').join('authorized_keys')
    with authorized_keys_path.open('w') as f:
        print(format_openssh_pubkey(master_key), file=f)
    expires_at = authorize(
        public_keys,
        master_key,
        Remote('user', '127.0.0.1', port),
        timeout=datetime.timedelta(seconds=5)
    )
    with authorized_keys_path.open() as f:
        saved_keys = map(parse_openssh_pubkey, f)
        assert frozenset(saved_keys) == (public_keys | {master_key})
    while datetime.datetime.now(datetime.timezone.utc) <= expires_at:
        time.sleep(1)
    time.sleep(1)
    with authorized_keys_path.open() as f:
        saved_keys = map(parse_openssh_pubkey, f)
        assert frozenset(saved_keys) == {master_key}
