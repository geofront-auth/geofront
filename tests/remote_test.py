import ipaddress
import threading

from libcloud.compute.drivers.dummy import DummyNodeDriver
from paramiko.rsakey import RSAKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport
from pytest import fixture, raises, yield_fixture

from geofront.keystore import format_openssh_pubkey, parse_openssh_pubkey
from geofront.remote import Address, AuthorizedKeyList, CloudRemoteSet
from .sftpd import start_server


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


@yield_fixture
def fx_sftpd(request, tmpdir):
    getopt = request.config.getoption
    port_min = getopt('--sshd-port-min')
    port_max = getopt('--sshd-port-max')
    servers = {}
    for port in range(port_min, port_max + 1):
        path = tmpdir.mkdir(str(port))
        t = threading.Thread(
            target=start_server,
            args=(str(path), '127.0.0.1', port)
        )
        servers[port] = (t, path)
    yield servers
    for port, (t, _) in servers.items():
        assert not t.is_alive(), '{!r} (for port #{}) is still alive'.format(
            t, port
        )


@fixture
def fx_authorized_keys():
    return [RSAKey.generate(1024) for _ in range(5)]


@yield_fixture
def fx_authorized_sftp(fx_sftpd, fx_authorized_keys):
    port, (thread, path) = fx_sftpd.popitem()
    thread.start()
    key = RSAKey.generate(1024)
    dot_ssh = path.mkdir('.ssh')
    with dot_ssh.join('authorized_keys').open('w') as f:
        print(format_openssh_pubkey(key), file=f)
        for authorized_key in fx_authorized_keys:
            print(format_openssh_pubkey(authorized_key), file=f)
    transport = Transport(('127.0.0.1', port))
    transport.connect(pkey=key)
    sftp_client = SFTPClient.from_transport(transport)
    yield sftp_client, path, [key] + fx_authorized_keys
    sftp_client.close()
    transport.close()


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
