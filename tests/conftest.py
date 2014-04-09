import threading

from paramiko.rsakey import RSAKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport
from pytest import fixture, yield_fixture

from geofront.keystore import format_openssh_pubkey
from .sftpd import start_server


def pytest_addoption(parser):
    parser.addoption('--sshd-port-min',
                     metavar='PORT',
                     type=int,
                     default=12220,
                     help='the minimum unused port number [%default(s)]')
    parser.addoption('--sshd-port-max',
                     metavar='PORT',
                     type=int,
                     default=12224,
                     help='the maximum unused port number [%default(s)]')
    parser.addoption('--redis-host', metavar='HOST', help='redis host')
    parser.addoption('--redis-port',
                     metavar='PORT',
                     type=int,
                     default=6379,
                     help='redis port [%default(s)]')
    parser.addoption('--redis-password',
                     metavar='PASSWORD',
                     help='redis password')
    parser.addoption('--redis-db',
                     metavar='DB',
                     type=int,
                     default=1,
                     help='redis db number [%(default)s]')
    parser.addoption('--github-access-token',
                     metavar='TOKEN',
                     help='github access token for key store test (caution: '
                          'it will remove all ssh keys of the account)')


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
