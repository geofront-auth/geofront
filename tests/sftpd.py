import os.path
try:
    import selectors
except ImportError:
    from asyncio import selectors  # type: ignore
import socket
import threading
import time

from paramiko.common import AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.rsakey import RSAKey
from paramiko.server import ServerInterface
from paramiko.sftp_server import SFTPServer
from paramiko.transport import Transport
from sftpserver.stub_sftp import StubSFTPServer

from geofront.keystore import parse_openssh_pubkey


class StubServer(ServerInterface):

    def __init__(self, path, users={'user'}):
        self.path = path
        self.users = frozenset(users)

    @property
    def authorized_keys(self):
        list_file = os.path.join(self.path, '.ssh', 'authorized_keys')
        with open(list_file) as f:
            for line in f.readlines():
                yield parse_openssh_pubkey(line.strip())

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_auth_password(self, username, password):
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username in self.users:
            for authorized_key in self.authorized_keys:
                if authorized_key == key:
                    return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


def start_server(path: str, host: str, port: int, terminated: threading.Event):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server_socket.bind((host, port))
    server_socket.listen(1)
    stub_cls = type('StubSFTPServer', (StubSFTPServer,), {'ROOT': path})
    host_key = RSAKey.generate(1024)

    def accept(server_socket, mask):
        conn, addr = server_socket.accept()
        transport = Transport(conn)
        transport.add_server_key(host_key)
        transport.set_subsystem_handler('sftp', SFTPServer, stub_cls)
        server = StubServer(path)
        transport.start_server(server=server)
        while not terminated.is_set():
            channel = transport.accept(1)
            if channel is not None and not terminated.is_set():
                while transport.is_active() and not terminated.is_set():
                    terminated.wait(1)
                break

    sel = selectors.DefaultSelector()
    sel.register(server_socket, selectors.EVENT_READ, accept)
    last_used = time.time()
    while not terminated.is_set() and last_used + 10 > time.time():
        events = sel.select(1)
        for key, mask in events:
            key.data(key.fileobj, mask)
            last_used = time.time()
