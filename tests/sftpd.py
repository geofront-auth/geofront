import os.path
import socket
import time

from paramiko.common import AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.rsakey import RSAKey
from paramiko.server import ServerInterface
from paramiko.sftp_server import SFTPServer
from paramiko.transport import Transport
from sftpserver.stub_sftp import StubSFTPServer

from geofront.keystore import parse_openssh_pubkey


class StubServer(ServerInterface):

    def __init__(self, path):
        self.path = path

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
        for authorized_key in self.authorized_keys:
            if authorized_key == key:
                return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


def start_server(path: str, host: str, port: int):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server_socket.bind((host, port))
    server_socket.listen(1)
    stub_cls = type('StubSFTPServer', (StubSFTPServer,), {'ROOT': path})
    host_key = RSAKey.generate(1024)
    conn, addr = server_socket.accept()
    transport = Transport(conn)
    transport.add_server_key(host_key)
    transport.set_subsystem_handler('sftp', SFTPServer, stub_cls)
    server = StubServer(path)
    transport.start_server(server=server)
    channel = transport.accept()
    while channel is not None and transport.is_active():
        time.sleep(1)
