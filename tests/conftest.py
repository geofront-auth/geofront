import datetime
import http.client
import io
import os
import re
import threading
import urllib.request

from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport
from pytest import fixture, yield_fixture
from werkzeug.test import EnvironBuilder

from geofront.keystore import format_openssh_pubkey
from geofront import server
from .sftpd import start_server


# By default it's a minute, but a minute is enough to make the test suite
# very slow.  For faster unit testing we shorten this constant.
server.AUTHORIZATION_TIMEOUT = datetime.timedelta(seconds=5)


def env_default(env):
    return {'default': os.environ[env]} if env in os.environ else {}


def pytest_addoption(parser):
    parser.addoption('--sshd-port-min',
                     metavar='PORT',
                     type=int,
                     default=12220,
                     help='the minimum unused port number [%default(s)]')
    parser.addoption('--sshd-port-max',
                     metavar='PORT',
                     type=int,
                     default=12399,
                     help='the maximum unused port number [%default(s)]')
    parser.addoption('--redis-host',
                     metavar='HOSTNAME',
                     help='redis host',
                     **env_default('REDIS_HOST'))
    parser.addoption('--redis-port',
                     metavar='PORT',
                     type=int,
                     default=6379,
                     help='redis port [%default(s)]')
    parser.addoption('--redis-password',
                     metavar='PASSWORD',
                     default=None,
                     help='redis password')
    parser.addoption('--redis-db',
                     metavar='DB',
                     type=int,
                     default=1,
                     help='redis db number [%(default)s]')
    parser.addoption('--postgresql-host',
                     metavar='HOSTNAME',
                     help='postgresql database server host [%(default)s]',
                     **env_default('PGHOST'))
    parser.addoption('--postgresql-port',
                     metavar='PORT',
                     type=int,
                     help='postgresql database server port [%(default)s]',
                     **env_default('PGPORT'))
    parser.addoption('--postgresql-user',
                     metavar='USER',
                     help='postgresql user [%(default)s]',
                     **env_default('PGUSER'))
    parser.addoption('--postgresql-password',
                     metavar='PASSWORD',
                     help='postgresql user password [%(default)s]',
                     **env_default('PGPASSWORD'))
    parser.addoption('--postgresql-database',
                     metavar='DBNAME',
                     help='postgresql database name [%(default)s]',
                     **env_default('PGDATABASE'))
    parser.addoption('--mysql-host',
                     metavar='HOSTNAME',
                     help='mysql database server host [%(default)s]',
                     **env_default('MYSQL_HOST'))
    parser.addoption('--mysql-port',
                     metavar='PORT',
                     type=int,
                     help='mysql database server port [%(default)s]',
                     **env_default('MYSQL_PORT'))
    parser.addoption('--mysql-user',
                     metavar='USER',
                     help='mysql user [%(default)s]',
                     **env_default('MYSQL_USER'))
    parser.addoption('--mysql-passwd',
                     metavar='PASSWD',
                     help='mysql user password [%(default)s]',
                     **env_default('MYSQL_PASSWD'))
    parser.addoption('--mysql-database',
                     metavar='DATABASE',
                     help='mysql database name [%(default)s]',
                     **env_default('MYSQL_DATABASE'))
    parser.addoption('--github-access-token',
                     metavar='TOKEN',
                     help='github access token for key store test (caution: '
                          'it will remove all ssh keys of the account)',
                     **env_default('GITHUB_ACCESS_TOKEN'))
    parser.addoption('--github-org-login',
                     metavar='LOGIN',
                     help='github org login for team test',
                     **env_default('GITHUB_ORG_LOGIN'))
    parser.addoption('--github-team-slugs',
                     metavar='SLUGS',
                     help='space-separated github team slugs for group '
                          'listing test',
                     **env_default('GITHUB_TEAM_SLUGS'))


def pytest_assertrepr_compare(op, left, right):
    if op == '==' and isinstance(left, PKey) and isinstance(right, PKey):
        left_key = format_openssh_pubkey(left)
        right_key = format_openssh_pubkey(right)
        return [
            '{!r} == {!r}'.format(left, right),
            '   {} != {}'.format(left_key, right_key)
        ]


used_port = 0


@yield_fixture
def fx_sftpd(request, tmpdir):
    global used_port
    getopt = request.config.getoption
    port_min = max(used_port + 1, getopt('--sshd-port-min'))
    port_max = min(port_min + 2, getopt('--sshd-port-max'))
    used_port = port_max
    servers = {}
    for port in range(port_min, port_max + 1):
        path = tmpdir.mkdir(str(port))
        terminated = threading.Event()
        thread = threading.Thread(
            target=start_server,
            args=(str(path), '127.0.0.1', port, terminated)
        )
        servers[port] = thread, path, terminated
    yield servers
    for port, (th, _, ev) in servers.items():
        ev.set()
    for port, (th, _, ev) in servers.items():
        if th.is_alive():
            th.join(10)
        assert not th.is_alive(), '{!r} (for port #{}) is still alive'.format(
            th, port
        )


@fixture
def fx_authorized_keys():
    return [RSAKey.generate(1024) for _ in range(5)]


@yield_fixture
def fx_authorized_sftp(fx_sftpd, fx_authorized_keys):
    port, (thread, path, ev) = fx_sftpd.popitem()
    thread.start()
    key = RSAKey.generate(1024)
    dot_ssh = path.mkdir('.ssh')
    with dot_ssh.join('authorized_keys').open('w') as f:
        print(format_openssh_pubkey(key), file=f)
        for authorized_key in fx_authorized_keys:
            print(format_openssh_pubkey(authorized_key), file=f)
    transport = Transport(('127.0.0.1', port))
    transport.connect(username='user', pkey=key)
    sftp_client = SFTPClient.from_transport(transport)
    yield sftp_client, path, [key] + fx_authorized_keys
    sftp_client.close()
    transport.close()


@fixture
def fx_master_key():
    return RSAKey.generate(1024)


@fixture
def fx_authorized_servers(fx_sftpd, fx_master_key):
    for port, (thread, path, ev) in fx_sftpd.items():
        with path.mkdir('.ssh').join('authorized_keys').open('w') as f:
            f.write(format_openssh_pubkey(fx_master_key))
        thread.start()
    return fx_sftpd


class TestHTTPHandler(urllib.request.HTTPHandler):

    mock_hosts = {}
    mock_urls = {}

    def http_open(self, req):
        cls = type(self)
        url = req.full_url
        url_without_qs = re.sub(r'\?.*$', '', url)
        try:
            handler = cls.mock_urls[url_without_qs]
        except KeyError:
            try:
                wsgi_app = cls.mock_hosts[req.host]
            except KeyError:
                return super().http_open(req)
            builder = EnvironBuilder(
                path=req.selector,
                base_url=re.match(r'^https?://[^/]+', url).group(0),
                method=req.get_method(),
                headers=req.headers,
                data=req.data,
                content_type=req.headers.get(
                    'content-type',
                    'application/x-www-form-urlencoded' if req.data else None
                )
            )
            status_code = None
            headers = None

            def start_response(code, hlist):
                nonlocal status_code, headers
                status_code = code
                headers = hlist
            buffer_ = io.BytesIO()
            for chunk in wsgi_app(builder.get_environ(), start_response):
                buffer_.write(chunk)
            buffer_.seek(0)
            resp = urllib.request.addinfourl(
                buffer_,
                {k.lower().strip(): v for k, v in headers},
                url
            )
            code, resp.msg = status_code.split(None, 1)
            resp.code = resp.status = int(code)
            resp.reason = resp.msg
            resp.version = 10
            return resp
        content, status_code, headers = handler(req)
        if isinstance(content, str):
            buffer_ = io.StringIO(content)
        elif isinstance(content, bytes):
            buffer_ = io.BytesIO(content)
        elif isinstance(content, io.IOBase):
            buffer_ = content
        else:
            raise TypeError('content must be a string, or a bytes, or a file '
                            'object, not ' + repr(content))
        resp = urllib.request.addinfourl(
            buffer_,
            {k.lower().strip(): v for k, v in headers.items()},
            url
        )
        resp.code = status_code
        resp.msg = http.client.responses[status_code]
        return resp

    @classmethod
    def route(cls, url: str):
        def decorate(function):
            cls.mock_urls[url] = function
            return function
        return decorate

    @classmethod
    def route_wsgi(cls, host, app):
        assert callable(app)
        cls.mock_hosts[host] = app


@yield_fixture
def fx_urllib_mock(request):
    original_opener = urllib.request._opener
    handler_cls = type(
        'TestHTTPHandler_',
        (TestHTTPHandler,),
        {'mock_urls': {}, 'mock_hosts': {}}
    )
    opener = urllib.request.build_opener(handler_cls)
    urllib.request.install_opener(opener)
    yield handler_cls
    urllib.request._opener = original_opener
