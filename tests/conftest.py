

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
