

def pytest_addoption(parser):
    parser.addoption('--redis-host', metavar='HOST', help='redis host')
    parser.addoption('--redis-port',
                     metavar='PORT',
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
