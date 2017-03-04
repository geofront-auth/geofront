from pytest import fail, fixture, skip, yield_fixture
from werkzeug.utils import import_string

from ..keystore_test import assert_keystore_compliance
from ..server_test import DummyTeam
from geofront.backends.dbapi import DatabaseKeyStore
from geofront.identity import Identity


DRIVERS = {
    'sqlite3': 'pysqlite',  # https://docs.python.org/3/library/sqlite3.html
    'psycopg2': 'psycopg2',  # http://initd.org/psycopg/
    'pymysql': 'PyMySQL',  # http://www.pymysql.org/
    'mysql.connector': 'mysql-connector-python',
    # http://dev.mysql.com/doc/connector-python/en/
}


@yield_fixture(scope='function', params=list(DRIVERS.keys()))
def fx_db_module(request, tmpdir):
    import_name = request.param
    package = DRIVERS[import_name]
    try:
        db_module = import_string(import_name)
    except ImportError:
        skip(package + ' is not installed; skipped')
    args = ()
    kwargs = {}
    getoption = request.config.getoption
    if import_name == 'sqlite3':
        args = str(tmpdir.join('geofront_test.db')),
    elif package == 'psycopg2':
        try:
            pgdatabase = getoption('--postgresql-database')
        except ValueError:
            pgdatabase = None
        if pgdatabase is None:
            skip('--postgresql-database is not provided; skipped')
        kwargs['database'] = pgdatabase
        for option in 'host', 'port', 'user', 'password':
            try:
                kwargs[option] = getoption('--postgresql-' + option)
            except ValueError:
                continue
    elif 'mysql' in import_name:
        try:
            mysql_db = getoption('--mysql-database')
        except ValueError:
            mysql_db = None
        if mysql_db is None:
            skip('--mysql-database is not provided; skipped')
        kwargs['database'] = mysql_db
        for option in 'host', 'port', 'user', 'passwd':
            try:
                kwargs[option] = getoption('--mysql-' + option)
            except ValueError:
                continue
            if kwargs[option] is None:
                del kwargs[option]
    else:
        fail('arguments to {}.connect() are not ready'.format(import_name))
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    yield db_module, args, kwargs
    if 'sqlite' not in import_name.lower():
        connection = db_module.connect(*args, **kwargs)
        try:
            cursor = connection.cursor()
            try:
                cursor.execute('DROP TABLE geofront_public_key')
            finally:
                cursor.close()
        finally:
            connection.close()


@fixture
def fx_db_key_store(fx_db_module):
    mod, args, kwargs = fx_db_module
    return DatabaseKeyStore(mod, *args, **kwargs)


def test_db_key_store(fx_db_key_store):
    identity = Identity(DummyTeam, 'abcd')
    assert_keystore_compliance(fx_db_key_store, identity)
    identity2 = Identity(DummyTeam, 'efg')
    assert_keystore_compliance(fx_db_key_store, identity2)
