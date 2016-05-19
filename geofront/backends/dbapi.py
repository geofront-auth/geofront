""":mod:`geofront.backends.dbapi` --- Key store using DB-API 2.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. seealso::

   :pep:`249` --- Python Database API Specification v2.0

.. versionadded:: 0.2.0

"""
import base64
import contextlib
import types
import typing

from paramiko.pkey import PKey
from tsukkomi.typed import typechecked

from ..identity import Identity
from ..keystore import (KEY_TYPES, DuplicatePublicKeyError, KeyStore,
                        KeyTypeError, get_key_fingerprint)

__all__ = 'DatabaseKeyStore',


class DatabaseKeyStore(KeyStore):
    """Store public keys into database through DB-API 2.0.  It takes
    a module that implements DB-API 2.0, and arguments/keywords to
    its ``connect()`` method.  For example, the following code stores
    public keys into SQLite 3 database::

        import sqlite3
        DatabaseKeyStore(sqlite3, 'geofront.db')

    The following code stores public keys into PostgreSQL database
    through psycopg2_::

        import psycopg2
        DatabaseKeyStore(psycopg2, database='geofront', user='postgres')

    It will create a table named ``geofront_public_key`` into the database.

    :param db_module: :pep:`249` DB-API 2.0 compliant module
    :type db_module: :class:`types.ModuleType`
    :param \*args: arguments to ``db_module.connect()`` function
    :param \*kwargs: keyword arguments to ``db_module.connect()`` function

    .. _psycopg2: http://initd.org/psycopg/

    """

    @typechecked
    def __init__(self, db_module: types.ModuleType, *args, **kwargs) -> None:
        if not callable(getattr(db_module, 'connect', None)):
            module_name = db_module.__name__
            raise TypeError('db_module must be DB-API 2.0 compliant, but {} '
                            'lacks connect() function'.format(module_name))
        self.db_module = db_module
        self.integrity_error = db_module.IntegrityError
        self.connection_args = args
        self.connection_kwargs = kwargs

    @contextlib.contextmanager
    def _connect(self):
        connection = self.db_module.connect(*self.connection_args,
                                            **self.connection_kwargs)
        cursor = connection.cursor()
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS geofront_public_key (
                    key_type VARCHAR(64) NOT NULL,
                    key_fingerprint VARCHAR(32) NOT NULL,
                    key_base64 VARCHAR(2048) NOT NULL,
                    team_type VARCHAR(128) NOT NULL,
                    identifier VARCHAR(128) NOT NULL,
                    PRIMARY KEY (key_type, key_fingerprint)
                )
            ''')
            connection.commit()
        finally:
            cursor.close()
        yield connection
        connection.close()

    def _execute(self, cursor, sql: str, params: tuple) -> None:
        """To support various paramstyles.  See the following specification:

        http://legacy.python.org/dev/peps/pep-0249/#paramstyle

        """
        paramstyle = self.db_module.paramstyle
        if paramstyle == 'format':
            sql = sql.replace('?', '%s')
        elif paramstyle != 'qmark':
            if paramstyle == 'numeric':
                fmt = ':{}'
                i = 1
            else:
                if paramstyle == 'named':
                    fmt = ':p{}'
                else:  # pyformat
                    fmt = '%(p{})s'
                params = {'p' + str(i): val for i, val in enumerate(params)}
                i = 0
            while '?' in sql:
                sql = sql.replace('?', fmt.format(i), 1)
                i += 1
        cursor.execute(sql, params)

    def _get_key_params(self, public_key: PKey) -> typing.Tuple[str, str]:
        return public_key.get_name(), get_key_fingerprint(public_key, '')

    def _get_identity_params(self,
                             identity: Identity) -> typing.Tuple[str, str]:
        return ('{0.__module__}.{0.__qualname__}'.format(identity.team_type),
                str(identity.identifier))

    def _get_key_class(self, keytype: str) -> type:
        try:
            return KEY_TYPES[keytype]
        except KeyError:
            raise KeyTypeError('unsupported key type: ' + repr(keytype))

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
        with self._connect() as connection:
            cursor = connection.cursor()
            try:
                params = (self._get_key_params(public_key) +
                          (public_key.get_base64(),) +
                          self._get_identity_params(identity))
                self._execute(cursor, '''
                    INSERT INTO geofront_public_key (
                        key_type, key_fingerprint, key_base64,
                         team_type, identifier
                    ) VALUES (?, ?, ?, ?, ?)
                ''', params)
                connection.commit()
            except self.integrity_error as e:
                raise DuplicatePublicKeyError(str(e))
            finally:
                cursor.close()

    @typechecked
    def list_keys(self, identity: Identity) -> typing.AbstractSet[PKey]:
        with self._connect() as connection:
            cursor = connection.cursor()
            try:
                self._execute(cursor, '''
                    SELECT key_type, key_base64
                    FROM geofront_public_key
                    WHERE team_type = ? AND identifier = ?
                ''', self._get_identity_params(identity))
                return frozenset(
                    self._get_key_class(keytype)(data=base64.b64decode(b64))
                    for keytype, b64 in cursor.fetchall()
                )
            finally:
                cursor.close()

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
        with self._connect() as connection:
            cursor = connection.cursor()
            try:
                params = (self._get_key_params(public_key) +
                          self._get_identity_params(identity))
                self._execute(cursor, '''
                    DELETE FROM geofront_public_key
                    WHERE key_type = ? AND key_fingerprint = ? AND
                          team_type = ? AND identifier = ?
                ''', params)
                connection.commit()
            finally:
                cursor.close()
