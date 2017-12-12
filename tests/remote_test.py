import collections.abc
import datetime
import time

from paramiko.rsakey import RSAKey
from pytest import mark, raises

from geofront.identity import Identity
from geofront.keystore import format_openssh_pubkey, parse_openssh_pubkey
from geofront.remote import (AuthorizedKeyList, DefaultPermissionPolicy,
                             GroupMetadataPermissionPolicy, Remote,
                             RemoteSetFilter, RemoteSetUnion, authorize)
from geofront.team import Team


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


def get_next_line(fo):
    line = ''
    while not line:
        line = fo.readline()
        if not line:
            return line
        line = line.strip()
    return line


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
            assert parse_openssh_pubkey(get_next_line(f)) == keys[i]
        assert not get_next_line(f)
    # Positive index
    key_list[2] = keys[3]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(get_next_line(f)) == keys[0]
        assert parse_openssh_pubkey(get_next_line(f)) == keys[1]
        assert parse_openssh_pubkey(get_next_line(f)) == keys[3]
        assert not get_next_line(f)
    # Negative index
    key_list[-1] = keys[4]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(get_next_line(f)) == keys[0]
        assert parse_openssh_pubkey(get_next_line(f)) == keys[1]
        assert parse_openssh_pubkey(get_next_line(f)) == keys[4]
        assert not get_next_line(f)


def test_authorized_keys_list_insert(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    new_key = RSAKey.generate(1024)
    key_list.insert(2, new_key)
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(get_next_line(f)) == keys[0]
        assert parse_openssh_pubkey(get_next_line(f)) == keys[1]
        assert parse_openssh_pubkey(get_next_line(f)) == new_key
        for i in range(2, 6):
            assert parse_openssh_pubkey(get_next_line(f)) == keys[i]
        assert not get_next_line(f)


def test_authorized_keys_list_extend(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    new_keys = [RSAKey.generate(1024) for _ in range(3)]
    key_list.extend(new_keys)
    with path.join('.ssh', 'authorized_keys').open() as f:
        for i in range(6):
            assert parse_openssh_pubkey(get_next_line(f)) == keys[i]
        for i in range(3):
            assert parse_openssh_pubkey(get_next_line(f)) == new_keys[i]
        assert not get_next_line(f)


def test_authorized_keys_list_delitem(fx_authorized_sftp):
    sftp_client, path, keys = fx_authorized_sftp
    key_list = AuthorizedKeyList(sftp_client)
    # Slice deletion
    del key_list[3:]
    with path.join('.ssh', 'authorized_keys').open() as f:
        for i in range(3):
            assert parse_openssh_pubkey(get_next_line(f)) == keys[i]
        assert not get_next_line(f)
    # Positive index
    del key_list[2]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(get_next_line(f)) == keys[0]
        assert parse_openssh_pubkey(get_next_line(f)) == keys[1]
        assert not get_next_line(f)
    # Negative index
    del key_list[-1]
    with path.join('.ssh', 'authorized_keys').open() as f:
        assert parse_openssh_pubkey(get_next_line(f)) == keys[0]
        assert not get_next_line(f)


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
        saved_keys = frozenset(parse_openssh_pubkey(line)
                               for line in f if line.strip())
        assert saved_keys == (public_keys | {master_key})
    while datetime.datetime.now(datetime.timezone.utc) <= expires_at:
        time.sleep(1)
    time.sleep(1)
    with authorized_keys_path.open() as f:
        saved_keys = map(parse_openssh_pubkey, f)
        assert frozenset(saved_keys) == {master_key}


class DummyTeam(Team):

    pass


def test_default_permission_policy():
    remotes = {
        'a': Remote('a', 'localhost'),
        'b': Remote('b', 'localhost')
    }
    identity = Identity(DummyTeam, 'a')
    p = DefaultPermissionPolicy()
    assert p.filter(remotes, identity, {'x'}) == remotes
    for remote in remotes.values():
        assert p.permit(remote, identity, {'x'})


@mark.parametrize(('key', 'separator'), [
    ('role', None),
    ('role', ','),
    ('role', '/'),
    ('groups', None)
])
def test_group_metadata_permission_policy(key, separator):
    sep = separator or ' '
    remotes = {
        'web-1': Remote(
            'ubuntu', '192.168.0.5',
            metadata={key: sep.join(['web', 'a']), 'other': 'ignore'}
        ),
        'web-2': Remote(
            'ubuntu', '192.168.0.6',
            metadata={key: sep.join(['web', 'b']), 'other': 'ignore'}
        ),
        'web-3': Remote(
            'ubuntu', '192.168.0.7',
            metadata={key: sep.join(['web', 'c']), 'other': 'ignore'}
        ),
        'worker-1': Remote(
            'ubuntu', '192.168.0.25',
            metadata={key: sep.join(['worker', 'a']), 'other': 'ignore'}
        ),
        'worker-2': Remote(
            'ubuntu', '192.168.0.26',
            metadata={key: sep.join(['worker', 'b']), 'other': 'ignore'}
        ),
        'db-1': Remote(
            'ubuntu', '192.168.0.50',
            metadata={key: sep.join(['db', 'a']), 'other': 'ignore'}
        ),
        'db-2': Remote(
            'ubuntu', '192.168.0.51',
            metadata={key: sep.join(['db', 'b']), 'other': 'ignore'}
        )
    }

    def subset(*keys):
        return {a: r for a, r in remotes.items() if a in keys}
    p = GroupMetadataPermissionPolicy(key, separator)
    identity = Identity(DummyTeam, 1)
    assert (p.filter(remotes, identity, {'web', 'a'}) ==
            subset('web-1', 'web-2', 'web-3', 'worker-1', 'db-1'))
    assert (p.filter(remotes, identity, {'db', 'c'}) ==
            subset('web-3', 'worker-3', 'db-1', 'db-2'))
    assert p.permit(remotes['db-1'], identity, {'web', 'a'})
    assert not p.permit(remotes['db-1'], identity, {'web', 'b'})
    assert p.permit(remotes['db-1'], identity, {'db', 'a'})
    assert p.permit(remotes['db-1'], identity, {'db', 'b'})


def test_remote_set_filter():
    dict_ = {
        'inc-a': Remote('a', 'example.com'),
        'inc-b': Remote('b', 'example.com'),
        'exc-c': Remote('c', 'example.com'),
        'exc-d': Remote('d', 'example.com'),
        'inc-e': Remote('e', 'example.com', 10022),
        'exc-f': Remote('f', 'example.com', 10022),
    }
    filtered = RemoteSetFilter(
        lambda a, r: a.startswith('inc-') and r.port == 22,
        dict_
    )
    assert isinstance(filtered, collections.abc.Mapping)
    assert set(filtered) == set(filtered.keys()) == {'inc-a', 'inc-b'}
    assert len(filtered) == 2
    assert filtered['inc-a'] == filtered.get('inc-a') == dict_['inc-a']
    assert filtered['inc-b'] == filtered.get('inc-b') == dict_['inc-b']
    with raises(KeyError):
        filtered['exc-c']
    assert filtered.get('exc-c') is None
    with raises(KeyError):
        filtered['exc-d']
    assert filtered.get('exc-d') is None
    with raises(KeyError):
        filtered['inc-e']
    assert filtered.get('inc-e') is None
    with raises(KeyError):
        filtered['exc-f']
    assert filtered.get('exc-f') is None
    assert set(filtered.items()) == {
        ('inc-a', dict_['inc-a']),
        ('inc-b', dict_['inc-b']),
    }
    assert set(filtered.values()) == {dict_['inc-a'], dict_['inc-b']}
    #
    # test lazy evaluation
    del dict_['inc-b']
    dict_['inc-g'] = g = Remote('g', 'sample.com')
    assert set(filtered) == set(filtered.keys()) == {'inc-a', 'inc-g'}
    assert len(filtered) == 2
    assert filtered['inc-a'] == filtered.get('inc-a') == dict_['inc-a']
    with raises(KeyError):
        filtered['exc-c']
    assert filtered.get('exc-c') is None
    with raises(KeyError):
        filtered['exc-d']
    assert filtered.get('exc-d') is None
    with raises(KeyError):
        filtered['inc-e']
    assert filtered.get('inc-e') is None
    with raises(KeyError):
        filtered['exc-f']
    assert filtered.get('exc-f') is None
    assert filtered['inc-g'] == filtered.get('inc-g') == g
    assert set(filtered.items()) == {('inc-a', dict_['inc-a']), ('inc-g', g)}


def test_remote_set_union():
    a = {
        'web-1': Remote('ubuntu', '192.168.0.5'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.8'),
    }
    b = {
        'worker-1': Remote('ubuntu', '192.168.0.25'),
        'worker-2': Remote('ubuntu', '192.168.0.26'),
        'db-1': Remote('ubuntu', '192.168.0.27'),
        'db-2': Remote('ubuntu', '192.168.0.28'),
        'db-3': Remote('ubuntu', '192.168.0.29'),
    }
    c = {
        'web-1': Remote('ubuntu', '192.168.0.49'),
        'db-1': Remote('ubuntu', '192.168.0.50'),
        'db-2': Remote('ubuntu', '192.168.0.51'),
    }
    union = RemoteSetUnion(a, b, c)
    assert isinstance(union, collections.abc.Mapping)
    assert set(union) == set(union.keys()) == {
        'web-1', 'web-2', 'web-3', 'worker-1', 'worker-2',
        'db-1', 'db-2', 'db-3'
    }
    assert len(union) == 8
    assert union['web-1'] == union.get('web-1') == c['web-1']
    assert union['web-2'] == union.get('web-2') == a['web-2']
    assert union['web-3'] == union.get('web-3') == a['web-3']
    assert union['worker-1'] == union.get('worker-1') == b['worker-1']
    assert union['worker-2'] == union.get('worker-2') == b['worker-2']
    assert union['db-1'] == union.get('db-1') == c['db-1']
    assert union['db-2'] == union.get('db-2') == c['db-2']
    assert union['db-3'] == union.get('db-3') == b['db-3']
    assert set(union.items()) == {
        ('web-1', c['web-1']),
        ('web-2', a['web-2']),
        ('web-3', a['web-3']),
        ('worker-1', b['worker-1']),
        ('worker-2', b['worker-2']),
        ('db-1', c['db-1']),
        ('db-2', c['db-2']),
        ('db-3', b['db-3']),
    }
    assert set(union.values()) == {
        c['web-1'], a['web-2'], a['web-3'],
        b['worker-1'], b['worker-2'],
        c['db-1'], c['db-2'], b['db-3'],
    }
    #
    # test lazy evaluation
    del c['web-1']
    assert isinstance(union, collections.abc.Mapping)
    assert set(union) == set(union.keys()) == {
        'web-1', 'web-2', 'web-3', 'worker-1', 'worker-2',
        'db-1', 'db-2', 'db-3'
    }
    assert len(union) == 8
    assert union['web-1'] == union.get('web-1') == a['web-1']
    assert union['web-2'] == union.get('web-2') == a['web-2']
    assert union['web-3'] == union.get('web-3') == a['web-3']
    assert union['worker-1'] == union.get('worker-1') == b['worker-1']
    assert union['worker-2'] == union.get('worker-2') == b['worker-2']
    assert union['db-1'] == union.get('db-1') == c['db-1']
    assert union['db-2'] == union.get('db-2') == c['db-2']
    assert union['db-3'] == union.get('db-3') == b['db-3']
    assert set(union.items()) == {
        ('web-1', a['web-1']),
        ('web-2', a['web-2']),
        ('web-3', a['web-3']),
        ('worker-1', b['worker-1']),
        ('worker-2', b['worker-2']),
        ('db-1', c['db-1']),
        ('db-2', c['db-2']),
        ('db-3', b['db-3']),
    }
    assert set(union.values()) == {
        a['web-1'], a['web-2'], a['web-3'],
        b['worker-1'], b['worker-2'],
        c['db-1'], c['db-2'], b['db-3'],
    }
