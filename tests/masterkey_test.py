import os.path

from paramiko.rsakey import RSAKey
from pytest import raises

from geofront.masterkey import EmptyStoreError, FileSystemMasterKeyStore


def test_fs_master_key_store_load():
    path = os.path.join(os.path.dirname(__file__), 'test_id_rsa')
    s = FileSystemMasterKeyStore(path)
    key = s.load()
    assert isinstance(key, RSAKey)
    assert key.get_base64() == (
        'AAAAB3NzaC1yc2EAAAADAQABAAABAQC7+fDpQ9sQKIdzXvqT3TzrPp2OpUCOJtUW3k0oi'
        'trqqHe1XiCke++DSpAv56poCppTj9qo3N1HyhZhSv/jH7/ejZ8NZdtvLIZGOCQZVdKNy0'
        'cg7jlimrWA2s8X201Yn3hYpUrYJYbhAAuQM5flvbyBtn5/miONQ8NVimgjG6UVANVqX4W'
        'H9kqdr4SBf45/+BAdenf2j5DC3xceOOW8wZfe2rOJpQ0msVxMeXExGqF9DS2E3bqOwE1C'
        'MPEGYr5KZCx7IeJ/4udBuKc/gOXb8tPiTTNxtYXEBcqhBdCa/M6pEdW5LiHxxoF5b6xY9'
        'q0nmi7Rn0weXK0SufhGgKrpSH+B'
    )


def test_fs_master_key_store_save(tmpdir):
    path = tmpdir.join('id_rsa')
    s = FileSystemMasterKeyStore(str(path))
    with raises(EmptyStoreError):
        s.load()
    key = RSAKey.generate(1024)
    s.save(key)
    stored_key = s.load()
    assert isinstance(stored_key, RSAKey)
    assert stored_key.get_base64() == stored_key.get_base64()
