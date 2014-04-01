from paramiko import RSAKey
from pytest import fixture, mark

from geofront.keystore import KeyType, PublicKey


@mark.parametrize('as_bytes', [True, False])
def test_parse_line(as_bytes):
    line = (
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCom2CDLekY6AVGexhkjHn0t4uZGelVn'
        'AI2NN7jkRIkoFp+LH+wwSjYILZguMAGZxY203/L7WIurFHDdTWCC08YaQo6fgDyyxcExy'
        'Yxodm05BTKIWRPPOyl6AYt+NOfbPLe2OK4ywC3NicmQtafa2zysnrBAVZ1YUVyizIx2b7'
        'SxdCL25nf4t4MS+3U32JIhRY7cXEgqa32bvomZKGRY5J+GlMeSN1rgra+/wQ+BKSaGvk2'
        '7mV6dF5Xzla+FL9qjaN131e9znyMNvuyvb6a/DwHmMkq+naXzY/5M3f4WJFVD1YkDP5Cq'
        'VxLhOKj1FCzYChWGytlKZ45CeYsvSdrTWA5 dahlia@hongminhee-thinkpad-e435'
    )
    if as_bytes:
        line = line.encode()
    key = PublicKey.parse_line(line)
    assert isinstance(key, PublicKey)
    assert key.keytype == KeyType.ssh_rsa
    assert key.key == (
        b'\x00\x00\x00\x07\x73\x73\x68\x2d\x72\x73\x61\x00\x00\x00\x03\x01\x00'
        b'\x01\x00\x00\x01\x01\x00\xa8\x9b\x60\x83\x2d\xe9\x18\xe8\x05\x46\x7b'
        b'\x18\x64\x8c\x79\xf4\xb7\x8b\x99\x19\xe9\x55\x9c\x02\x36\x34\xde\xe3'
        b'\x91\x12\x24\xa0\x5a\x7e\x2c\x7f\xb0\xc1\x28\xd8\x20\xb6\x60\xb8\xc0'
        b'\x06\x67\x16\x36\xd3\x7f\xcb\xed\x62\x2e\xac\x51\xc3\x75\x35\x82\x0b'
        b'\x4f\x18\x69\x0a\x3a\x7e\x00\xf2\xcb\x17\x04\xc7\x26\x31\xa1\xd9\xb4'
        b'\xe4\x14\xca\x21\x64\x4f\x3c\xec\xa5\xe8\x06\x2d\xf8\xd3\x9f\x6c\xf2'
        b'\xde\xd8\xe2\xb8\xcb\x00\xb7\x36\x27\x26\x42\xd6\x9f\x6b\x6c\xf2\xb2'
        b'\x7a\xc1\x01\x56\x75\x61\x45\x72\x8b\x32\x31\xd9\xbe\xd2\xc5\xd0\x8b'
        b'\xdb\x99\xdf\xe2\xde\x0c\x4b\xed\xd4\xdf\x62\x48\x85\x16\x3b\x71\x71'
        b'\x20\xa9\xad\xf6\x6e\xfa\x26\x64\xa1\x91\x63\x92\x7e\x1a\x53\x1e\x48'
        b'\xdd\x6b\x82\xb6\xbe\xff\x04\x3e\x04\xa4\x9a\x1a\xf9\x36\xee\x65\x7a'
        b'\x74\x5e\x57\xce\x56\xbe\x14\xbf\x6a\x8d\xa3\x75\xdf\x57\xbd\xce\x7c'
        b'\x8c\x36\xfb\xb2\xbd\xbe\x9a\xfc\x3c\x07\x98\xc9\x2a\xfa\x76\x97\xcd'
        b'\x8f\xf9\x33\x77\xf8\x58\x91\x55\x0f\x56\x24\x0c\xfe\x42\xa9\x5c\x4b'
        b'\x84\xe2\xa3\xd4\x50\xb3\x60\x28\x56\x1b\x2b\x65\x29\x9e\x39\x09\xe6'
        b'\x2c\xbd\x27\x6b\x4d\x60\x39'
    )
    assert key.comment == 'dahlia@hongminhee-thinkpad-e435'


def test_from_pkey():
    rsakey = RSAKey.generate(1024)
    key = PublicKey.from_pkey(rsakey)
    assert key.keytype == KeyType.ssh_rsa
    assert key.base64_key == rsakey.get_base64()


@fixture
def fx_public_key():
    return PublicKey(
        KeyType.ssh_rsa,
        base64_key='AAAAB3NzaC1yc2EAAAABIwAAAQEA0ql70Tsi8ToDGm+gkkRGv12Eb15QSg'
                   'dVQeIFbasK+yHNITAOVHtbM3nlUTIxFh7sSga7UmEjCya0ljU0GJ+zvnFO'
                   'xKvRypBoUY38W8XkR3f2IJQwbWE7/t4Vs4DViramrZr/wnQtRstLZRncIj'
                   '307ApQuB18uedbtreGdg+cd75/KfTvDc3L17ZYlgdmJ+tTdzTi5mYbiPmt'
                   'n631Qm8/OCBazwUSfidRlG1SN97QJdV5ZFLNN+3BRR7RIRzYZ/2KEJqiOI'
                   '5nqi3TEiPeq49/LJElu4tdJ8icXT7COrGllnhBbpZdxRM26hhVXv62vOTQ'
                   'wXm1fumg0PgMACP2S1WVNw==',
        comment='dahlia@Hong-Minhees-MacBook-Pro.local'
    )


@fixture
def fx_equivalent_key(fx_public_key):
    return PublicKey(
        KeyType.ssh_rsa,
        key=fx_public_key.key,
        comment=fx_public_key.comment
    )


@fixture
def fx_equivalent_key_except_comment(fx_public_key):
    return PublicKey(KeyType.ssh_rsa, key=fx_public_key.key)


@fixture
def fx_different_keys(fx_public_key):
    return {
        PublicKey(KeyType.ssh_rsa, key=b'...'),
        PublicKey(KeyType.ssh_dss, key=fx_public_key.key),
        PublicKey(KeyType.ssh_dss, key=b'...')
    }


def test_public_key_eq(fx_public_key, fx_equivalent_key,
                       fx_equivalent_key_except_comment, fx_different_keys):
    assert fx_public_key == fx_equivalent_key
    assert fx_public_key == fx_equivalent_key_except_comment
    for key in fx_different_keys:
        assert not (fx_public_key == key)


def test_public_key_ne(fx_public_key, fx_equivalent_key,
                       fx_equivalent_key_except_comment, fx_different_keys):
    assert not (fx_public_key != fx_equivalent_key)
    assert not (fx_public_key != fx_equivalent_key_except_comment)
    for key in fx_different_keys:
        assert fx_public_key != key


def test_public_key_hash(fx_public_key, fx_equivalent_key,
                         fx_equivalent_key_except_comment, fx_different_keys):
    assert hash(fx_public_key) == hash(fx_equivalent_key)
    assert hash(fx_public_key) == hash(fx_equivalent_key_except_comment)
    for key in fx_different_keys:
        assert hash(fx_public_key) != hash(key)


@mark.parametrize('as_bytes', [True, False])
def test_public_key_str(fx_public_key, as_bytes):
    expected = (
        'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA0ql70Tsi8ToDGm+gkkRGv12Eb15QSgdVQ'
        'eIFbasK+yHNITAOVHtbM3nlUTIxFh7sSga7UmEjCya0ljU0GJ+zvnFOxKvRypBoUY38W8'
        'XkR3f2IJQwbWE7/t4Vs4DViramrZr/wnQtRstLZRncIj307ApQuB18uedbtreGdg+cd75'
        '/KfTvDc3L17ZYlgdmJ+tTdzTi5mYbiPmtn631Qm8/OCBazwUSfidRlG1SN97QJdV5ZFLN'
        'N+3BRR7RIRzYZ/2KEJqiOI5nqi3TEiPeq49/LJElu4tdJ8icXT7COrGllnhBbpZdxRM26'
        'hhVXv62vOTQwXm1fumg0PgMACP2S1WVNw== dahlia@Hong-Minhees-MacBook-Pro.l'
        'ocal'
    )
    if as_bytes:
        assert bytes(fx_public_key) == expected.encode()
    else:
        assert str(fx_public_key) == expected


@mark.parametrize('as_bytes', [True, False])
def test_public_key_str_without_comment(fx_equivalent_key_except_comment,
                                        as_bytes):
    expected = (
        'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA0ql70Tsi8ToDGm+gkkRGv12Eb15QSgdVQ'
        'eIFbasK+yHNITAOVHtbM3nlUTIxFh7sSga7UmEjCya0ljU0GJ+zvnFOxKvRypBoUY38W8'
        'XkR3f2IJQwbWE7/t4Vs4DViramrZr/wnQtRstLZRncIj307ApQuB18uedbtreGdg+cd75'
        '/KfTvDc3L17ZYlgdmJ+tTdzTi5mYbiPmtn631Qm8/OCBazwUSfidRlG1SN97QJdV5ZFLN'
        'N+3BRR7RIRzYZ/2KEJqiOI5nqi3TEiPeq49/LJElu4tdJ8icXT7COrGllnhBbpZdxRM26'
        'hhVXv62vOTQwXm1fumg0PgMACP2S1WVNw=='
    )
    if as_bytes:
        expected = expected.encode()
        assert bytes(fx_equivalent_key_except_comment).strip() == expected
    else:
        assert str(fx_equivalent_key_except_comment).strip() == expected
