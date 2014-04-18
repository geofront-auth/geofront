from paramiko.dsskey import DSSKey
from paramiko.rsakey import RSAKey
from pytest import fixture, raises

from geofront.keystore import (KeyTypeError, format_openssh_pubkey,
                               get_key_fingerprint, parse_openssh_pubkey)


@fixture
def fx_id_rsa_pub():
    return (
        'AAAAB3NzaC1yc2EAAAABIwAAAQEA0ql70Tsi8ToDGm+gkkRGv12Eb15QSgdVQeIFbasK+'
        'yHNITAOVHtbM3nlUTIxFh7sSga7UmEjCya0ljU0GJ+zvnFOxKvRypBoUY38W8XkR3f2IJ'
        'QwbWE7/t4Vs4DViramrZr/wnQtRstLZRncIj307ApQuB18uedbtreGdg+cd75/KfTvDc3'
        'L17ZYlgdmJ+tTdzTi5mYbiPmtn631Qm8/OCBazwUSfidRlG1SN97QJdV5ZFLNN+3BRR7R'
        'IRzYZ/2KEJqiOI5nqi3TEiPeq49/LJElu4tdJ8icXT7COrGllnhBbpZdxRM26hhVXv62v'
        'OTQwXm1fumg0PgMACP2S1WVNw=='
    )


def test_parse_openssh_pubkey_rsa(fx_id_rsa_pub):
    pkey = parse_openssh_pubkey('ssh-rsa ' + fx_id_rsa_pub)
    assert isinstance(pkey, RSAKey)
    assert pkey.get_name() == 'ssh-rsa'
    assert pkey.get_base64() == fx_id_rsa_pub
    pkey = parse_openssh_pubkey('ssh-rsa ' + fx_id_rsa_pub + ' comment')
    assert isinstance(pkey, RSAKey)
    assert pkey.get_name() == 'ssh-rsa'
    assert pkey.get_base64() == fx_id_rsa_pub


def test_parse_openssh_pubkey_dsa():
    id_dsa_pub = (
        'AAAAB3NzaC1kc3MAAACBALTeFi9rlCkORWTj2sznDx2p/nUDFGZY0j9ynIioho0vlNfgj'
        '4U9/3SCq4JjhXhH7OB6h0NyUSNEVe9bbe7mHFTpQWwy1bmXEBaJALv1IqIBme1ZJcdUbe'
        'ZM3PCLmbPTE7sjgUwk98hT3TI8CI5hLkJmsV1nFckEONgIG9IPjnmnAAAAFQCb72U4lNY'
        '2DsZ+e2TaxTtT8i996QAAAIEAlO7/8Vypf5bgAkeHGJ15cfiuR1X/gkSUj+sAhJYJ7pyB'
        'h7vnJbBPztgxVvuHxELFcCufFyps7sibUq4MifqBPrVwLiK4PiNNcK8M2hjDJmWrqo/Bw'
        'LRXkc1LWWxLr/PCBVeqAe2OTFEtu4ZLaqlex+WI2Ezgn4pItAH9lIACBlcAAACAa5GI36'
        'nWqU89z07Pdh7q8gZHR9KXHMS3T6dGxkOhLb+XSATV14+udjqtrULs552d+d7Pdq+0KBm'
        '+6lC/YRn6ETsJ2AJzWxlG+sJ/eTFEWw9Q2uTWOBRbAqL2VJG5DG+K+lhgRRNNKHMtUF1j'
        '1MeJb71HT7amaOcE+dNEgKS0xi4='
    )
    pkey = parse_openssh_pubkey('ssh-dss ' + id_dsa_pub)
    assert isinstance(pkey, DSSKey)
    assert pkey.get_name() == 'ssh-dss'
    assert pkey.get_base64() == id_dsa_pub
    pkey = parse_openssh_pubkey('ssh-dss ' + id_dsa_pub + ' comment')
    assert isinstance(pkey, DSSKey)
    assert pkey.get_name() == 'ssh-dss'
    assert pkey.get_base64() == id_dsa_pub


def test_parse_openssh_unsupported():
    with raises(KeyTypeError):
        parse_openssh_pubkey(
            'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyN'
            'TYAAABBBDs0y6X8UquYBtTvDjbK+RZIAWduMbfWfUmh2MRtWpo2ZqEyQiyeTRDJ/4'
            '1A5heiONtm7QhUJoBF5VBUjsxiIFk= dahlia@hongminhee-thinkpad-e435'
        )


def test_format_openssh_pubkey():
    rsakey = RSAKey.generate(1024)
    assert parse_openssh_pubkey(format_openssh_pubkey(rsakey)) == rsakey
    dsskey = DSSKey.generate(1024)
    assert parse_openssh_pubkey(format_openssh_pubkey(dsskey)) == dsskey


def test_get_key_fingerprint(fx_id_rsa_pub):
    pkey = parse_openssh_pubkey('ssh-rsa ' + fx_id_rsa_pub)
    assert (get_key_fingerprint(pkey) ==
            'f5:6e:03:1c:cd:2c:84:64:d7:94:18:8b:79:60:11:df')
    assert (get_key_fingerprint(pkey, '-') ==
            'f5-6e-03-1c-cd-2c-84-64-d7-94-18-8b-79-60-11-df')
    assert get_key_fingerprint(pkey, '') == 'f56e031ccd2c8464d794188b796011df'
