from geofront.identity import Identity


def test_identity_eq():
    assert Identity(int, 1) == Identity(int, 1)
    assert not (Identity(int, 1) == Identity(int, 2))
    assert not (Identity(int, 1) == Identity(str, 1))
    assert not (Identity(int, 1) == Identity(str, 2))


def test_identity_hash():
    assert hash(Identity(int, 1)) == hash(Identity(int, 1))
