from geofront.identity import Identity
from geofront.team import Team


class DummyTeamA(Team):

    pass


class DummyTeamB(Team):

    pass


def test_identity_eq():
    assert Identity(DummyTeamA, 1) == Identity(DummyTeamA, 1)
    assert not (Identity(DummyTeamA, 1) == Identity(DummyTeamA, 2))
    assert not (Identity(DummyTeamA, 1) == Identity(DummyTeamB, 1))
    assert not (Identity(DummyTeamA, 1) == Identity(DummyTeamB, 2))


def test_identity_ne():
    assert not (Identity(DummyTeamA, 1) != Identity(DummyTeamA, 1))
    assert Identity(DummyTeamA, 1) != Identity(DummyTeamA, 2)
    assert Identity(DummyTeamA, 1) != Identity(DummyTeamB, 1)
    assert Identity(DummyTeamA, 1) != Identity(DummyTeamB, 2)


def test_identity_hash():
    assert hash(Identity(DummyTeamA, 1)) == hash(Identity(DummyTeamA, 1))
