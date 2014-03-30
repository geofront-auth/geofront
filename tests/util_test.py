import numbers

from pytest import raises

from geofront.util import typed


@typed
def add(a: int, b: int):
    return a + b


def test_typed():
    with raises(TypeError):
        add('strings are not ', 'accepted')
    with raises(TypeError):
        add('string', 2)
    with raises(TypeError):
        add(1, 'string')
    assert add(1, 2) == 3


@typed
def typed_function(a, b: numbers.Real):
    return a, b


def test_typed_subtype():
    with raises(TypeError):
        typed_function(None, 'string')
    assert typed_function(None, 123) == (None, 123)
    assert typed_function(None, 123.56) == (None, 123.56)
