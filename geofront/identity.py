""":mod:`geofront.identity` --- Member identification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import collections.abc
from typing import TYPE_CHECKING, Hashable, Type, Union, cast

if TYPE_CHECKING:
    from .team import Team  # noqa: F401

__all__ = 'Identity',


class Identity(collections.abc.Hashable):
    """Hashable value object which purposes to identify the owner of
    each public key in the store.

    :param team_type: a sbclass of :class:`~.team.Team`
    :type team_type: :class:`~typing.Type`\ [:class:`~.team.Team`]
    :param identifier: any hashable identifier for the owner.
                       it's interpreted by ``team_type``
    :type identifier: :class:`~typing.Hashable`
    :param access_token: an optional access token which may used by key store

    """

    #: (:class:`~typing.Type`\ [:class:`~.team.Team`]) A subclass of
    #: :class:`~.team.Team`.
    team_type = None  # type: Type[Team]

    #: (:class:`~typing.Hashable`) Any hashable identifier for
    #: the owner.  It's interpreted by :attr:`team_type`.
    identifier = None  # type: Union[Hashable, str, int]

    #: An optional access token which may be used by key store.
    #:
    #: .. note::
    #:
    #:    The attribute is ignored by :token:`==`, and :token:`!=`
    #:    operators, and :func:`hash()` function.
    access_token = None

    def __init__(self,
                 team_type: Type['Team'],
                 identifier: Union[Hashable, str, int],  # workaround mypy bug
                 access_token=None) -> None:
        if not isinstance(team_type, type):
            raise TypeError('team_type must be a type, not ' + repr(team_type))
        from .team import Team  # noqa: F811
        if not issubclass(team_type, Team):
            raise TypeError('team_type must be a subclass of {0.__module__}.'
                            '{0.__qualname__}'.format(Team))
        elif not callable(getattr(identifier, '__hash__')):
            raise TypeError('identifier must be hashable, not ' +
                            repr(identifier))
        self.team_type = cast(Type[Team], team_type)
        self.identifier = identifier  # type: Union[Hashable, str, int]
        self.access_token = access_token

    def __eq__(self, other) -> bool:
        return (isinstance(other, type(self)) and
                self.team_type is other.team_type and
                self.identifier == other.identifier)

    def __ne__(self, other) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash((self.team_type, self.identifier))

    def __repr__(self) -> str:
        fmt = ('{0.__module__}.{0.__qualname__}'
               '({1.__module__}.{1.__qualname__}, {2!r}, access_token={3!r})')
        return fmt.format(
            type(self),
            self.team_type,
            self.identifier,
            self.access_token
        )
