""":mod:`geofront.identity` --- Member identification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import collections.abc

from tsukkomi.typed import typechecked

__all__ = 'Identity',


class Identity(collections.abc.Hashable):
    """Hashable value object which purposes to identify the owner of
    each public key in the store.

    :param team_type: a sbclass of :class:`~.team.Team`
    :type team_type: :class:`type`
    :param identifier: any hashable identifier for the owner.
                       it's interpreted by ``team_type``
    :type identifier: :class:`collections.abc.Hashable`
    :param access_token: an optional access token which may used by key store

    """

    #: (:class:`type`) A subclass of :class:`~.team.Team`.
    team_type = None

    #: (:class:`collections.abc.Hashable`) Any hashable identifier for
    #: the owner.  It's interpreted by :attr:`team_type`.
    identifier = None

    #: An optional access token which may be used by key store.
    #:
    #: .. note::
    #:
    #:    The attribute is ignored by :token:`==`, and :token:`!=`
    #:    operators, and :func:`hash()` function.
    access_token = None

    @typechecked
    def __init__(self,
                 team_type: type,
                 identifier: collections.abc.Hashable,
                 access_token=None) -> None:
        self.team_type = team_type
        self.identifier = identifier
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
