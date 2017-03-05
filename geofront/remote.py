""":mod:`geofront.remote` --- Remote sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every :class:`RemoteSet` is represented as a mapping (which is immutable,
or mutable) of alias :class:`str` to :class:`Remote` object e.g.::

    {
        'web-1': Remote('ubuntu', '192.168.0.5'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.25'),
        'worker-2': Remote('ubuntu', '192.168.0.26'),
        'db-1': Remote('ubuntu', '192.168.0.50'),
        'db-2': Remote('ubuntu', '192.168.0.51'),
    }

However, in the age of the cloud, you don't have to manage the remote set
since the most of cloud providers offer their API to list provisioned
remote nodes.

Geofront provides builtin :class:`~.backends.cloud.CloudRemoteSet`,
a subtype of :class:`RemoteSet` (which is alias of
:class:`~typing.Mapping`\ [:class:`str`, :class:`Remote`]), that proxies to
the list dynamically made by cloud providers.

.. versionchanged:: 0.2.0
   ``CloudRemoteSet`` is moved from this module to
   :mod:`geofront.backends.cloud`.
   See :class:`~.backends.cloud.CloudRemoteSet`.

"""
import collections.abc
import datetime
import io
import itertools
import logging
import threading
import time
from typing import (TYPE_CHECKING,
                    AbstractSet, Callable, ItemsView, Iterable, Iterator,
                    List, Mapping, Optional, Tuple, Union, ValuesView,
                    cast)

from paramiko.pkey import PKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport
from typeguard import typechecked

from .identity import Identity
from .keystore import format_openssh_pubkey, parse_openssh_pubkey
from .team import GroupSet

if TYPE_CHECKING:
    from typing import Set  # noqa: F401

__all__ = ('AuthorizedKeyList', 'DefaultPermissionPolicy',
           'GroupMetadataPermissionPolicy', 'PermissionPolicy',
           'Remote', 'RemoteSet', 'RemoteSetFilter', 'RemoteSetUnion',
           'authorize')


class Remote:
    """Remote node to SSH.

    :param user: the username to :program:`ssh`
    :type user: :class:`str`
    :param host: the host to access
    :type host: :class:`str`
    :param port: the port number to :program:`ssh`.
                 the default is 22 which is the default :program:`ssh` port
    :type port: :class:`int`
    :param metadata: optional metadata mapping.  keys and values have to
                     be all strings.  empty by default
    :type metadata: :class:`~typing.Mapping`\ [:class:`str`, :class:`object`]

    .. versionadded:: 0.2.0
       Added optional ``metadata`` parameter.

    """

    #: (:class:`str`) The username to SSH.
    user = None  # type: str

    #: (:class:`str`) The hostname to access.
    host = None  # type: str

    #: (:class:`int`) The port number to SSH.
    port = None  # type: int

    #: (:class:`~typing.Mapping`\ [:class:`str`, :class:`object`])
    #: The additional metadata.
    #: Note that it won't affect to :func:`hash()` of the object,
    #: nor :token:`==`/:token:`!=` comparison of the object.
    #:
    #: .. versionadded:: 0.2.0
    metadata = None  # type: Mapping[str, object]

    @typechecked
    def __init__(self,
                 user: str,
                 host: str,
                 port: int=22,
                 metadata: Mapping[str, object]={}) ->None:
        self.user = user
        self.host = host
        self.port = port
        self.metadata = dict(metadata)

    def __eq__(self, other) -> bool:
        return (isinstance(other, type(self)) and
                self.user == other.user and
                self.host == other.host and
                self.port == other.port)

    def __ne__(self, other) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.user, self.host, self.port))

    def __str__(self) -> str:  # pragma: no cover
        return '{}@{}:{}'.format(self.user, self.host, self.port)

    def __repr__(self) -> str:
        return '{0.__module__}.{0.__qualname__}{1!r}'.format(
            type(self), (self.user, self.host, self.port, self.metadata)
        )


#: The abstract type for remote sets.  Keys are strings and values are
#: :class:`Remote` objects.
#:
#: Alias of :class:`~typing.AbstractSet`\ [:class:`str`, :class:`Remote`].
#:
#: .. versionadded:: 0.4.0
RemoteSet = Mapping[str, Remote]


class AuthorizedKeyList(collections.abc.MutableSequence):
    """List-like abstraction for remote :file:`authorized_keys`.

    Note that the contents are all lazily evaluated, so in order to
    pretend heavy duplicate communications over SFTP use :func:`list()`
    to eagerly evaluate e.g.::

        lazy_list = AuthorizedKeyList(sftp_client)
        eager_list = list(lazy_list)
        # ... some modifications on eager_list ...
        lazy_list[:] = eager_list

    :param sftp_client: the remote sftp connection to access
                        :file:`authorized_keys`
    :type sftp_client: :class:`paramiko.sftp_client.SFTPClient`

    """

    #: (:class:`str`) The path of :file:`authorized_keys` file.
    FILE_PATH = '.ssh/authorized_keys'

    @typechecked
    def __init__(self, sftp_client: SFTPClient) -> None:
        self.sftp_client = sftp_client

    def _iterate_lines(self) -> Iterator[str]:
        with io.BytesIO() as fo:
            self.sftp_client.getfo(self.FILE_PATH, fo)
            fo.seek(0)
            for line in fo:
                line_str = line.decode().strip()
                if line_str:
                    yield line_str

    def _save(self,
              lines: List[str],
              existing_lines: Optional[List[str]]=None) -> None:
        check = frozenset(line.strip() for line in lines)
        if existing_lines is None:
            mode = 'w'
        else:
            assert lines[:len(existing_lines)] == existing_lines
            lines = lines[len(existing_lines):]
            mode = 'a'
        with self.sftp_client.open(self.FILE_PATH, mode) as fo:
            if mode == 'a':
                fo.write('\n')
            for line in lines:
                fo.write(line + '\n')
        actual = frozenset(self._iterate_lines())
        if actual != check:
            logger = logging.getLogger(__name__ + '.AuthorizedKeyList._save')
            logger.debug('file check error: expected = %r, actual = %r',
                         check, actual)
            raise IOError('failed to write to ' + self.FILE_PATH)

    def __iter__(self) -> Iterator[PKey]:
        for line in self._iterate_lines():
            line = line.strip()
            if line:
                yield parse_openssh_pubkey(line)

    def __len__(self) -> int:
        i = 0
        for _ in self._iterate_lines():
            i += 1
        return i

    def __getitem__(self, index: Union[slice, int]) -> PKey:
        if isinstance(index, slice):
            lines = list(self._iterate_lines())
            return list(map(parse_openssh_pubkey, lines[index]))
        elif isinstance(index, int):
            if index >= 0:
                for i, line in enumerate(self._iterate_lines()):
                    if i == index:
                        return parse_openssh_pubkey(line)
            else:
                lines = list(self._iterate_lines())
                line = lines[index]
                return parse_openssh_pubkey(line)
            raise IndexError('authorized_keys out of range: ' + repr(index))
        raise TypeError(
            'authorized_keys indices must be integers, not '
            '{0.__module__}.{0.__qualname__}'.format(type(index))
        )

    def __setitem__(self, index: Union[slice, int], value: PKey):
        lines = list(self._iterate_lines())
        if isinstance(index, slice):
            lines[index] = map(format_openssh_pubkey, value)
        elif isinstance(index, int):
            lines[index] = format_openssh_pubkey(value)
        else:
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        self._save(lines)

    def insert(self, index: int, value: PKey) -> None:
        if not isinstance(index, int):
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        lines = list(self._iterate_lines())
        lines.insert(index, format_openssh_pubkey(value))
        self._save(lines)

    def extend(self, values: Iterable[PKey]) -> None:
        existing_lines = list(self._iterate_lines())
        appended_lines = map(format_openssh_pubkey, values)
        lines = itertools.chain(existing_lines, appended_lines)
        self._save(list(lines), existing_lines=existing_lines)

    def __delitem__(self, index: Union[int, slice]) -> None:
        if not isinstance(index, (int, slice)):
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        lines = list(self._iterate_lines())
        del lines[index]
        self._save(lines)


@typechecked
def authorize(public_keys: AbstractSet[PKey],
              master_key: PKey,
              remote: Remote,
              timeout: datetime.timedelta) -> datetime.datetime:
    """Make an one-time authorization to the ``remote``, and then revokes
    it when ``timeout`` reaches soon.

    :param public_keys: the set of public keys to authorize
    :type public_keys:
        :class:`~typing.AbstractSet`\ [:class:`paramiko.pkey.PKey`]
    :param master_key: the master key (*not owner's key*)
    :type master_key: :class:`paramiko.pkey.PKey`
    :param remote: a remote to grant access permission
    :type remote: :class:`~.remote.Remote`
    :param timeout: the time an authorization keeps alive
    :type timeout: :class:`datetime.timedelta`
    :return: the expiration time
    :rtype: :class:`datetime.datetime`

    """
    transport = Transport((remote.host, remote.port))
    transport.connect(username=remote.user, pkey=master_key)
    try:
        sftp_client = SFTPClient.from_transport(transport)
        try:
            authorized_keys = AuthorizedKeyList(sftp_client)
            authorized_keys.extend(public_keys)
        except:
            sftp_client.close()
            raise
    except:
        transport.close()
        raise

    def rollback():
        time.sleep(timeout.total_seconds())
        authorized_keys[:] = [master_key]
        sftp_client.close()
        transport.close()
    timer = threading.Thread(target=rollback)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + timeout
    timer.start()
    return expires_at


class PermissionPolicy:
    """Permission policy determines which remotes are visible by a team
    member, and which remotes are allowed to SSH.  So each remote
    can have one of three states for each team member:

    Listed and allowed
        A member can SSH to the remote.

    Listed but disallowed
        A member can be aware of the remote, but cannot SSH to it.

    Unlisted and disallowed
        A member can't be aware of the remote, and can't SSH to it either.

    Unlisted but allowed
        It is possible in theory, but mostly meaningless in practice.

    The implementation of this interface has to implement two methods.
    One is :meth:`filter()` which determines whether remotes are listed or
    unlisted.  Other one is :meth:`permit()` which determines whether
    remotes are allowed or disallowed to SSH.

    .. versionadded:: 0.2.0

    """

    @typechecked
    def filter(self,
               remotes: RemoteSet,
               identity: Identity,
               groups: GroupSet) -> RemoteSet:
        """Determine which ones in the given ``remotes`` are visible
        to the ``identity`` (which belongs to ``groups``).  The resulted
        mapping of filtered remotes has to be a subset of the input
        ``remotes``.

        :param remotes: the remotes set to filter.  keys are alias strings
                        and values are :class:`Remote` objects
        :type remotes: :class:`RemoteSet`
        :param identity: the identity that the filtered remotes would
                         be visible to
        :type identity: :class:`~.identity.Identity`
        :param groups: the groups that the given ``identity`` belongs to.
                       every element is a group identifier and
                       :class:`~typing.Hashable`
        :type groups: :const:`~.team.GroupSet`
        :return: the filtered result remote set
        :rtype: :class:`RemoteSet`

        """
        raise NotImplementedError('filter() method has to be implemented')

    @typechecked
    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: GroupSet) -> bool:
        """Determine whether to allow the given ``identity`` (which belongs
        to ``groups``) to SSH the given ``remote``.

        :param remote: the remote to determine
        :type remote: :class:`Remote`
        :param identity: the identity to determine
        :type identity: :class:`~.identity.Identity`
        :param groups: the groups that the given ``identity`` belongs to.
                       every element is a group identifier and
                       :class:`~typing.Hashable`
        :type groups: :const:`~.team.GroupSet`

        """
        raise NotImplementedError('permit() method has to be implemented')


class DefaultPermissionPolicy(PermissionPolicy):
    """All remotes are listed and allowed for everyone in the team.

    .. versionadded:: 0.2.0

    """

    @typechecked
    def filter(self,
               remotes: RemoteSet,
               identity: Identity,
               groups: GroupSet) -> RemoteSet:
        return remotes

    @typechecked
    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: GroupSet) -> bool:
        return True


class GroupMetadataPermissionPolicy(PermissionPolicy):
    """Allow/disallow remotes according their metadata.  It assumes every
    remote has a metadata key that stores a set of groups to allow.
    For example, suppose there's the following remote set::

        {
            'web-1': Remote('ubuntu', '192.168.0.5', metadata={'role': 'web'}),
            'web-2': Remote('ubuntu', '192.168.0.6', metadata={'role': 'web'}),
            'web-3': Remote('ubuntu', '192.168.0.7', metadata={'role': 'web'}),
            'worker-1': Remote('ubuntu', '192.168.0.25',
                               metadata={'role': 'worker'}),
            'worker-2': Remote('ubuntu', '192.168.0.26',
                               metadata={'role': 'worker'}),
            'db-1': Remote('ubuntu', '192.168.0.50', metadata={'role': 'db'}),
            'db-2': Remote('ubuntu', '192.168.0.51', metadata={'role': 'db'})
        }

    and there are groups identified as ``'web'``, ``'worker'``, and ``'db'``.
    So the following policy would allow only members who belong to
    the corresponding groups:

        GroupMetadataPermissionPolicy('role')

    :param metadata_key: the key to find corresponding groups in metadata
                         of each remote
    :type metadata_key: :class:`str`
    :param separator: the character separates multiple group identifiers
                      in the metadata value.  for example, if the groups
                      are stored as like ``'sysadmin,owners'`` then
                      it should be ``','``.  it splits group identifiers
                      by all whitespace characters by default
    :type separator: :class:`str`

    .. versionadded:: 0.2.0

    """

    @typechecked
    def __init__(self, metadata_key: str, separator: str=None) -> None:
        self.metadata_key = metadata_key
        self.separator = separator

    def _get_groups(self, remote):
        groups = remote.metadata.get(self.metadata_key, '')
        if self.separator is None:
            groups = groups.split()
        else:
            groups = groups.split(self.separator)
        return frozenset(groups)

    @typechecked
    def filter(self,
               remotes: RemoteSet,
               identity: Identity,
               groups: GroupSet) -> RemoteSet:
        return {alias: remote
                for alias, remote in remotes.items()
                if self.permit(remote, identity, groups)}

    @typechecked
    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: GroupSet) -> bool:
        return not self._get_groups(remote).isdisjoint(groups)


class RemoteSetFilter(collections.abc.Mapping):
    """It takes a ``filter`` function and a ``remote_set``, and then
    return a filtered set of remotes.

    >>> remotes = {
    ...     'web-1': Remote('ubuntu', '192.168.0.5'),
    ...     'web-2': Remote('ubuntu', '192.168.0.6'),
    ...     'web-3': Remote('ubuntu', '192.168.0.7'),
    ...     'worker-1': Remote('ubuntu', '192.168.0.25'),
    ...     'worker-2': Remote('ubuntu', '192.168.0.26'),
    ...     'db-1': Remote('ubuntu', '192.168.0.50'),
    ...     'db-2': Remote('ubuntu', '192.168.0.51'),
    ... }
    >>> filtered = RemoteSetFilter(
    ...     lambda a, r: a == 'web' or r.host.endswith('5'),
    ...     remotes
    ... )
    >>> dict(filtered)
    {
        'web-1': Remote('ubuntu', '192.168.0.5'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.25')
    }

    The key difference of this and conditional dict comprehension is
    evaluation time.  (TL;DR: the contents of :class:`RemoteSetFilter`
    is evaluated everytime its filtered result is needed.)

    If ``remote_set`` is an ordinary :class:`dict` object,
    :class:`RemoteSetFilter` is not needed.  But if ``remote_set`` is,
    for example, :class:`~geofront.backends.cloud.CloudRemoteSet`,
    the filtered result of dict comprehension on it is fixed at Geofront's
    configuration loading time.  That means ``geofront-cli remotes`` doesn't
    change even if the list of remotes in the cloud is changed.

    On the other hand, the filtered result of :class:`RemoteSetFilter` is
    never fixed, because the filter on ``remote_set`` is always evaluated
    again when its :meth:`__iter__()`/:meth:`__getitem__`/etc are called.

    >>> remotes['web-4'] = Remote('ubuntu', '192.168.0.8')
    >>> del remotes['worker-1']
    >>> dict(filtered)
    {
        'web-1': Remote('ubuntu', '192.168.0.5'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'web-4': Remote('ubuntu', '192.168.0.25'),  # this replaced worker-1!
    }

    :param filter: a filter function which takes key (alias name) and
                   :class:`Remote`, and :const:`False` if exclude it,
                   or :const:`True` if include it
    :type filter: :class:`~typing.Callable`\ [[:class:`str`, :class:`Remote`],
                                              :class:`bool`]
    :param remote_set: a set of remotes.  it has to be a mapping of
                       alias name to :class:`Remote`
    :type remote_set: :class:`RemoteSet`

    .. versionadded:: 0.3.1

    """

    def __init__(self,
                 filter: Callable[[str, Remote], bool],
                 remote_set: RemoteSet) -> None:
        self.filter = filter
        self.remote_set = remote_set

    def __iter__(self) -> Iterator[str]:
        for alias, _ in self.items():
            yield alias

    def __getitem__(self, alias: str) -> Remote:
        remote = self.remote_set[alias]
        if self.filter(alias, remote):
            return remote
        raise KeyError(alias)

    def __len__(self) -> int:
        i = 0
        for _ in self.items():
            i += 1
        return i

    def iteritems(self) -> Iterable[Tuple[str, Remote]]:
        for alias, remote in self.remote_set.items():
            if self.filter(alias, remote):
                yield alias, remote

    def items(self) -> ItemsView[str, Remote]:
        return cast(ItemsView[str, Remote], list(self.iteritems()))

    def itervalues(self) -> Iterable[Remote]:
        for _, remote in self.items():
            yield remote

    def values(self) -> ValuesView[Remote]:
        return cast(ValuesView[Remote], list(self.itervalues()))


class RemoteSetUnion(collections.abc.Mapping):
    """It takes two or more remote sets, and then return a union set of them.
    Note that the order of arguments affect overriding of aliases (keys).
    If there are any duplicated aliases (keys), the latter alias (key) is
    prior to the former.

    >>> a = {
    ...     'web-1': Remote('ubuntu', '192.168.0.5'),
    ...     'web-2': Remote('ubuntu', '192.168.0.6'),
    ...     'web-3': Remote('ubuntu', '192.168.0.7'),
    ...     'worker-1': Remote('ubuntu', '192.168.0.8'),
    ... }
    >>> b = {
    ...     'worker-1': Remote('ubuntu', '192.168.0.25'),
    ...     'worker-2': Remote('ubuntu', '192.168.0.26'),
    ...     'db-1': Remote('ubuntu', '192.168.0.27'),
    ...     'db-2': Remote('ubuntu', '192.168.0.28'),
    ...     'db-3': Remote('ubuntu', '192.168.0.29'),
    ... }
    >>> c = {
    ...     'web-1': Remote('ubuntu', '192.168.0.49'),
    ...     'db-1': Remote('ubuntu', '192.168.0.50'),
    ...     'db-2': Remote('ubuntu', '192.168.0.51'),
    ... }
    >>> union = RemoteSetUnion(a, b, c)
    >>> dict(union)
    {
        'web-1': Remote('ubuntu', '192.168.0.49'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.25'),
        'worker-2': Remote('ubuntu', '192.168.0.26'),
        'db-1': Remote('ubuntu', '192.168.0.50'),
        'db-2': Remote('ubuntu', '192.168.0.51'),
        'db-3': Remote('ubuntu', '192.168.0.29'),
    }

    Note that :class:`RemoteSetUnion` is evaluated everytime its contents
    is needed, like :class:`RemoteSetFilter`:

    >>> del c['web-1']
    >>> dict(union)
    {
        'web-1': Remote('ubuntu', '192.168.0.5'),  # changed!
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.25'),
        'worker-2': Remote('ubuntu', '192.168.0.26'),
        'db-1': Remote('ubuntu', '192.168.0.50'),
        'db-2': Remote('ubuntu', '192.168.0.51'),
        'db-3': Remote('ubuntu', '192.168.0.29'),
    }

    :param \*remote_sets: two or more remote sets.  every remote set has to be
                          a mapping of alias :class:`str` to :class:`Remote`
    :type \*remote_sets: :class:`RemoteSet`

    .. versionadded:: 0.3.2

    """

    def __init__(self, *remote_sets) -> None:
        if len(remote_sets) < 2:
            raise TypeError('expected two or more arguments')
        for remote_set in remote_sets:
            if not isinstance(remote_set, collections.abc.Mapping):
                raise TypeError('expected mappings, not ' + repr(remote_set))
        self.remote_sets = remote_sets

    def __iter__(self) -> Iterator[str]:
        for alias, _ in self.items():
            yield alias

    def __len__(self) -> int:
        return len({a for remote_set in self.remote_sets for a in remote_set})

    def __getitem__(self, alias: str) -> Remote:
        for remote_set in reversed(self.remote_sets):
            try:
                return remote_set[alias]
            except KeyError:
                continue
        raise KeyError(alias)

    def iteritems(self) -> Iterable[Tuple[str, Remote]]:
        keys = set()  # type: Set[str]
        for remote_set in reversed(self.remote_sets):
            for alias, remote in remote_set.items():
                if alias in keys:
                    continue
                yield alias, remote
                keys.add(alias)

    def items(self) -> ItemsView[str, Remote]:
        return cast(ItemsView[str, Remote], list(self.iteritems()))

    def itervalues(self) -> Iterable[Remote]:
        for _, remote in self.items():
            yield remote

    def values(self) -> ValuesView[Remote]:
        return cast(ValuesView[Remote], list(self.itervalues()))
