""":mod:`geofront.remote` --- Remote sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every remote set is represented as a mapping (which is immutable, or mutable)
of alias :class:`str` to :class:`Remote` object e.g.::

    {
        'web-1': Remote('ubuntu', '192.168.0.5'),
        'web-2': Remote('ubuntu', '192.168.0.6'),
        'web-3': Remote('ubuntu', '192.168.0.7'),
        'worker-1': Remote('ubuntu', '192.168.0.25'),
        'worker-2': Remote('ubuntu', '192.168.0.26'),
        'db-1': Remote('ubuntu', '192.168.0.50'),
        'db-2': Remote('ubuntu', '192.168.0.51')
    }

However, in the age of the cloud, you don't have to manage the remote set
since the most of cloud providers offer their API to list provisioned
remote nodes.

Geofront provides builtin :class:`~.backends.cloud.CloudRemoteSet`,
a subtype of :class:`collections.abc.Mapping`, that proxies to the list
dynamically made by cloud providers.

.. versionchanged:: group
   ``CloudRemoteSet`` is moved from this module to
   :mod:`geofront.backends.cloud`.
   See :class:`~.backends.cloud.CloudRemoteSet`.

"""
import collections.abc
import datetime
import io
import itertools
import numbers
import threading
import time

from paramiko.pkey import PKey
from paramiko.sftp_client import SFTPClient
from paramiko.transport import Transport
from geofront.identity import Identity

from .keystore import format_openssh_pubkey, parse_openssh_pubkey
from .util import typed

__all__ = ('AuthorizedKeyList', 'DefaultPermissionPolicy',
           'GroupMetadataPermissionPolicy', 'PermissionPolicy', 'Remote',
           'authorize')


class Remote:
    """Remote node to SSH.

    :param user: the username to :program:`ssh`
    :type user: :class:`str`
    :param host: the host to access
    :type host: :class:`str`
    :param port: the port number to :program:`ssh`.
                 the default is 22 which is the default :program:`ssh` port
    :type port: :class:`numbers.Integral`
    :param metadata: optional metadata mapping.  keys and values have to
                     be all strings.  empty by default
    :type metadata: :class:`collections.abc.Mapping`

    .. versionchanged:: group
       Added optional ``metadata`` parameter.

    """

    #: (:class:`str`) The username to SSH.
    user = None

    #: (:class:`Address`) The hostname to access.
    host = None

    #: (:class:`numbers.Integral`) The port number to SSH.
    port = None

    #: (:class:`collections.abc.Mapping`) The additional metadata.
    #: Note that it won't affect to :func:`hash()` of the object,
    #: nor :token:`==`/:token:`!=` comparison of the object.
    #:
    #: .. versionadded:: group
    metadata = None

    @typed
    def __init__(self, user: str, host: str, port: numbers.Integral=22,
                 metadata: collections.abc.Mapping={}):
        self.user = user
        self.host = host
        self.port = port
        self.metadata = dict(metadata)

    def __eq__(self, other):
        return (isinstance(other, type(self)) and
                self.user == other.user and
                self.host == other.host and
                self.port == other.port)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.user, self.host, self.port))

    def __str__(self):  # pragma: no cover
        return '{}@{}:{}'.format(self.user, self.host, self.port)

    def __repr__(self):
        return '{0.__module__}.{0.__qualname__}{1!r}'.format(
            type(self), (self.user, self.host, self.port, self.metadata)
        )


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

    @typed
    def __init__(self, sftp_client: SFTPClient):
        self.sftp_client = sftp_client

    def _iterate_lines(self):
        with io.BytesIO() as fo:
            self.sftp_client.getfo(self.FILE_PATH, fo)
            fo.seek(0)
            for line in fo:
                line = line.decode().strip()
                if line:
                    yield line

    def _save(self, authorized_keys: str):
        with io.BytesIO(authorized_keys.encode()) as fo:
            self.sftp_client.putfo(fo, self.FILE_PATH)

    def __iter__(self):
        for line in self._iterate_lines():
            line = line.strip()
            if line:
                yield parse_openssh_pubkey(line)

    def __len__(self):
        i = 0
        for _ in self._iterate_lines():
            i += 1
        return i

    def __getitem__(self, index):
        if isinstance(index, slice):
            lines = list(self._iterate_lines())
            return list(map(parse_openssh_pubkey, lines[index]))
        elif isinstance(index, numbers.Integral):
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

    def __setitem__(self, index, value):
        lines = list(self._iterate_lines())
        if isinstance(index, slice):
            lines[index] = map(format_openssh_pubkey, value)
        elif isinstance(index, numbers.Integral):
            lines[index] = format_openssh_pubkey(value)
        else:
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        self._save('\n'.join(lines))

    def insert(self, index, value):
        if not isinstance(index, numbers.Integral):
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        lines = list(self._iterate_lines())
        lines.insert(index, format_openssh_pubkey(value))
        self._save('\n'.join(lines))

    def extend(self, values):
        lines = itertools.chain(
            self._iterate_lines(),
            map(format_openssh_pubkey, values)
        )
        self._save('\n'.join(lines))

    def __delitem__(self, index):
        if not isinstance(index, (numbers.Integral, slice)):
            raise TypeError(
                'authorized_keys indices must be integers, not '
                '{0.__module__}.{0.__qualname__}'.format(type(index))
            )
        lines = list(self._iterate_lines())
        del lines[index]
        self._save('\n'.join(lines))


@typed
def authorize(public_keys: collections.abc.Set,
              master_key: PKey,
              remote: Remote,
              timeout: datetime.timedelta) -> datetime.datetime:
    """Make an one-time authorization to the ``remote``, and then revokes
    it when ``timeout`` reaches soon.

    :param public_keys: the set of public keys (:class:`paramiko.pkey.PKey`)
                        to authorize
    :type public_keys: :class:`collections.abc.Set`
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

    .. versionadded:: group

    """

    @typed
    def filter(self,
               remotes: collections.abc.Mapping,
               identity: Identity,
               groups: collections.abc.Set) -> collections.abc.Mapping:
        """Determine which ones in the given ``remotes`` are visible
        to the ``identity`` (which belongs to ``groups``).  The resulted
        mapping of filtered remotes has to be a subset of the input
        ``remotes``.

        :param remotes: the remotes set to filter.  keys are alias strings
                        and values are :class:`Remote` objects
        :type remotes: :class:`collections.abc.Mapping`
        :param identity: the identity that the filtered remotes would
                         be visible to
        :type identity: :class:`~.identity.Identity`
        :param groups: the groups that the given ``identity`` belongs to.
                       every element is a group identifier and
                       :class:`collections.abc.Hashable`
        :type groups: :class:`collections.abc.Set`

        """
        raise NotImplementedError('filter() method has to be implemented')

    @typed
    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: collections.abc.Set) -> bool:
        """Determine whether to allow the given ``identity`` (which belongs
        to ``groups``) to SSH the given ``remote``.

        :param remote: the remote to determine
        :type remote: :class:`Remote`
        :param identity: the identity to determine
        :type identity: :class:`~.identity.Identity`
        :param groups: the groups that the given ``identity`` belongs to.
                       every element is a group identifier and
                       :class:`collections.abc.Hashable`
        :type groups: :class:`collections.abc.Set`

        """
        raise NotImplementedError('permit() method has to be implemented')


class DefaultPermissionPolicy(PermissionPolicy):
    """All remotes are listed and allowed for everyone in the team.

    .. versionadded:: group

    """

    @typed
    def filter(self,
               remotes: collections.abc.Mapping,
               identity: Identity,
               groups: collections.abc.Set) -> collections.abc.Mapping:
        return remotes

    @typed
    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: collections.abc.Set) -> bool:
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

    .. versionadded:: group

    """

    @typed
    def __init__(self, metadata_key: str, separator: str=None):
        self.metadata_key = metadata_key
        self.separator = separator

    def _get_groups(self, remote):
        groups = remote.metadata.get(self.metadata_key, '')
        if self.separator is None:
            groups = groups.split()
        else:
            groups = groups.split(self.separator)
        return frozenset(groups)

    @typed
    def filter(self,
               remotes: collections.abc.Mapping,
               identity: Identity,
               groups: collections.abc.Set) -> collections.abc.Mapping:
        return {alias: remote
                for alias, remote in remotes.items()
                if self.permit(remote, identity, groups)}

    @typed
    def permit(self,
               remote: Remote,
               identity: Identity,
               groups: collections.abc.Set) -> bool:
        return not self._get_groups(remote).isdisjoint(groups)
