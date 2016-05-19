""":mod:`geofront.team` --- Team authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Geofront doesn't force you to manage team members by yourself.
Instead it hides how to manage team members, and offers :class:`Team`,
the layering interface to implement custom team data provider
e.g. :class:`~.backends.github.GitHubOrganization`.

It is theologically possible to implement a straightforward RDBMS-backed
team provider, but we rather recommend to adapt your existing team data
instead e.g. `GitHub organization`__, `Google Apps organization`__,
`Bitbucket team`__.

__ https://github.com/blog/674-introducing-organizations
__ https://support.google.com/a/answer/182433?hl=en
__ http://blog.bitbucket.org/2012/05/30/bitbucket-teams/

"""
import collections.abc
import typing

from tsukkomi.typed import typechecked

from .identity import Identity

__all__ = 'AuthenticationContinuation', 'AuthenticationError', 'Team'


class AuthenticationContinuation:
    """The contunuation value for the process between
    :meth:`Team.request_authentication()` and :meth:`Team.authenticate()`.

    It is created by :meth:`Team.request_authentication()` method,
    and holds following two attributes:

    .. attribute:: next_url

       (:class:`str`) The url to direct the authenticator to.

    .. attribute:: state

       The arbitrary value to be passed to :meth:`Team.authenticate()`
       method's ``state`` parameter.

       It can be used for passing arbitrary nonce, or request token, etc.

       It has to be possible to pickle.

    .. versionadded:: 0.3.0

    """

    @typechecked
    def __init__(self, next_url: str, state):
        self.next_url = next_url
        self.state = state

    def __repr__(self):
        return '{0.__module__}.{0.__qualname__}({1!r}, {2!r})'.format(
            type(self), self.next_url, self.state
        )


class Team:
    """Backend interface for team membership authentication.

    Authorization process consists of three steps (and therefore every
    backend subclass has to implement these three methods):

    1. :meth:`request_authentication()` makes the url to interact with
       the owner of the identity to authenticate.  I.e. the url to login
       web page of the backend service.
    2. :meth:`authenticate()` finalize authentication of the identity,
       and then returns :class:`~.identity.Identity`.
    3. :meth:`authorize()` tests the given :class:`~.identity.Identity`
       belongs to the team.  It might be a redundant step for several
       backends, but is a necessary step for some backends that distinguish
       identity authentication between team membership authorization.
       For example, Any Gmail users can authenticate they own their Gmail
       account, but only particular users can authenticate their account
       belongs to the configured Google Apps organization.

    """

    @typechecked
    def request_authentication(
        self, redirect_url: str
    ) -> AuthenticationContinuation:
        """First step of authentication process, to prepare the "sign in"
        interaction with the owner.  It typically returns a url to
        the login web page.

        :param redirect_url: a url that owner's browser has to redirect to
                             after the "sign in" interaction finishes
        :type redirect_url: :class:`str`
        :return: a url to the web page to interact with the owner
                 in their browser
        :rtype: :class:`AuthenticationContinuation`

        .. versionchanged:: 0.3.0
           The ``auth_nonce`` parameter was removed.  Instead, it became to
           return :class:`AuthenticationContinuation` value so that share
           state more general than simple ``auth_nonce`` between
           :meth:`request_authentication()` and :meth:`authenticate()`.
           If arbitrary nonce is needed, :meth:`request_authentication()`
           method has to generate one by itself.

        """
        raise NotImplementedError('request_authentication() method has to '
                                  'be implemented')

    @typechecked
    def authenticate(
        self,
        state,
        requested_redirect_url: str,
        wsgi_environ: typing.Mapping[str, typing.Any]
    ) -> Identity:
        """Second step of authentication process, to create a verification
        token for the identity.  The token is used by :meth:`authorize()`
        method, and the key store as well (if available).

        :param state: :attr:`AuthenticationContinuation.state` vaule
                      returned by :meth:`request_authentication()` method
        :param requested_redirect_url: a url that was passed to
                                       :meth:`request_authentication()`'s
                                       ``redirect_url`` parameter
        :type requested_redirect_url: :class:`str`
        :param wsgi_environ: forwarded wsgi environ dictionary
        :type wsgi_environ: :class:`typing.Mapping`[:class:`str`,
                                                    :class:`typing.Any`]
        :return: an identity which contains a verification token
        :rtype: :class:`~.identity.Identity`
        :raise geofront.team.AuthenticationError:
            when something goes wrong e.g. network errors,
            the user failed to verify their ownership

        .. versionchanged:: 0.3.0
           The ``auth_nonce`` parameter was replaced by more general ``state``
           parameter.  The new parameter has no longer type constraints
           so that it can be any value even if it's not a :class:`str`.

        """
        raise NotImplementedError('authenticate() method has to '
                                  'be implemented')

    @typechecked
    def authorize(self, identity: Identity) -> bool:
        """The last step of authentication process.
        Test whether the given ``identity`` belongs to the team.

        Note that it can be called every time the owner communicates with
        Geofront server, out of authentication process.

        :param identity: the identity to authorize
        :type identity: :class:`~.identity.Identity`
        :return: :const:`True` only if the ``identity`` is a member of the team
        :rtype: :class:`bool`

        """
        raise NotImplementedError('authorize() method has to be implemented')

    @typechecked
    def list_groups(
        self, identity: Identity
    ) -> typing.AbstractSet[collections.abc.Hashable]:
        """List the all groups that the given ``identity`` belongs to.
        Any hashable value can be an element to represent a group e.g.::

            {1, 4, 9}

        Or::

            {'owners', 'programmers'}

        Whatever value the set consists of these would be referred by
        :class:`~.remote.Remote` objects.

        Some team implementations might not have a concept like groups.
        It's okay to return always an empty set then.

        :param identity: the identity to list his/her groups
        :type identity: :class:`~.identity.Identity`
        :return: the set of groups associated with the ``identity``
        :rtype: :class:`collections.abc.Set`

        .. versionadded:: 0.2.0

        """
        raise NotImplementedError('list_groups() method has to be implemented')


class AuthenticationError(Exception):
    """Authentication exception which rise when the authentication process
    has trouble including network problems.

    .. todo:: Exception hierarchy is needed.

    """
