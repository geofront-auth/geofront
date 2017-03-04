""":mod:`geofront.backends.bitbucket` --- Bitbucket Cloud team
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 0.4.0

Provides team implementation for `Bitbucket Cloud`_
(which is also known as simply Bitbucket).

In order to use Bitbucket's API you need to add an OAuth consumer.
You can find the form from :menuselection:`Bitbucket settings -->
Access Management --> OAuth --> OAuth consumers --> Add consumer`.
OAuth consumer has to be set like the following:

:guilabel:`Callback`
   It has to be the root url of the Geofront server.

:guilabel:`Permissions`
   The following permissions are required:

   :guilabel:`Account`
      :guilabel:`Read`.

      It's used for identifying the authenticated Bitbucket user.

   :guilabel:`Team membership`
      :guilabel:`Read`.

      It's used for determining whether the authenticated Bitbucket user
      belongs to the Bitbucket team.

   Other than the above are unnecessary.

.. note::

   Not to be confused with `Bitbucket Server`_ (which was Stash).
   For Bitbucket Server, use :mod:`geofront.backend.stash` module instead.

.. note::

   Unfortunately, Atlassian deprecated the existing SSH keys endpoint
   from their HTTP RESTful API.  Unlike :mod:`geofront.backends.github` or
   :mod:`geofront.backends.stash`, Bitbucket Cloud cannot be used for
   storing/loading public keys, but can be used only for authentication and
   authorization.  You need to use other key store implementations instead
   e.g. :class:`~.cloud.CloudKeyStore` or :class:`~.dbapi.DatabaseKeyStore`.

.. _Bitbucket Server: https://bitbucket.org/product/server
.. _Bitbucket Cloud: https://bitbucket.org/

"""
import collections.abc
import logging

from typeguard import typechecked

from ..identity import Identity
from .oauth import OAuth2Team, request

__all__ = 'BitbucketTeam',


class BitbucketTeam(OAuth2Team):
    """Authenticate team membership through Bitbucket Cloud,
    and authorize to access Bitbucket Cloud key store.

    Note that group identifiers :meth:`list_groups()` method returns
    are Bitbucket team group *slugs*.  You can find the list of your available
    group slugs in the team using Bitbucket API:

    .. code-block:: console

       $ curl -u YourUsername \
https://api.bitbucket.org/1.0/groups/YourTeamUsername/
       [
           {
               "name": "Administrators",
               "permission": "read",
               "auto_add": false,
               "slug": "administrators",
               ...
           },
           {
               "name": "Developers",
               "permission": "read",
               "auto_add": false,
               "slug": "developers",
               ...
           },
       ]

    :param consumer_key: bitbucket oauth consumer key
    :type consumer_key: :class:`str`
    :param consumer_secret: bitbucket oauth consumer secret
    :type consumer_secret: :class:`str`
    :param team_username: bitbucket team account name.  for example ``'spoqa'``
                          in https://bitbucket.org/spoqa
    :type team_username: :class:`str`

    """

    authorize_url = 'https://bitbucket.org/site/oauth2/authorize'
    authorize_scope = 'account:write team'
    access_token_url = 'https://bitbucket.org/site/oauth2/access_token'
    user_url = 'https://api.bitbucket.org/2.0/user'
    teams_list_url = 'https://api.bitbucket.org/2.0/teams?role=member'
    groups_list_url = \
        'https://api.bitbucket.org/1.0/groups/{team.team_username}'
    unauthorized_identity_message_format = (
        '@{identity.identifier} user is not a member of '
        '@{team.team_username} team'
    )

    @typechecked
    def __init__(self,
                 consumer_key: str,
                 consumer_secret: str,
                 team_username: str) -> None:
        super().__init__(consumer_key, consumer_secret)
        self.team_username = team_username.lower()

    def determine_identity(self, access_token: str) -> Identity:
        user_data = request(access_token, self.user_url)
        return Identity(type(self), user_data['username'], access_token)

    def authorize(self, identity: Identity) -> bool:
        logger = logging.getLogger(__name__ + '.BitbucketTeam.authorize')
        if not issubclass(identity.team_type, type(self)):
            return False
        url = self.teams_list_url
        while url:
            logger.debug('requesting %s...', url)
            try:
                response = request(identity, url)
            except IOError as e:
                logger.debug(str(e), exc_info=True)
                return False
            if isinstance(response, collections.abc.Mapping) and \
               'error' in response:
                logger.debug('error response: %r', response)
                return False
            logger.debug('successful response: %r', response)
            for team in response['values']:
                if team['username'].lower() == self.team_username:
                    return True
            url = response.get('next')
        return False

    def list_groups(self, identity: Identity):
        if not issubclass(identity.team_type, type(self)):
            return frozenset()
        list_url = self.groups_list_url.format(team=self)
        try:
            response = request(identity, list_url)
        except IOError:
            return frozenset()
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return frozenset()
        return frozenset(t['slug'] for t in response)
