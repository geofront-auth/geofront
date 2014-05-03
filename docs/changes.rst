Geofront Changelog
==================

Version 0.2.0
-------------

Released on May 3, 2014.

- Added :meth:`~geofront.team.Team.list_groups()` method to
  :class:`~geofront.team.Team` interface.
- Added :meth:`~geofront.backends.github.GitHubOrganization.list_groups()`
  method to :class:`~geofront.backends.github.GitHubOrganization` class.
- Removed an unnecessary dependency to enum34_ on Python 3.3.
- Added :mod:`geofront.backends.cloud` module.

  - ``geofront.masterkey.CloudMasterKeyStore`` is moved to
    :class:`geofront.backends.cloud.CloudMasterKeyStore`.
  - ``geofront.remote.CloudRemoteSet`` is moved to
    :class:`geofront.backends.cloud.CloudRemoteSet`.

- :class:`~geofront.remote.Remote` now has
  :attr:`~geofront.remote.Remote.metadata` attribute.
- :class:`~geofront.backends.cloud.CloudRemoteSet` fills
  :attr:`~geofront.remote.Remote.metadata` of the resulted
  :class:`~geofront.remote.Remote` objects if the given driver supports.
- Now depends on singledispatch_ if Python is older than 3.4.
- Added :class:`~geofront.remote.PermissionPolicy` interface.
- Added :class:`~geofront.remote.DefaultPermissionPolicy` class.
- Added :class:`~geofront.remote.GroupMetadataPermissionPolicity` class.
- Added new ``PERMISSION_POLICY`` configuration.
- Added :mod:`geofront.backends.dbapi` module.
- Added :program:`geofront-key-regen` command.
- HTTP APIs became more RESTful.  Now it has the root endpoint which provides
  the link to create a new token, and the token API provides several
  links to subresources as well.
- Added new ``MASTER_KEY_BITS`` configuration.
- Added new ``bits`` optional parameters to :func:`renew_master_key()
  <geofront.masterkey.renew_master_key>`, :class:`PeriodicalRenewal
  <geofront.masterkey.PeriodicalRenewal>`, and :func:`regenerate()
  <geofront.regen.regenerate>`.
- Added :class:`~geofront.backends.cloud.CloudKeyStore`.  [:issue:`2`]
- Added :class:`~geofront.backends.cloud.CloudMasterPublicKeyStore`.
  [:issue:`2`]

.. _enum34: https://pypi.python.org/pypi/enum34
.. _singledispatch: https://pypi.python.org/pypi/singledispatch


Version 0.1.1
-------------

Released on April 22, 2014.

- Fixed :exc:`TypeError` that rises when :class:`CloudMasterKeyStore
  <geofront.backends.cloud.CloudMasterKeyStore>` is used with AWS S3 driver.
- Added :option:`--trusted-proxy <geofront-server --trusted-proxy>` option
  to :program:`geofront-server` command.  It's useful when the server is
  run behind a reverse proxy.
- Added token no-op API: :http:get:`/tokens/(token_id:token_id)/`.


Version 0.1.0
-------------

First alpha release.  Released on April 21, 2014.
