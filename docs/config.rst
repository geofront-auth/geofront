Configuration
=============

The :program:`geofront-server` command takes a configuration file as required
argument.  The configuration is an ordinary Python script that defines
the following required and optional variables.  Note that all names have to
be uppercase.

.. data:: TEAM

   (:class:`geofront.team.Team`) The backend implementation for team
   authentication.  For example, in order to authorize members of GitHub
   organization use :class:`~geofront.backends.github.GitHubOrganization`
   implementation::

       from geofront.backends.github import GitHubOrganization

       TEAM = GitHubOrganization(
           client_id='GitHub OAuth app client id goes here',
           client_secret='GitHub OAuth app client secret goes here',
           org_login='your_org_name'  #  in https://github.com/your_org_name
       )

   Or you can implement your own backend by subclassing
   :class:`~geofront.team.Team`.

   .. seealso::

      Module :mod:`geofront.team` --- Team authentication
         The interface for team authentication.

      Class :class:`geofront.backends.github.GitHubOrganization`
         The :class:`~geofront.team.Team` implementation for GitHub
         organizations.

.. data:: REMOTE_SET

   (:class:`collections.abc.Mapping`) The set of remote servers to be managed
   by Geofront.  It can be anything only if it's an mapping object.
   For example, you can hard-code it by using Python :class:`dict` data
   structure::

       from geofront.remote import Remote
       from ipaddress import ip_address

       REMOTE_SET = {
           'web-1': Remote('ubuntu', ip_address('192.168.0.5')),
           'web-2': Remote('ubuntu', ip_address('192.168.0.6')),
           'web-3': Remote('ubuntu', ip_address('192.168.0.7')),
           'worker-1': Remote('ubuntu', ip_address('192.168.0.25')),
           'worker-2': Remote('ubuntu', ip_address('192.168.0.26')),
           'db-1': Remote('ubuntu', ip_address('192.168.0.50')),
           'db-2': Remote('ubuntu', ip_address('192.168.0.51'))
       }

   Every key has to be a string, and every valye has to be an instance of
   :class:`~geofront.remote.Remote`.  :class:`~geofront.remote.Remote` consits
   of an user, an address (which is already resolved), and the port to
   SSH.  For example, if you've :program:`ssh`-ed to a remote server by
   the following command:

   .. code-block:: console

      $ ssh -p 2222 ubuntu@192.168.0.50

   A :class:`~geofront.remote.Remote` object for it should be::

       Remote('ubuntu', ip_address('192.168.0.50'), 2222)

   You can add more dynamism by providing custom :class:`dict`-like mapping
   object.  :class:`collections.abc.Mapping` could help to implement it.
   For example, :class:`~geofront.remote.CloudRemoteSet` is a subtype of
   :class:`~collections.abc.Mapping`, and it dynamically loads the list
   of available instance nodes in the cloud e.g. EC2_ of AWS_.  Due to
   Apache Libcloud_ it can work with more than 20 cloud providers like
   AWS_, Azure_, or Rackspace_.  ::


       from geofront.remote import CloudRemoteSet
       from libcloud.compute.types import Provider
       from libcloud.compute.providers import get_driver

       driver_cls = get_driver(Provider.EC2_US_WEST)
       driver = driver_cls('access id', 'secret key')
       REMOTE_SET = CloudRemoteSet(driver)

   .. seealso::

      Class :class:`geofront.remote.Remote`
         Value type that represents a remote server to :program:`ssh`.

      Class :class:`geofront.remote.CloudRemoteSet`
         The Libcloud_-backed dynamic remote set.

      Module :mod:`collections.abc` --- Abstract Base Classes for Containers
         This module provides abstract base classes that can be used to
         test whether a class provides a particular interface; for
         example, whether it is hashable or whether it is a mapping.

   .. _EC2: http://aws.amazon.com/ec2/
   .. _AWS: http://aws.amazon.com/
   .. _Libcloud: https://libcloud.apache.org/
   .. _Azure: http://azure.microsoft.com/
   .. _Rackspace: http://www.rackspace.com/

.. data:: TOKEN_STORE

   (:class:`werkzeug.contrib.cache.BaseCache`) The store to save access tokens.
   It uses Werkzeug's cache interface, and Werkzeug provides several
   built-in implementations as well e.g.:

   - :class:`~werkzeug.contrib.cache.MemcachedCache`
   - :class:`~werkzeug.contrib.cache.RedisCache`
   - :class:`~werkzeug.contrib.cache.FileSystemCache`

   For example, in order to store access tokens into Redis::

       from werkzeug.contrib.cache import RedisCache

       TOKEN_STORE = RedisCache(host='localhost', db=0)

   Of course you can implement your own backend by subclassing
   :class:`~werkzeug.contrib.cache.BaseCache`.

   Although it's a required configuration, but when :option:`-d
   <geofront-server -d>`/:option:`--debug <geofront-server --debug>` is
   enabled, :class:`~werkzeug.contrib.cache.SimpleCache` (which is all expired
   after :program:`geofront-server` process terminated) is used by default.

   .. seealso::

      Cache__ --- Werkzeug
         Cache backend interface and implementations provided by Werkzeug.

      __ http://werkzeug.pocoo.org/docs/contrib/cache/

.. data:: KEY_STORE

   (:class:`geofront.keystore.KeyStore`) The store to save *public keys*
   for each team member.  (Not the *master key*; don't be confused with
   :data:`MASTER_KEY_STORE`.)

   If :data:`TEAM` is a :class:`~geofront.backends.github.GitHubOrganization`
   object, :data:`KEY_STORE` also can be
   :class:`~geofront.backends.github.GitHubKeyStore`.  It's an adapter class
   of GitHub's per-account public key list.  ::

       from geofront.backends.github import GitHubKeyStore

       KEY_STORE = GitHubKeyStore()

.. data:: MASTER_KEY_STORE

   (:class:`geofront.masterkey.MasterKeyStore`)  The store to save
   the *master key*.  (Not *public keys*; don't be confused with
   :data:`KEY_STORE`.)

   The master key store should be secure, and hard to lose the key at the
   same time.  Geofront provides some built-in implementations:

   :class:`~geofront.masterkey.FileSystemMasterKeyStore`
      It stores the master key into the file system as the name suggests.
      You can set the path to save the key.  Although it's not that secure,
      but it might help you to try out Geofront.

   :class:`~geofront.masterkey.CloudMasterKeyStore`
      It stores the master key into the cloud object storage like S3_ of AWS_.
      It supports more than 20 cloud providers through the efforts of Libcloud_.

   ::

       from geofront.masterkey import FileSystemMasterKeyStore

       MASTER_KEY_STORE = FilesystemMasterKeyStore('/var/lib/geofront/id_rsa')

   .. _S3: http://aws.amazon.com/s3/
