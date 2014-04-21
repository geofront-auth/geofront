Geofront Changelog
==================

Version 0.1.1
-------------

To be released.

- Fixed :exc:`TypeError` that rises when :class:`CloudMasterKeyStore
  <geofront.masterkey.CloudMasterKeyStore>` is used with AWS S3 driver.
- Added :option:`--trusted-proxy <geofront-server --trusted-proxy>` option
  to :program:`goefront-server` command.  It's useful when the server is
  run behind a reverse proxy.
- Added token no-op API: :http:get:`/tokens/(token_id:token_id)/`.


Version 0.1.0
-------------

First alpha release.  Released on April 21, 2014.
