Installation
============

.. note::

   We recommend to :doc:`setup Geofront using Docker <docker>`
   since it is easier and requires no prerequisites but Docker_.

   .. _Docker: https://www.docker.com/

You can easily install Geofront server using pip:

.. code-block:: console

   $ pip3 install Geofront


Running server
--------------

.. currentmodule:: config

Geofront server requires a configuration file.  Configuration file is a typical
Python script.  The server is sensitive to the values of some uppercase
variables like :data:`TEAM`, :data:`KEY_STORE`, and :data:`MASTER_KEY_BITS`.
The filename of the configuration is not important, but recommend to use
:file:`.cfg.py` suffix.  You also can find an example configuration in
the Geofront repository: :file:`example.cfg.py`.

.. seealso::

   :doc:`config`
      The reference manual for Geofront server configuration.

If a configuration file is ready you can run the server right now.  Suppose
the configuration file is :file:`geofront.cfg.py`.

:program:`geofront-server` command provides several options like
:option:`--host <geofront-server --host>`, and requires a configuration
filename as its argument.

.. code-block:: console

   $ geofront-server -p 8080 geofront.cfg.py

It might be terminated with the following error message:

.. code-block:: console

   $ geofront-server -p 8080 geofront.cfg.py
   usage: geofront-server [...] FILE
   geofront-server: error: no master key;
   try --create-master-key option if you want to create one

It means :data:`MASTER_KEY_STORE` you configured has no master key yet.
:option:`--create-master-key <geofront-server --create-master-key>` option
creates a new master key if there's no master key yet, and then stores it into
the configured :data:`MASTER_KEY_STORE`.

.. code-block:: console

   $ geofront-server -p 8080 --create-master-key geofront.cfg.py
   no master key;  create one...
   created new master key: 2b:d5:64:fd:27:f9:7a:6a:12:7d:88:76:a7:54:bd:6a
   serving on http://0.0.0.0:8080

If it successfully starts serving it will show you the bound host and port.


Reverse proxy
-------------

Application servers typically run behind the reverse proxy like Nginx_.
Here's an example configuration for Geofront server behind Nginx reverse proxy:

.. code-block:: nginx

   # Redirect all HTTP requests to HTTPS.
   # We highly recommend to expose Geofront server only through HTTPS.
   server {
     listen 80;
     server_name geofront-example.org;
     rewrite ^(.*)$ https://geofront-example.org$1;
   }

   # Forward all requests to https://geofront-example.org to internal
   # http://127.0.0.1:8080.
   server {
     listen 443 ssl;
     server_name geofront-example.org;
     access_log  /var/log/nginx/geofront/access.log;
     error_log /var/log/nginx/geofront/error.log;

     ssl on;
     ssl_certificate /path/to/ssl_cert_chain.pem;
     ssl_certificate_key /path/to/ssl_cert.pem;

     # HSTS: https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
     add_header Strict-Transport-Security "max-age=31536000";

     location / {
         proxy_pass http://127.0.0.1:8080;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     }
   }

.. _Nginx: http://nginx.org/


Using :program:`geofront-cli`
-----------------------------

Every team member who want to use Geofront has to install a client for Geofront.
`geofront-cli`_ is the reference implementation of Geofront client.
It can be installed using :program:`pip`:

.. code-block:: console

   $ pip install geofront-cli

To setup what Geofront server to use use :program:`geofront-cli start` command.
It will show a prompt:

.. code-block:: console

   $ geofront-cli start
   Geofront server URL:

Type the server URL, and then it will open an authentication page in your
default web browser:

.. code-block:: console

   $ geofront-cli start
   Geofront server URL: https://geofront-example.org/
   Continue to authenticate in your web browser...
   Press return to continue

That's done.  Setup process is only required at first.  You can show the list
of available remotes using :program:`geofront-cli remotes`:

.. code-block:: console

   $ geofront-cli remotes
   web-1
   web-2
   ...

For more details on :program:`geofront-cli`, read the manual of its
:file:`README.rst`, or use :option:`geofront-cli --help` option.

.. _geofront-cli: https://github.com/spoqa/geofront-cli


Remote colonization
-------------------

Until a remote server authorizes the master key you can't access to the remote
using :program:`geofront-cli`.  So the master key needs to be added to remote's
:file:`authorized_keys` list.  Geofront calls it *colonization*.  You can
colonize a remote using :program:`geofront-cli colonize` command.  Surely
the following command has to be run by who can access to it:

.. code-block:: console

   $ geofront-cli remotes
   web-1
   web-2
   ...
   $ geofront-cli colonize web-1

You can understand :program:`geofront-cli colonize` is :program:`ssh-copy-id`
for Geofront.  Once colonized remote is accessible by every team member
unless you configured more fine-grained ACL.
(See also :data:`~config.PERMISSION_POLICY` if you're interested in ACL.)


SSH through Geofront
--------------------

If a remote is once colonized any team member can :program:`ssh` to it through
Geofront.  Use :program:`geofront-cli ssh` command:

.. code-block:: console

   $ geofront-cli ssh web-1
   Last login: Sat May  3 16:32:15 2014 from hong-minhees-macbook-pro.local
   $
