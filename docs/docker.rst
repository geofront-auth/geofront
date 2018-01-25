Installation using Docker
=========================

.. image:: https://img.shields.io/docker/build/spoqa/geofront.svg
   :target: https://hub.docker.com/r/spoqa/geofront/
   :alt: Docker automated build

Geofront provides the official Docker image based on Alpine Linux.  The
official repository is `spoqa/geofront`__:

.. code-block:: text

   docker pull spoqa/geofront:stable

__ https://hub.docker.com/r/spoqa/geofront/


Images
------

Tags
~~~~

There are rules for tags:

``spoqa/geofront:latest``
   It is the bleeding edge image.  Follows the latest ``master`` branch
   of Geofront.

``spoqa/geofront:stable``
   It is the latest release image.

``spoqa/geofront:*.*.*``
   It is the immutable tag for the specific version.

``spoqa/geofront:*.*``
   It is the latest minor release image.  For example, if there are ``1.0.0``,
   ``1.0.1``, ``1.0.2``, ``1.1.0``, ``1.1.1``, and ``2.0.0`` verions,
   ``spoqa/geofront:1.0`` is equivalent to ``spoqa/geofront:1.0.2``.


Exposed port: ``8080``
~~~~~~~~~~~~~~~~~~~~~~

Since Geofront server works as a HTTP server, the official image also exposes
the port number **8080** to listen.  You can map the port using
:program:`docker run` command's :option:`-p`/:option:`--publish` option.


Additional backend dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The base ``spoqa/geofront`` Docker images provide only the core modules.
To use additional backend dependencies, such as :mod:`redis` or
:mod:`pyscopg2`, you need to build your own image.

First, create a Dockerfile that extends from one of the official images.
Then, add additional package installation commands, such as ``RUN pip3 install
<your-own-deps>`` for pure Python packages, while it is recommended to search
`the Alpine Linux package repository <http://pkgs.alpinelinux.org/>`_ for
Python packages with compiled binaries and install them by ``RUN apk add
--no-cache <alpine-pkg-name>``.  Most binary Python packages in Alpine Linux
has the naming style of ``py3-xxx``.

Example:

.. code-block:: docker

   FROM spoqa/geofront:stable
   RUN pip3 install redis
   RUN apk add --no-cache py3-psycopg2


.. _docker-config:

Configuration
-------------

There are two ways to configure Geofront.  The first one, a simple-but-limited
way, is to pass configuration values through :ref:`docker-env-vars`.
The other one, a complex-but-advanced way, is to :ref:`pass a whole
configuration file <docker-config-file>` through data volumes.


.. _docker-env-vars:

Environment variables
~~~~~~~~~~~~~~~~~~~~~

The official Geofront image takes environment variables of the same name to
:doc:`its own configuration fields <config>` (e.g. ``TEAM``, ``REMOTE_SET``).
For example, the following environment variable configure a Geofront to use
GitHub as its team authentication backend:

.. code-block:: bash

   TEAM='geofront.backends.github:GitHubOrganization(client_id="...", client_secret="...", org_login="your_org_name")'

As you can guess, it has its own mini-language and the language contains some
Python syntax.  This language consists of two part: a module path and an
expression separated by a colon.  In the above, ``geofront.backends.github`` is
a module path.  It's also called as "import path" in Python.

The above environment variable is equivalent to the following configuration::

    from geofront.backends.github import *
    TEAM = GitHubOrganization(
        client_id="...",
        client_secret="...",
        org_login="your_org_name"
    )

You can use a simple literal syntax as well:

.. code-block:: bash

   REMOTE_SET='geofront.remote:{"web-1": Remote("ubuntu", "192.168.0.5")}'

The above environment variable is equivalent to the following configuration::

    from geofront.remote import *
    REMOTE_SET = {"web-1": Remote("ubuntu", "192.168.0.5")}

It's okay to leave module path empty:

.. code-block:: bash

   ENABLE_HSTS=':True'

Docker's :program:`docker run` comamnd :option:`-e`/:option:`--env` option to
pass environment variables:

.. code-block:: bash

   $ docker run -e TEAM='geofront.backends.github:GitHubOrganization(...)' \
                -e REMOTE_SET='geofront.remote:{"web-1": Remote(...)}' \
                --detach --publish 8080 \
                spoqa/geofront:stable

Although :option:`-e`/:option:`--env` can be repeated, it's not suitable for
maintaining configurations.  We therefore recommend to use :option:`--env-file`
option or Docker Compose.

To specify objects with complex initialization steps, Geofront provides several
shortcut factory functions such as :func:`create_compute_driver
<geofront.backends.cloud.create_compute_driver>`, :func:`create_storage_driver
<geofront.backends.cloud.create_storage_driver>`, and
:func:`create_cloud_master_pubkey_store
<geofront.backends.cloud.create_cloud_master_pubkey_store>`.
For example:

.. code-block:: bash

   docker run -e REMOTE_SET='geofront.backends.cloud:CloudRemoteSet(create_compute_driver("EC2", ("AKIA...", "..."), region="ap-northeast-2"), addresser=lambda n: n.private_ips[0], filter=lambda n: bool(n.private_ips))' \
              -e MASTER_KEY_STORE='geofront.backends.cloud:create_cloud_master_pubkey_store("EC2", "S3_AP_NORTHEAST2", ("AKIA...", "..."), "keypair-name", "s3-bucket-name", "s3-object-name", region="ap-northeast-2")' \
              --detach --publish 8080 \
              spoqa/geofront:stable


.. note::

   Configuration cannot refer to each other.  If you need to do that
   :ref:`pass a complete configuration file <docker-config-file>` instead of
   environment variables.

.. seealso::

   `Define environment variables`__ --- Docker Documentation

   `Set environment variables (-e, --env, --env-file)`__ --- Docker Documentation

__ https://docs.docker.com/docker-cloud/getting-started/deploy-app/6_define_environment_variables/
__ https://docs.docker.com/engine/reference/commandline/run/#set-environment-variables--e---env---env-file


.. _docker-config-file:

Passing a complete configuration file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:doc:`Geofront uses Python the language for its configuration file <config>`
so that it can be easily extended.  Although configuring Geofront through
:ref:`environment variables <docker-env-vars>` are simple and easy to use,
it's more limited than passing a complete configuration file written in Python.

The official Geofront image looks up its configration file at
:file:`/etc/geofront.cfg.py`.  So you can override it by mounting your own
configuration file into the path:

.. code-block:: console

   $ docker run --volume /host/path/your.cfg.py:/etc/geofront.cfg.py:ro \
                --detach --publish 8080 \
                spoqa/geofront:stable

.. note::

   If :file:`/etc/geofront.cfg.py` is overridden :ref:`configuration through
   environment variables <docker-env-vars>` doesn't work anymore.

.. seealso::

   `Manage data in containers`__ --- Docker Documentation

__ https://docs.docker.com/engine/tutorials/dockervolumes/


.. _docker-config-compose:

Using Docker Compose
~~~~~~~~~~~~~~~~~~~~

Docker Compopse is a great way to launch a cluster of multiple containers
that works together.  It is useful to containerize external daemons such as
Redis and nginx.

Check out `an example Docker Compose configuration
<https://github.com/spoqa/geofront/blob/2b41f018/example.docker-compose.yml>`_.

.. seealso::

   `Docker Compose Documentation`__

__ https://docs.docker.com/compose/
