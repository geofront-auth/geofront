HTTP API
========

Server version
--------------

The release policy of Geofront follows `Semantic Versioning`_, and the HTTP
API which this docs covers also does the same.  You can treat what you could
do on Geofront 1.2.3:

- might be broken on Geofront 2.0.0;
- shouldn't be broken 1.3.0;
- must not be broken on Geofront 1.2.4.

Also broken things on Geofront 1.2.3 might be fixed on Geofront 1.2.4.

So how does the server tell its version through HTTP API?  It provides two
headers that are equivalent:

:mailheader:`Server`
   Which is a standard compliant header.  The form follows also the standard
   e.g. ``Geofront/1.2.3``.

:mailheader:`X-Geofront-Version`
   Which is a non-standard extended header.  The form consists of only the
   version number e.g. ``1.2.3``.

These headers even are provided when the response is error:

.. code-block:: http

   HTTP/1.0 404 Not Found
   Content-Length: 9
   Content-Type: text/plain
   Date: Tue, 01 Apr 2014 17:46:36 GMT
   Server: Geofront/0.9.0
   X-Geofront-Version: 0.9.0

   Not Found

.. _Semantic Versioning: http://semver.org/


Endpoints
---------

.. autoflask:: geofront.server:app
   :undoc-static:
