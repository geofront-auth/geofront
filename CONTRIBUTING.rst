How to contribute
=================

License agreement
-----------------

All contributed codes have to be free software licensed under the terms of
the `GNU Affero General Public License Version 3`__ or any later version.
We treat all pull requests imply agreement of it, but if a significant
amount of code is involved, it is safest to mention in the pull request
comments that you agree to let the patch be used under the GNU Affero General
Public License Version 3 or any later version as part of the Geofront code.

__ http://www.gnu.org/licenses/agpl-3.0.html


Coding style
------------

- Follow `PEP 8`_ except you can limit all lines to
  a maximum of 80 characters (not 79).
- Order ``import``\ s in lexicographical order.
- Prefer relative ``import``\ s.
- All functions, classes, methods, attributes, and modules
  should have the docstring.


.. _PEP 8: http://www.python.org/dev/peps/pep-0008/


Tests
-----

- All code patches should contain one or more unit tests of
  the feature to add or regression tests of the bug to fix.
- You can run the test suite using ``runtests.sh`` script.  It installs
  librearies for testing as well if not installed.
- Or you can simply run ``py.test`` command if you have all dependencies
  for testing.
- Some tests would be skipped unless you give additional options.  You can
  see the list of available options in *custom options* section of
  ``py.test --help``.
- All commits will be tested by `Travis CI`__.

__ https://travis-ci.org/spoqa/geofront
