""":mod:`geofront.version` --- Version data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""

#: (:class:`typing.Tuple`[:class:`int`, :class:`int`, :class:`int`])
#: The triple of version numbers e.g. ``(1, 2, 3)``.
VERSION_INFO = (0, 4, 0)

#: (:class:`str`) The version string e.g. ``'1.2.3'``.
VERSION = '{}.{}.{}'.format(*VERSION_INFO)


if __name__ == '__main__':
    print(VERSION)
