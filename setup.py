from __future__ import with_statement

import operator
import os
import sys

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from geofront.version import VERSION


def readme():
    with open('README.rst') as f:
        return f.read()


install_requires = [
    'setuptools',
    'paramiko >= 1.15.0',
    'Werkzeug >= 0.9',
    'Flask >= 0.10',
    'apache-libcloud >= 0.15.0',
    'waitress >= 0.8.8'
]

supported_pyversions = [(3, 3), (3, 4), (3, 5)]

pyversion_requires = {
    ('<', (3, 4)): ['singledispatch'],
}

tests_require = [
    'pytest >= 2.5.0',
    'sftpserver == 0.2py3',  # https://github.com/spoqa/sftpserver/releases
    'iso8601 >= 0.1.10',
    'redis',
    'pytest-cov'
]

docs_require = [
    'Sphinx >= 1.2',
    'sphinxcontrib-httpdomain >= 1.2.1',
    'sphinxcontrib-autoprogram'
]

if sys.version_info < (3, 4):
    tests_require.append('asyncio >= 0.4.1')

extras_require = {
    'tests': tests_require,
    'docs': docs_require,
}

# The current wheel version (0.24.0) doesn't seem to cover all comparison
# operators of PEP 426 except for ==, so we need to expand all other operators
# to multiple equals e.g. <=2.7 to ==2.6, ==2.7.
operators = {
    '==': operator.eq, '!=': operator.ne, '<': operator.lt, '<=': operator.le,
    '>': operator.gt, '>=': operator.ge
}
for (op, ver), packages in pyversion_requires.items():
    for pyversion in supported_pyversions:
        if operators[op](pyversion, ver):
            extras_require.setdefault(
                ':python_version==' + repr('.'.join(map(str, pyversion))),
                []
            ).extend(packages)
            # FIXME: Shitty hack... The current version of setuptools and pip
            # doesn't support PEP 426, so we need to manually inject
            # conditional requirements into install_requires.
            # Note that injection must not be done for bdist_wheel since
            # wheel statically captures all install_requires and then
            # freezes them into JSON.
            if 'bdist_wheel' not in sys.argv:
                install_requires.extend(packages)

# Install requirements for documentation if it's run by ReadTheDocs.org
if os.environ.get('READTHEDOCS'):
    install_requires.extend(docs_require)


setup(
    name='Geofront',
    version=VERSION,
    description='Simple SSH key management service',
    long_description=readme(),
    url='https://github.com/spoqa/geofront',
    author='Hong Minhee',
    author_email='minhee' '@' 'member.fsf.org',
    maintainer='Spoqa',
    maintainer_email='dev' '@' 'spoqa.com',
    license='AGPLv3 or later',
    packages=find_packages(exclude=['tests']),
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require=extras_require,
    entry_points='''
        [console_scripts]
        geofront-server = geofront.server:main
        geofront-key-regen = geofront.regen:main
    ''',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved '
        ':: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
    ]
)
