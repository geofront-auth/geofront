from __future__ import with_statement

import operator
import os
import sys

from setuptools import setup, find_packages

from geofront.version import VERSION


def readme():
    with open('README.rst') as f:
        return f.read()


install_requires = [
    'setuptools',
    'typeguard >= 2.1.1, < 3.0.0',
    'cryptography >= 1.4',
    # indirect dependency thorugh paramiko; just for version constraint (>=1.4)
    'paramiko >= 2.0.1',
    'Werkzeug >= 0.11',
    'oauthlib[rsa, signedtoken] >= 1.1.1, < 2.0.0',
    'Flask >= 0.10.1',
    'apache-libcloud >= 1.1.0',
    'waitress >= 1.0.2, < 2.0.0'
]

supported_pyversions = [(3, 3), (3, 4), (3, 5), (3, 6)]

pyversion_requires = {
    ('<', (3, 4)): ['singledispatch'],
    ('<', (3, 5)): ['typing'],
}

tests_require = [
    'pytest >= 2.5.0',
    'sftpserver == 0.2setuptools',
    # FIXME: https://github.com/spoqa/sftpserver/releases
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
    author_email='hongminhee' '@' 'member.fsf.org',
    maintainer='Spoqa',
    maintainer_email='dev' '@' 'spoqa.com',
    license='AGPLv3 or later',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.3.0',
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
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
    ]
)
