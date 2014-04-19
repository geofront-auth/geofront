from __future__ import with_statement

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
    'paramiko >= 1.13.0, == dev',
    'Werkzeug >= 0.9',
    'Flask >= 0.10',
    'apache-libcloud >= 0.14.0',
    'waitress >= 0.8.8'
]

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
    install_requires.append('enum34')
    tests_require.append('asyncio >= 0.4.1')

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
    author_email='minhee' '@' 'dahlia.kr',
    maintainer='Spoqa',
    maintainer_email='dev' '@' 'spoqa.com',
    license='AGPLv3 or later',
    packages=find_packages(exclude=['tests']),
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        'tests': tests_require,
        'docs': docs_require
    },
    entry_points='''
        [console_scripts]
        geofront-server = geofront.server:main
    ''',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved '
        ':: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
    ]
)
