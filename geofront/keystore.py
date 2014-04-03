""":mod:`geofront.keystore` --- Public key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import base64
import collections.abc
import enum

from paramiko.pkey import PKey

from .identity import Identity
from .util import typed

__all__ = {'AuthorizationError', 'DuplicatePublicKeyError', 'KeyStore',
           'KeyStoreError'}


class KeyStore:
    """The key store backend interface.  Every key store has to guarantee
    that public keys are unique for all identities i.e. the same public key
    can't be registered across more than an identity.

    """

    @typed
    def register(self, identity: Identity, public_key: PKey):
        """Register the given ``public_key`` to the ``identity``.

        :param ientity: the owner identity
        :type identity: :class:`~.identity.Identity`
        :param public_key: the public key to register
        :type public_key: :class:`paramiko.pkey.PKey`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store
        :raise geofront.keystore.DuplicatePublicKeyError:
            when the ``public_key`` is already in use


        """
        raise NotImplementedError('register() has to be implemented')

    @typed
    def list_keys(self, identity: Identity) -> collections.abc.Set:
        """List registered public keys of the given ``identity``.

        :param identity: the owner of keys to list
        :type identity: :class:`~.identity.Identity`
        :return: the set of :class:`paramiko.pkey.PKey`
                 owned by the ``identity``
        :rtype: :class:`collections.abc.Set`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('list_keys() has to be implemented')

    @typed
    def deregister(self, identity: Identity, public_key: PKey):
        """Remove the given ``public_key`` of the ``identity``.
        It silently does nothing if there isn't the given ``public_key``
        in the store.

        :param ientity: the owner identity
        :type identity: :class:`~.identity.Identity`
        :param public_key: the public key to remove
        :type public_key: :class:`paramiko.pkey.PKey`
        :raise geofront.keystore.AuthorizationError:
            when the given ``identity`` has no required permission
            to the key store

        """
        raise NotImplementedError('deregister() has to be implemented')


class KeyStoreError(Exception):
    """Exceptions related to :class:`KeyStore` are an instance of this."""


class AuthorizationError(KeyStoreError):
    """Authorization exception that rise when the given identity has
    no required permission to the key store.

    """


class DuplicatePublicKeyError(KeyStoreError):
    """Exception that rise when the given public key is already registered."""
