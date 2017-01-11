import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from django.utils.translation import ugettext_lazy as _
from OpenSSL.rand import bytes as generate_bytes
from rest_framework import exceptions

from knox.settings import knox_settings, CONSTANTS

sha = knox_settings.SECURE_HASH_ALGORITHM


def create_token_string():
    return binascii.hexlify(
        generate_bytes(int(knox_settings.AUTH_TOKEN_CHARACTER_LENGTH / 2))
    ).decode()


def create_salt_string():
    return binascii.hexlify(
        generate_bytes(int(CONSTANTS.SALT_LENGTH / 2))).decode()


def hash_token(token, salt):
    '''
    Calculates the hash of a token and salt.
    input is unhexlified
    '''
    digest = hashes.Hash(sha(), backend=default_backend())
    try:
        digest.update(binascii.unhexlify(token))
    except binascii.Error:
        msg = _('Non-hexadecimal digit found. '
                'The token string passed to authentication may be null.')
        raise exceptions.AuthenticationFailed(msg)
    digest.update(binascii.unhexlify(salt))
    return binascii.hexlify(digest.finalize()).decode()
