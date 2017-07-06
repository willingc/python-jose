
import pytest

from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError
from jose.jwk import HMACKey

from tests.keys import RSA_PUBLIC_KEY
from tests.keys import RSA_X509_CERTIFICATE
from tests.keys import RSA_PKCS1_PEM
from tests.keys import RSA_PRIVATE_KEY
from tests.keys import RSA_OPENSSL_KEY


class TestHMACAlgorithm:

    def test_non_string_key(self):
        with pytest.raises(JOSEError):
            HMACKey(object(), ALGORITHMS.HS256)

    def test_RSA_key(self):

        for key in (
                RSA_PUBLIC_KEY,
                RSA_X509_CERTIFICATE,
                RSA_PKCS1_PEM,
                RSA_PRIVATE_KEY,
                RSA_OPENSSL_KEY):
            with pytest.raises(JOSEError):
                HMACKey(key, ALGORITHMS.HS256)

    def test_to_dict(self):
        passphrase = 'The quick brown fox jumps over the lazy dog'
        encoded = b'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw'
        key = HMACKey(passphrase, ALGORITHMS.HS256)

        as_dict = key.to_dict()
        assert 'alg' in as_dict
        assert as_dict['alg'] == ALGORITHMS.HS256

        assert 'kty' in as_dict
        assert as_dict['kty'] == 'oct'

        assert 'k' in as_dict
        assert as_dict['k'] == encoded
