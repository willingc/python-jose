
import pytest
import sys

from jose.backends.pycrypto_backend import RSAKey
from jose.backends.cryptography_backend import CryptographyRSAKey
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError, JWKError

from Crypto.PublicKey import RSA

from tests.keys import RSA_PRIVATE_KEY


# Deal with integer compatibilities between Python 2 and 3.
# Using `from builtins import int` is not supported on AppEngine.
if sys.version_info > (3,):
    long = int


class TestRSAAlgorithm:

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_RSA_key(self, Backend):
        assert not Backend(RSA_PRIVATE_KEY, ALGORITHMS.RS256).is_public()

    def test_pycrypto_RSA_key_instance(self):
        key = RSA.construct((long(26057131595212989515105618545799160306093557851986992545257129318694524535510983041068168825614868056510242030438003863929818932202262132630250203397069801217463517914103389095129323580576852108653940669240896817348477800490303630912852266209307160550655497615975529276169196271699168537716821419779900117025818140018436554173242441334827711966499484119233207097432165756707507563413323850255548329534279691658369466534587631102538061857114141268972476680597988266772849780811214198186940677291891818952682545840788356616771009013059992237747149380197028452160324144544057074406611859615973035412993832273216732343819), long(65537)))
        RSAKey(key, ALGORITHMS.RS256)

    def test_cryptography_RSA_key_instance(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.RSAPublicNumbers(
            long(65537),
            long(26057131595212989515105618545799160306093557851986992545257129318694524535510983041068168825614868056510242030438003863929818932202262132630250203397069801217463517914103389095129323580576852108653940669240896817348477800490303630912852266209307160550655497615975529276169196271699168537716821419779900117025818140018436554173242441334827711966499484119233207097432165756707507563413323850255548329534279691658369466534587631102538061857114141268972476680597988266772849780811214198186940677291891818952682545840788356616771009013059992237747149380197028452160324144544057074406611859615973035412993832273216732343819),
            ).public_key(default_backend())

        pubkey = CryptographyRSAKey(key, ALGORITHMS.RS256)
        assert pubkey.is_public()

        pem = pubkey.to_pem()
        assert pem.startswith(b'-----BEGIN PUBLIC KEY-----')

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_string_secret(self, Backend):
        key = 'secret'
        with pytest.raises(JOSEError):
            Backend(key, ALGORITHMS.RS256)

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_object(self, Backend):
        key = object()
        with pytest.raises(JOSEError):
            Backend(key, ALGORITHMS.RS256)

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_bad_cert(self, Backend):
        key = '-----BEGIN CERTIFICATE-----'
        with pytest.raises(JOSEError):
            Backend(key, ALGORITHMS.RS256)

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_invalid_algorithm(self, Backend):
        with pytest.raises(JWKError):
            Backend(RSA_PRIVATE_KEY, ALGORITHMS.ES256)

        with pytest.raises(JWKError):
            Backend({'kty': 'bla'}, ALGORITHMS.RS256)

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_RSA_jwk(self, Backend):
        key = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        }
        assert Backend(key, ALGORITHMS.RS256).is_public()

        key = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
            "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
            "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
            "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
            "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX 59ehik",
            "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
            "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"
        }
        assert not Backend(key, ALGORITHMS.RS256).is_public()

        del key['p']

        # Some but not all extra parameters are present
        with pytest.raises(JWKError):
            Backend(key, ALGORITHMS.RS256)

        del key['q']
        del key['dp']
        del key['dq']
        del key['qi']

        # None of the extra parameters are present, but 'key' is still private.
        assert not Backend(key, ALGORITHMS.RS256).is_public()

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_string_secret(self, Backend):
        key = 'secret'
        with pytest.raises(JOSEError):
            Backend(key, ALGORITHMS.RS256)

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_get_public_key(self, Backend):
        key = Backend(RSA_PRIVATE_KEY, ALGORITHMS.RS256)
        public_key = key.public_key()
        public_key2 = public_key.public_key()
        assert public_key.is_public()
        assert public_key2.is_public()
        assert public_key == public_key2

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_to_pem(self, Backend):
        key = Backend(RSA_PRIVATE_KEY, ALGORITHMS.RS256)
        assert key.to_pem().strip() == RSA_PRIVATE_KEY.strip().encode('utf-8')

    def assert_parameters(self, as_dict, private):
        assert isinstance(as_dict, dict)

        # Public parameters should always be there.
        assert 'n' in as_dict
        assert 'e' in as_dict

        if private:
            # Private parameters as well
            assert 'd' in as_dict
            assert 'p' in as_dict
            assert 'q' in as_dict
            assert 'dp' in as_dict
            assert 'dq' in as_dict
            assert 'qi' in as_dict
        else:
            # Private parameters should be absent
            assert 'd' not in as_dict
            assert 'p' not in as_dict
            assert 'q' not in as_dict
            assert 'dp' not in as_dict
            assert 'dq' not in as_dict
            assert 'qi' not in as_dict

    def assert_roundtrip(self, key, Backend):
        assert Backend(
            key.to_dict(),
            ALGORITHMS.RS256
        ).to_dict() == key.to_dict()

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_to_dict(self, Backend):
        key = Backend(RSA_PRIVATE_KEY, ALGORITHMS.RS256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)
        self.assert_roundtrip(key, Backend)
        self.assert_roundtrip(key.public_key(), Backend)

    @pytest.mark.parametrize("BackendSign", [RSAKey, CryptographyRSAKey])
    @pytest.mark.parametrize("BackendVerify", [RSAKey, CryptographyRSAKey])
    def test_signing_parity(self, BackendSign, BackendVerify):
        key_sign = BackendSign(RSA_PRIVATE_KEY, ALGORITHMS.RS256)
        key_verify = BackendVerify(RSA_PRIVATE_KEY, ALGORITHMS.RS256).public_key()

        msg = b'test'
        sig = key_sign.sign(msg)

        # valid signature
        assert key_verify.verify(msg, sig)

        # invalid signature
        assert not key_verify.verify(msg, b'n' * 64)

    @pytest.mark.parametrize("Backend", [RSAKey, CryptographyRSAKey])
    def test_pycrypto_unencoded_cleartext(self, Backend):
        key = Backend(RSA_PRIVATE_KEY, ALGORITHMS.RS256)

        with pytest.raises(JWKError):
            key.sign(True)
