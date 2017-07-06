import json

from jose import jws
from jose.constants import ALGORITHMS
from jose.exceptions import JWSError

import pytest

from tests.keys import EC_PUBLIC_KEY
from tests.keys import EC_PRIVATE_KEY
from tests.keys import RSA_PUBLIC_KEY
from tests.keys import RSA_PRIVATE_KEY


@pytest.fixture
def payload():
    payload = b"test payload"
    return payload


class TestJWS(object):

    def test_unicode_token(self):
        token = u'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        jws.verify(token, 'secret', ['HS256'])

    def test_not_enough_segments(self):
        token = 'eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_header_invalid_padding(self):
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9A.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_header_not_json(self):
        token = 'dGVzdA.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_claims_invalid_padding(self):
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AeyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_claims_not_json(self):
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dGVzdA.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_invalid_key(self, payload):
        with pytest.raises(JWSError):
            jws.sign(payload, 'secret', algorithm='RS256')


class TestHMAC(object):

    def testHMAC256(self, payload):
        token = jws.sign(payload, 'secret', algorithm=ALGORITHMS.HS256)
        assert jws.verify(token, 'secret', ALGORITHMS.HS256) == payload

    def testHMAC384(self, payload):
        token = jws.sign(payload, 'secret', algorithm=ALGORITHMS.HS384)
        assert jws.verify(token, 'secret', ALGORITHMS.HS384) == payload

    def testHMAC512(self, payload):
        token = jws.sign(payload, 'secret', algorithm=ALGORITHMS.HS512)
        assert jws.verify(token, 'secret', ALGORITHMS.HS512) == payload

    def test_wrong_alg(self, payload):
        token = jws.sign(payload, 'secret', algorithm=ALGORITHMS.HS256)
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ALGORITHMS.HS384)

    def test_wrong_key(self, payload):
        token = jws.sign(payload, 'secret', algorithm=ALGORITHMS.HS256)
        with pytest.raises(JWSError):
            jws.verify(token, 'another', ALGORITHMS.HS256)

    def test_unsupported_alg(self, payload):
        with pytest.raises(JWSError):
            jws.sign(payload, 'secret', algorithm='SOMETHING')

    def test_add_headers(self, payload):

        additional_headers = {
            'test': 'header'
        }

        expected_headers = {
            'test': 'header',
            'alg': 'HS256',
            'typ': 'JWT',
        }

        token = jws.sign(payload, 'secret', headers=additional_headers)
        header, payload, signing_input, signature = jws._load(token)
        assert expected_headers == header


@pytest.fixture
def jwk_set():
    return {u'keys': [{u'alg': u'RS256',
            u'e': u'AQAB',
            u'kid': u'40aa42edac0614d7ca3f57f97ee866cdfba3b61a',
            u'kty': u'RSA',
            u'n': u'6lm9AEGLPFpVqnfeVFuTIZsj7vz_kxla6uW1WWtosM_MtIjXkyyiSolxiSOs3bzG66iVm71023QyOzKYFbio0hI-yZauG3g9nH-zb_AHScsjAKagHtrHmTdtq0JcNkQnAaaUwxVbjwMlYAcOh87W5jWj_MAcPvc-qjy8-WJ81UgoOUZNiKByuF4-9igxKZeskGRXuTPX64kWGBmKl-tM7VnCGMKoK3m92NPrktfBoNN_EGGthNfQsKFUdQFJFtpMuiXp9Gib7dcMGabxcG2GUl-PU086kPUyUdUYiMN2auKSOxSUZgDjT7DcI8Sn8kdQ0-tImaHi54JNa1PNNdKRpw',
            u'use': u'sig'},
           {u'alg': u'RS256',
            u'e': u'AQAB',
            u'kid': u'8fbbeea40332d2c0d27e37e1904af29b64594e57',
            u'kty': u'RSA',
            u'n': u'z7h6_rt35-j6NV2iQvYIuR3xvsxmEImgMl8dc8CFl4SzEWrry3QILajKxQZA9YYYfXIcZUG_6R6AghVMJetNIl2AhCoEr3RQjjNsm9PE6h5p2kQ-zIveFeb__4oIkVihYtxtoYBSdVj69nXLUAJP2bxPfU8RDp5X7hT62pKR05H8QLxH8siIQ5qR2LGFw_dJcitAVRRQofuaj_9u0CLZBfinqyRkBc7a0zi7pBxtEiIbn9sRr8Kkb_Boap6BHbnLS-YFBVarcgFBbifRf7NlK5dqE9z4OUb-dx8wCMRIPVAx_hV4Qx2anTgp1sDA6V4vd4NaCOZX-mSctNZqQmKtNw',
            u'use': u'sig'},
           {u'alg': u'RS256',
            u'e': u'AQAB',
            u'kid': u'6758b0b8eb341e90454860432d6a1648bf4de03b',
            u'kty': u'RSA',
            u'n': u'5K0rYaA7xtqSe1nFn_nCA10uUXY81NcohMeFsYLbBlx_NdpsmbpgtXJ6ektYR7rUdtMMLu2IONlNhkWlx-lge91okyacUrWHP88PycilUE-RnyVjbPEm3seR0VefgALfN4y_e77ljq2F7W2_kbUkTvDzriDIWvQT0WwVF5FIOBydfDDs92S-queaKgLBwt50SXJCZryLew5ODrwVsFGI4Et6MLqjS-cgWpCNwzcRqjBRsse6DXnex_zSRII4ODzKIfX4qdFBKZHO_BkTsK9DNkUayrr9cz8rFRK6TEH6XTVabgsyd6LP6PTxhpiII_pTYRSWk7CGMnm2nO0dKxzaFQ',
            u'use': u'sig'}]}

google_id_token = (
    'eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmYmJlZWE0MDMzMmQyYzBkMjdlMzdlMTkwN'
    'GFmMjliNjQ1OTRlNTcifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5'
    'jb20iLCJhdF9oYXNoIjoiUUY5RnRjcHlmbUFBanJuMHVyeUQ5dyIsImF1ZCI6IjQw'
    'NzQwODcxODE5Mi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwN'
    'zkzMjQxNjk2NTIwMzIzNDA3NiIsImF6cCI6IjQwNzQwODcxODE5Mi5hcHBzLmdvb2'
    'dsZXVzZXJjb250ZW50LmNvbSIsImlhdCI6MTQ2ODYyMjQ4MCwiZXhwIjoxNDY4NjI'
    '2MDgwfQ.Nz6VREh7smvfVRWNHlbKZ6W_DX57akRUGrDTcns06ndAwrslwUlBeFsWY'
    'RLon_tDw0QCeQCGvw7l1AT440UQBRP-mtqK_2Yny2JmIQ7Ll6UAIHRhXOD1uj9w5v'
    'X0jyI1MbjDtODeDWWn_9EDJRBd4xmwKhAONuWodTgSi7qGe1UVmzseFNNkKdoo54d'
    'XhCJiyiRAMnWB_FQDveRJghche131pd9O_E4Wj6hf_zCcMTaDaLDOmElcQe-WsKWA'
    'A3YwHFEWOLO_7x6u4uGmhItPGH7zsOTzYxPYhZMSZusgVg9fbE1kSlHVSyQrcp_rR'
    'WNz7vOIbvIlBR9Jrq5MIqbkkg'
)


class TestGetKeys(object):

    def test_dict(self):
        assert ({},) == jws._get_keys({})

    def test_custom_object(self):
        class MyDict(dict):
            pass
        mydict = MyDict()
        assert (mydict,) == jws._get_keys(mydict)

    def test_RFC7517_string(self):
        key = '{"keys": [{}, {}]}'
        assert [{}, {}] == jws._get_keys(key)

    def test_RFC7517_jwk(self):
        key = {'kty': 'hsa', 'k': 'secret', 'alg': 'HS256', 'use': 'sig'}
        assert (key, ) == jws._get_keys(key)

    def test_RFC7517_mapping(self):
        key = {"keys": [{}, {}]}
        assert [{}, {}] == jws._get_keys(key)

    def test_string(self):
        assert ('test',) == jws._get_keys('test')

    def test_tuple(self):
        assert ('test', 'key') == jws._get_keys(('test', 'key'))

    def test_list(self):
        assert ['test', 'key'] == jws._get_keys(['test', 'key'])


class TestRSA(object):

    def test_jwk_set(self, jwk_set):
        # Would raise a JWSError if validation failed.
        payload = jws.verify(google_id_token, jwk_set, ALGORITHMS.RS256)
        iss = json.loads(payload.decode('utf-8'))['iss']
        assert iss == "https://accounts.google.com"

    def test_jwk_set_failure(self, jwk_set):
        # Remove the key that was used to sign this token.
        del jwk_set['keys'][1]
        with pytest.raises(JWSError):
            payload = jws.verify(google_id_token, jwk_set, ALGORITHMS.RS256)

    def test_RSA256(self, payload):
        token = jws.sign(payload, RSA_PRIVATE_KEY, algorithm=ALGORITHMS.RS256)
        assert jws.verify(token, RSA_PUBLIC_KEY, ALGORITHMS.RS256) == payload

    def test_RSA384(self, payload):
        token = jws.sign(payload, RSA_PRIVATE_KEY, algorithm=ALGORITHMS.RS384)
        assert jws.verify(token, RSA_PUBLIC_KEY, ALGORITHMS.RS384) == payload

    def test_RSA512(self, payload):
        token = jws.sign(payload, RSA_PRIVATE_KEY, algorithm=ALGORITHMS.RS512)
        assert jws.verify(token, RSA_PUBLIC_KEY, ALGORITHMS.RS512) == payload

    def test_wrong_alg(self, payload):
        token = jws.sign(payload, RSA_PRIVATE_KEY, algorithm=ALGORITHMS.RS256)
        with pytest.raises(JWSError):
            jws.verify(token, RSA_PUBLIC_KEY, ALGORITHMS.RS384)

    def test_wrong_key(self, payload):
        token = jws.sign(payload, RSA_PRIVATE_KEY, algorithm=ALGORITHMS.RS256)
        with pytest.raises(JWSError):
            jws.verify(token, RSA_PUBLIC_KEY, ALGORITHMS.HS256)


class TestEC(object):

    def test_EC256(self, payload):
        token = jws.sign(payload, EC_PRIVATE_KEY, algorithm=ALGORITHMS.ES256)
        assert jws.verify(token, EC_PUBLIC_KEY, ALGORITHMS.ES256) == payload

    def test_EC384(self, payload):
        token = jws.sign(payload, EC_PRIVATE_KEY, algorithm=ALGORITHMS.ES384)
        assert jws.verify(token, EC_PUBLIC_KEY, ALGORITHMS.ES384) == payload

    def test_EC512(self, payload):
        token = jws.sign(payload, EC_PRIVATE_KEY, algorithm=ALGORITHMS.ES512)
        assert jws.verify(token, EC_PUBLIC_KEY, ALGORITHMS.ES512) == payload

    def test_wrong_alg(self, payload):
        token = jws.sign(payload, EC_PRIVATE_KEY, algorithm=ALGORITHMS.ES256)
        with pytest.raises(JWSError):
            jws.verify(token, RSA_PUBLIC_KEY, ALGORITHMS.ES384)


class TestLoad(object):

    def test_header_not_mapping(self):
        token = 'WyJ0ZXN0Il0.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_claims_not_mapping(self):
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.WyJ0ZXN0Il0.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])

    def test_signature_padding(self):
        token = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
        with pytest.raises(JWSError):
            jws.verify(token, 'secret', ['HS256'])
