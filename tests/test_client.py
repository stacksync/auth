'''
@author: Adrian Moreno
'''
import unittest
import urllib2
from oauthlib.common import urlencode, urldecode
from oauthlib import oauth1
from oauthlib.oauth1 import SIGNATURE_PLAINTEXT, SIGNATURE_TYPE_AUTH_HEADER, SIGNATURE_TYPE_BODY, SIGNATURE_TYPE_QUERY
import requests


BASE_URL = "http://localhost:8080/oauth"
CLIENT_KEY = "b3af4e669daf880fb16563e6f36051b105188d413"
CLIENT_SECRET = "c168e65c18d75b35d8999b534a3776cf"
REQUEST_TOKEN_ENDPOINT = "/request_token"
ACCESS_TOKEN_ENDPOINT = "/access_token"


class Test(unittest.TestCase):

    def __test_request_token_headers_params(self):
        client = oauth1.Client(CLIENT_KEY,
                               client_secret=CLIENT_SECRET,
                               signature_type=SIGNATURE_TYPE_AUTH_HEADER,
                               signature_method=SIGNATURE_PLAINTEXT,
                               callback_uri='http://localhost/callback')
        url = BASE_URL + REQUEST_TOKEN_ENDPOINT
        uri, headers, _ = client.sign(url,
                                      http_method='GET')
        r = requests.get(uri, headers=headers)

        if r.status_code != 200:
            assert False

        decoded_data = urldecode(r.text)
        oauth_response = dict(decoded_data)
        assert 'oauth_token' in oauth_response and 'oauth_token_secret' in oauth_response

    def __test_request_token_body_params(self):
        client = oauth1.Client(CLIENT_KEY,
                               client_secret=CLIENT_SECRET,
                               signature_type=SIGNATURE_TYPE_BODY,
                               signature_method=SIGNATURE_PLAINTEXT,
                               callback_uri='oob')
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        url = BASE_URL + REQUEST_TOKEN_ENDPOINT
        uri, headers, body = client.sign(url,
                                         headers=headers,
                                         http_method='POST',
                                         body='')
        r = requests.post(uri, body, headers=headers)

        if r.status_code != 200:
            assert False

        decoded_data = urldecode(r.text)
        oauth_response = dict(decoded_data)
        assert 'oauth_token' in oauth_response and 'oauth_token_secret' in oauth_response

    def __test_request_token_query_params(self):
        client = oauth1.Client(CLIENT_KEY,
                               client_secret=CLIENT_SECRET,
                               signature_type=SIGNATURE_TYPE_QUERY,
                               signature_method=SIGNATURE_PLAINTEXT,
                               callback_uri='oob')
        url = BASE_URL + REQUEST_TOKEN_ENDPOINT
        uri, headers, _ = client.sign(url,
                                      http_method='GET')

        r = requests.get(uri, headers=headers)

        if r.status_code != 200:
            assert False

        decoded_data = urldecode(r.text)
        oauth_response = dict(decoded_data)
        assert 'oauth_token' in oauth_response and 'oauth_token_secret' in oauth_response

    def test_access_token_query_params(self):
        client = oauth1.Client(CLIENT_KEY,
                               client_secret=CLIENT_SECRET,
                               signature_type=SIGNATURE_TYPE_QUERY,
                               signature_method=SIGNATURE_PLAINTEXT,
                               resource_owner_key='V7jictT3VGpSG7IAkiY2F9naaQ0bRe',
                               resource_owner_secret='h4x6lTb5UIgCFt0UOy1VJ0uQgcY68h',
                               verifier='69qjCUfvYp3LjmgBJfz0FN9EMVOp6m')
        url = BASE_URL + ACCESS_TOKEN_ENDPOINT
        uri, headers, _ = client.sign(url,
                                      http_method='GET')
        req = urllib2.Request(str(uri), headers=headers)
        resp = urllib2.urlopen(req)
        data = resp.read()
        decoded_data = urldecode(data)
        oauth_response = dict(decoded_data)
        assert 'oauth_token' in oauth_response and 'oauth_token_secret' in oauth_response

    def __test_protected_resource(self):
        client = oauth1.Client(CLIENT_KEY,
                               client_secret=CLIENT_SECRET,
                               signature_type=SIGNATURE_TYPE_QUERY,
                               signature_method=SIGNATURE_PLAINTEXT,
                               resource_owner_key='08f8404a0ea79d0916507206ffdaac0e',
                               resource_owner_secret='b5c1b22175d66451f4bfe87749f94ca0')
        url = self.base_url % ('resource', )
        uri, headers, _ = client.sign(url,
                                      http_method='GET')
        req = urllib2.Request(str(uri), headers=headers)
        resp = urllib2.urlopen(req)
        data = resp.read()
        assert 'OK' in data


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.requestNewToken']
    unittest.main()
