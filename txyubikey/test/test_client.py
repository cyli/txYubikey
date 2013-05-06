"""
Tests for L{txyubikey.client}
"""
from hashlib import sha1
import hmac
import mock

from twisted.internet import defer
from twisted.trial.unittest import TestCase
from twisted.web.client import Agent

from txyubikey.client import YubiKeyVerificationError, YubiKeyVerifier


class _DictTester(object):
    """
    Easier way to test what things are called with.
    """
    def __init__(self, test_function):
        self.test_function = test_function

    def __eq__(self, other):
        return isinstance(other, dict) and self.test_function(other)


class YubiKeyVerifierRequestTestCase(TestCase):
    """
    Tests for the part of L{txyubikey.client.YubiKeyVerifier.verify} regarding
    making the requests.
    """

    def setUp(self):
        self.agent = mock.MagicMock(Agent)
        self.verifier_id = "verifier"
        self.api_key = None
        self.nonce_generator = mock.MagicMock(spec=[], return_value='0'*36)
        self.validation_servers = ["server1", "server2"]
        self.client = YubiKeyVerifier(self.agent, self.verifier_id,
                                      self.api_key, self.nonce_generator,
                                      self.validation_servers)

        # mock out all of the client's methods
        self.client_patchers = {}
        for method in ('_request_from_all_servers', '_query_server',
                       '_verify_response', '_maybe_sign_query'):
            self.client_patchers[method] = mock.patch.object(
                self.client, method)
            self.client_patchers[method].start()

        self.addCleanup(mock.patch.stopall)

    def test_initializer_ignores_api_key_if_None(self):
        """
        L{txyubikey.client.YubiKeyVerifier} sets API key to None if None is
        passed in as the API key
        """
        self.assertEqual(None, self.client.api_key)

    def test_initializer_base64_decodes_api_key_if_not_none(self):
        """
        L{txyubikey.client.YubiKeyVerifier} base64-decodes API key if it is not
        None
        """
        api_key = "hey there!".encode('base64')
        self.client = YubiKeyVerifier(self.agent, self.verifier_id,
                                      api_key, self.nonce_generator,
                                      self.validation_servers)
        self.assertEqual('hey there!', self.client.api_key)

    def test_api_key_setter_ignores_api_key_if_None(self):
        """
        L{txyubikey.client.YubiKeyVerifier} sets API key to None if None is
        passed in as the API key
        """
        self.client.api_key = None
        self.assertEqual(None, self.client.api_key)

    def test_api_key_setter_base64_decodes_api_key_if_not_none(self):
        """
        L{txyubikey.client.YubiKeyVerifier} base64-decodes API key if it is not
        None
        """
        self.client.api_key = "hey there!".encode('base64')
        self.assertEqual('hey there!', self.client.api_key)

    def test_maybe_sign_query_no_signing_if_no_api_key(self):
        """
        L{txyubikey.client.YubiKeyVerifier._maybe_sign_query} does not attempt
        to sign the query if the API key is None
        """
        # stop patching this function
        self.client_patchers['_maybe_sign_query'].stop()

        params = {'a': '1', 'b': '2', 'c': '3'}
        self.client._maybe_sign_query(params)
        self.assertNotIn('h', params)

    def test_maybe_sign_query_signs_if_api_key(self):
        """
        If there is an API key, L{txyubikey.client.YubiKeyVerifier.verify}
        creates a URL formatted string of the sorted query dict and produces
        a signature from that string
        """
        # stop patching this function
        self.client_patchers['_maybe_sign_query'].stop()
        self.client.api_key = 'key'.encode('base64')

        params = {'z': '1', 'x': '2', 'y': '4'}
        sig = hmac.new('key', 'x=2&y=4&z=1', sha1).digest().encode('base64')

        self.client._maybe_sign_query(params)
        self.assertEqual(sig, params.get('h', None))

    def test_maybe_sign_query_ignores_existing_signature(self):
        """
        If there is an API key, and there is already a signature,
        L{txyubikey.client.YubiKeyVerifier.verify} creates a URL formatted
        string of the sorted query dict without the signature and produces
        a signature from that string
        """
        # stop patching this function
        self.client_patchers['_maybe_sign_query'].stop()
        self.client.api_key = 'key'.encode('base64')

        params = {'z': '1', 'x': '2', 'y': '4', 'h': 'signed!'}
        sig = hmac.new('key', 'x=2&y=4&z=1', sha1).digest().encode('base64')

        self.client._maybe_sign_query(params)
        self.assertEqual(sig, params.get('h', None))

    def test_verify_rejects_OTPs_of_the_wrong_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} raises a
        L{txyubikey.client.YubiKeyVerificationError} if the OTP is less than 32
        characters or greater than 48 characters
        """
        for invalid in ('x'*31, 'x'*49):
            f = self.failureResultOf(self.client.verify(invalid))
            self.assertTrue(f.check(YubiKeyVerificationError))

        self.assertEqual(0, self.client._maybe_sign_query.call_count)
        self.assertEqual(0, self.client._request_from_all_servers.call_count)

    def test_verify_accepts_OTPs_of_the_right_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} continues validating
        succesfully if the OTP is >= 32 characters and <= 48 characters
        """
        self.client._request_from_all_servers.side_effect = (
            lambda *args: defer.succeed('valid_yubikey_id'))

        for valid in ('x'*32, 'x'*48):
            result = self.successResultOf(self.client.verify(valid))
            self.assertEqual('valid_yubikey_id', result)

        self.assertEqual(2, self.client._maybe_sign_query.call_count)
        self.assertEqual(2, self.client._request_from_all_servers.call_count)

    def test_verify_rejects_nonces_of_the_wrong_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} raises a
        L{txyubikey.client.YubiKeyVerificationError} if the nonce generated
        with the generator is less than 16 characters or greater than 40
        characters
        """
        for invalid in (15, 41):
            self.nonce_generator.return_value = 'x'*invalid
            f = self.failureResultOf(self.client.verify('x'*36))
            self.assertTrue(f.check(YubiKeyVerificationError))

        self.assertEqual(0, self.client._maybe_sign_query.call_count)
        self.assertEqual(0, self.client._request_from_all_servers.call_count)

    def test_verify_accepts_nonces_of_the_right_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} continues_validating
        successfully if the nonce generated is >= 16 characters and <= 40
        characters
        """
        self.client._request_from_all_servers.side_effect = (
            lambda *args: defer.succeed('valid_yubikey_id'))

        for valid in (16, 40):
            self.nonce_generator.return_value = 'x'*valid
            result = self.successResultOf(self.client.verify('x'*36))
            self.assertEqual('valid_yubikey_id', result)

        self.assertEqual(2, self.client._maybe_sign_query.call_count)
        self.assertEqual(2, self.client._request_from_all_servers.call_count)

