"""
Tests for L{txyubikey.client}
"""
from hashlib import sha1
import hmac
import mock
from urllib import urlencode
from urlparse import parse_qs, urlsplit

from twisted.internet import defer
from twisted.trial.unittest import TestCase

from txyubikey import client


class _Tester(object):
    """
    Easier way to test what things are called with.
    """
    def __init__(self, test_type, test_function):
        self.test_type = test_type
        self.test_function = test_function

    def __eq__(self, other):
        return isinstance(other, self.test_type) and self.test_function(other)


def get_query_dict(url):
    splitted = urlsplit(url)
    return parse_qs(splitted.query)


class HelperTestCase(TestCase):
    """
    Tests for helper functions in L{txyubikey.client}.
    """
    def test_sign_query_calculates_correct_signature(self):
        """
        L{txyubikey.client.sign_query} creates a URL formatted string of the
        sorted query dict (ignoring 'h') and produces a signature from that
        string
        """
        query = {'z': '1', 'h': '3', 'y': '5', 'x': '7'}
        sig = hmac.new('key', 'x=7&y=5&z=1', sha1).digest().encode('base64')
        self.assertEqual(sig, client.sign_query(query, 'key'))


class YubiKeyVerifierTestCase(TestCase):
    """
    Tests for L{txyubikey.client.YubiKeyVerifier.verify}.
    """

    def setUp(self):
        self.deferreds = {}

        def mock_get(url):
            self.deferreds[url] = defer.Deferred()
            return self.deferreds[url]

        self.treq = mock.MagicMock(spec=['get'])
        self.treq.get.side_effect = mock_get

        self.verifier_id = "verifier"
        self.api_key = None
        self.nonce_generator = mock.MagicMock(spec=[], return_value='0'*36)
        self.validation_servers = ["server1"]
        self.client = client.YubiKeyVerifier(
            self.verifier_id, self.api_key, self.nonce_generator,
            self.validation_servers, _treq=self.treq)

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
        self.client = client.YubiKeyVerifier(self.verifier_id, api_key,
                                             self.nonce_generator,
                                             self.validation_servers,
                                             _treq=self.treq)
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

    def test_verify_rejects_OTPs_of_the_wrong_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} raises a
        L{txyubikey.client.YubiKeyVerificationError} if the OTP is less than 32
        characters or greater than 48 characters
        """
        for invalid in ('x'*31, 'x'*49):
            f = self.failureResultOf(self.client.verify(invalid))
            self.assertTrue(f.check(client.YubiKeyVerificationError))

        self.assertEqual(0, self.treq.get.call_count)

    def test_verify_accepts_OTPs_of_the_right_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} continues validating
        succesfully if the OTP is >= 32 characters and <= 48 characters
        """
        for valid in ('x'*32, 'x'*48):
            self.client.verify(valid)

        self.assertEqual(2, self.treq.get.call_count)

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
            self.assertTrue(f.check(client.YubiKeyVerificationError))

        self.assertEqual(0, self.treq.get.call_count)

    def test_verify_accepts_nonces_of_the_right_length(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} continues_validating
        successfully if the nonce generated is >= 16 characters and <= 40
        characters
        """
        for valid in (16, 40):
            self.nonce_generator.return_value = 'x'*valid
            self.client.verify('x'*36)

        self.assertEqual(2, self.treq.get.call_count)

    def test_verify_does_not_sign_if_no_api_key(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} does not attempt to sign
        the query if the API key is None
        """
        self.client.verify('x'*36)
        self.assertEqual(1, self.treq.get.call_count)
        self.assertNotIn('h', get_query_dict(self.deferreds.keys()[0]))

    def test_verify_signs_if_api_key(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} signs the query if there
        is an API
        """
        self.client.api_key = 'key'.encode('base64')
        self.client.verify('x'*36)
        self.assertEqual(1, self.treq.get.call_count)
        self.assertIn('h', get_query_dict(self.deferreds.keys()[0]))

    def test_verify_does_not_use_timestamp_sl_or_timeout_if_not_provided(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request that does
        not include the timestamp, sl, or timeout if they are not provided.
        """
        otp = 'x'*36
        self.client.verify(otp)
        expected = {'id': [self.verifier_id], 'otp': [otp],
                    'nonce': [self.nonce_generator.return_value]}
        self.assertEqual(1, self.treq.get.call_count)
        self.assertEqual(expected, get_query_dict(self.deferreds.keys()[0]))

    def test_verify_uses_timestamp_if_provided(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request that
        includes the timestamp if it is provided, coercing it to an int.
        """
        otp = 'x'*36
        expected = {'id': [self.verifier_id], 'otp': [otp], 'timestamp': ['1'],
                    'nonce': [self.nonce_generator.return_value]}

        mappings = [(1, 1), ('1', 1), ('0', 1), (True, 1),
                    (0, 0), ('', 0), (False, 0), ([], 0)]

        for timestamp, expected_t in mappings:
            expected['timestamp'] = [str(expected_t)]
            self.client.verify(otp, timestamp=timestamp)
            self.assertEqual(expected,
                             get_query_dict(self.deferreds.keys()[0]),
                             '{0!r} should be {1}'.format(timestamp,
                                                          expected_t))
            self.deferreds.clear()

    def test_verify_uses_sl_if_provided(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request that
        includes the timestamp if it is provided, coercing it to an int
        between 0 and 100, inclusive.
        """
        otp = 'x'*36
        expected = {'id': [self.verifier_id], 'otp': [otp], 'sl': None,
                    'nonce': [self.nonce_generator.return_value]}

        mappings = [(-1, 0), (101, 100), (5, 5), ('5', 5), ('-3', 0)]

        for sl, expected_s in mappings:
            expected['sl'] = [str(expected_s)]
            self.client.verify(otp, sl=sl)
            self.assertEqual(expected,
                             get_query_dict(self.deferreds.keys()[0]),
                             '{0!r} should be {1}'.format(sl, expected_s))
            self.deferreds.clear()

    def test_verify_uses_timeout_if_provided(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request that
        includes the timeout if it is provided, coercing it to an int
        """
        otp = 'x'*36
        expected = {'id': [self.verifier_id], 'otp': [otp], 'timeout': None,
                    'nonce': [self.nonce_generator.return_value]}

        mappings = [(0, 0), ('3', 3)]

        for timeout, expected_t in mappings:
            expected['timeout'] = [str(expected_t)]
            self.client.verify(otp, timeout=timeout)
            self.assertEqual(expected,
                             get_query_dict(self.deferreds.keys()[0]),
                             '{0!r} should be {1}'.format(timeout, expected_t))
            self.deferreds.clear()

    def test_verify_hits_all_validation_servers_at_once(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request to the
        right path of every validation server in the client.
        """
        self.client.validation_servers = ["server1", "server2", "server3"]
        otp = 'x'*36
        params = {'id': self.verifier_id, 'otp': otp,
                  'nonce': self.nonce_generator.return_value}

        urls = ['https://{}/wsapi/2.0/verify?{}'.format(s, urlencode(params))
                for s in self.client.validation_servers]

        self.client.verify(otp)
        self.assertEqual([mock.call(url) for url in urls],
                         self.treq.get.mock_calls)

    def test_verify_uses_scheme_specified(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request to the
        validation server using the http scheme specified.
        """
        self.client.scheme = 'bleh'
        self.client.verify('x'*36)
        self.assertEqual(1, self.treq.get.call_count)
        self.assertEqual('bleh', urlsplit(self.deferreds.keys()[0]).scheme)
