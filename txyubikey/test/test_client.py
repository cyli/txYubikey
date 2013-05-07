"""
Tests for L{txyubikey.client}
"""
from hashlib import sha1
import hmac
import mock
import string
from urllib import urlencode
from urlparse import parse_qs, urlsplit

from twisted.internet import defer
from twisted.trial.unittest import TestCase

import treq

from txyubikey import client


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

    def test_generate_nonce(self):
        """
        L{txyubikey.client.generate_nonce} creates a nonce between 16 and 40
        characters [a-ZA-Z0-9_] long.
        """
        nonce = client.generate_nonce()
        self.assertTrue(len(nonce) >= 16)
        self.assertTrue(len(nonce) <= 40)

        letters = string.ascii_letters + string.digits + '_'
        all([char in letters for char in nonce])


class YubiKeyVerifierTestCase(TestCase):
    """
    Tests for L{txyubikey.client.YubiKeyVerifier.verify}.
    """

    def setUp(self):
        self.otp = 'x'*36
        self.verifier_id = "verifier"
        self.api_key = None
        self.nonce = mock.MagicMock(spec=[], return_value='0'*36)
        self.validation_servers = ["server1"]

        self.deferreds = {}
        self.valid_response = (
            "\r\nid=yubikey_id\r\notp={0}\r\n\r\nnonce={1}\r\n".format(
                self.otp, self.nonce.return_value))

        def mock_get(url):
            self.deferreds[url] = defer.Deferred()
            return self.deferreds[url]

        self.treq = mock.MagicMock(spec=['get', 'text_content'])
        self.treq.get.side_effect = mock_get
        self.treq.text_content.return_value = defer.succeed(
            self.valid_response)

        self.client = client.YubiKeyVerifier(
            self.verifier_id, self.api_key, self.nonce,
            self.validation_servers, _treq=self.treq)

    def test_initialize_sets_default_nonce_generator(self):
        """
        L{txyubikey.client.YubiKeyVerifier} the default nonce generator
        """
        c = client.YubiKeyVerifier(self.verifier_id, None)
        self.assertEqual(client.generate_nonce, c.generate_nonce)

    def test_initialize_sets_default_validation_servers(self):
        """
        L{txyubikey.client.YubiKeyVerifier} the default validation_servers
        """
        c = client.YubiKeyVerifier(self.verifier_id, None)
        self.assertEqual(5, len(c.validation_servers))

    def test_initialize_sets_default_treq(self):
        """
        L{txyubikey.client.YubiKeyVerifier} the default treq
        """
        c = client.YubiKeyVerifier(self.verifier_id, None)
        self.assertEqual(treq, c._treq)

    def test_initializer_ignores_api_key_if_None(self):
        """
        L{txyubikey.client.YubiKeyVerifier} sets API key to None if None is
        passed in as the API key
        """
        c = client.YubiKeyVerifier(self.verifier_id, None)
        self.assertEqual(None, c.api_key)

    def test_initializer_base64_decodes_api_key_if_not_none(self):
        """
        L{txyubikey.client.YubiKeyVerifier} base64-decodes API key if it is not
        None
        """
        api_key = "hey there!".encode('base64')
        c = client.YubiKeyVerifier(self.verifier_id, api_key)
        self.assertEqual('hey there!', c.api_key)

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
            self.nonce.return_value = 'x'*invalid
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
            self.nonce.return_value = 'x'*valid
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
        self.client.verify(self.otp)
        expected = {'id': [self.verifier_id], 'otp': [self.otp],
                    'nonce': [self.nonce.return_value]}
        self.assertEqual(1, self.treq.get.call_count)
        self.assertEqual(expected, get_query_dict(self.deferreds.keys()[0]))

    def test_verify_uses_timestamp_if_provided(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request that
        includes the timestamp if it is provided, coercing it to an int.
        """
        expected = {'id': [self.verifier_id], 'otp': [self.otp],
                    'timestamp': ['1'], 'nonce': [self.nonce.return_value]}

        mappings = [(1, 1), ('1', 1), ('0', 1), (True, 1),
                    (0, 0), ('', 0), (False, 0), ([], 0)]

        for timestamp, expected_t in mappings:
            expected['timestamp'] = [str(expected_t)]
            self.client.verify(self.otp, timestamp=timestamp)
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
        expected = {'id': [self.verifier_id], 'otp': [self.otp], 'sl': None,
                    'nonce': [self.nonce.return_value]}

        mappings = [(-1, 0), (101, 100), (5, 5), ('5', 5), ('-3', 0)]

        for sl, expected_s in mappings:
            expected['sl'] = [str(expected_s)]
            self.client.verify(self.otp, sl=sl)
            self.assertEqual(expected,
                             get_query_dict(self.deferreds.keys()[0]),
                             '{0!r} should be {1}'.format(sl, expected_s))
            self.deferreds.clear()

    def test_verify_uses_timeout_if_provided(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} makes a request that
        includes the timeout if it is provided, coercing it to an int
        """
        expected = {'id': [self.verifier_id], 'otp': [self.otp],
                    'timeout': None, 'nonce': [self.nonce.return_value]}

        mappings = [(0, 0), ('3', 3)]

        for timeout, expected_t in mappings:
            expected['timeout'] = [str(expected_t)]
            self.client.verify(self.otp, timeout=timeout)
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
        params = {'id': self.verifier_id, 'otp': self.otp,
                  'nonce': self.nonce.return_value}

        urls = ['https://{}/wsapi/2.0/verify?{}'.format(s, urlencode(params))
                for s in self.client.validation_servers]

        self.client.verify(self.otp)
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

    def test_verify_considers_non_200_response_an_error(self):
        """
        If a response back from the server as a non-200 response,
        L{txyubikey.client.YubiKeyVerifier.verify} considers it an error.
        """
        d = self.client.verify('x'*36)
        self.deferreds.values()[0].callback(
            mock.MagicMock(spec=['code'], code=202))
        f = self.failureResultOf(d)
        self.assertTrue(f.check(client.YubiKeyVerificationError))

    def test_verify_parses_response(self):
        """
        A response back from the server comes back in text format with
        C{key} = C{value}, each on one line.
        L{txyubikey.client.YubiKeyVerifier.verify} parses this into a dict,
        ignoring extraneous whitespace.

        It returns this value, along with the validation server netloc, as the
        result.
        """
        self.client.api_key = 'key'.encode('base64')
        parsed = {'otp': self.otp, 'nonce': self.nonce.return_value,
                  'id': 'yubikey_id'}
        parsed['h'] = client.sign_query(parsed, self.client.api_key)

        d = self.client.verify(self.otp)

        self.treq.text_content.return_value = defer.succeed(
            'h={0}'.format(parsed['h']) + self.valid_response)
        self.deferreds.values()[0].callback(mock.MagicMock(code=200))
        self.assertEqual((parsed, "server1"), self.successResultOf(d))

    def test_verify_errors_if_otps_do_not_match(self):
        """
        If a response back from the server has a 'otp' that doesn't match
        the original otp, L{txyubikey.client.YubiKeyVerifier.verify} considers
        it an error.
        """
        self.treq.text_content.return_value = defer.succeed("otp=meh")

        d = self.client.verify(self.otp)
        self.deferreds.values()[0].callback(mock.MagicMock(code=200))
        f = self.failureResultOf(d)
        self.assertTrue(f.check(client.YubiKeyVerificationError))

    def test_verify_errors_if_nonces_do_not_match(self):
        """
        If a response back from the server has a 'nonce' that doesn't match
        the original nonce, L{txyubikey.client.YubiKeyVerifier.verify}
        considers it an error.
        """
        self.treq.text_content.return_value = defer.succeed("nonce=meh")

        d = self.client.verify(self.otp)
        self.deferreds.values()[0].callback(mock.MagicMock(code=200))
        f = self.failureResultOf(d)
        self.assertTrue(f.check(client.YubiKeyVerificationError))

    def test_verify_errors_if_response_signature_invalid(self):
        """
        If a response back from the server has a signature that ws not signed
        by the api key, L{txyubikey.client.YubiKeyVerifier.verify}
        considers it an error.
        """
        dictionary = {'otp': self.otp, 'nonce': self.nonce.return_value,
                      'status': 'ok'}
        dictionary['h'] = client.sign_query(dictionary, 'fake_key')
        self.treq.text_content.return_value = defer.succeed(
            "\r\n".join(["=".join(duo) for duo in dictionary.iteritems()]))

        self.client.api_key = 'real_key'.encode('base64')

        d = self.client.verify(self.otp)
        self.deferreds.values()[0].callback(mock.MagicMock(code=200))
        f = self.failureResultOf(d)
        self.assertTrue(f.check(client.YubiKeyVerificationError))

    def test_verify_returns_first_success(self):
        """
        L{txyubikey.client.YubiKeyVerifier.verify} returns the first successful
        result, even if the other results have not returned.
        """
        self.client.validation_servers = [str(i) for i in range(5)]
        d = self.client.verify(self.otp)
        ordered = [val for key, val in sorted(self.deferreds.iteritems(),
                                              key=(lambda duo: duo[0]))]

        ordered[2].callback(mock.MagicMock(code=200))
        ordered[0].callback(mock.MagicMock(code=200))

        result_dict, server = self.successResultOf(d)
        self.assertEqual(server, '2')

    def test_verify_ignores_all_errors_until_first_success(self):
        """
        Any server failure (server couldn't be reached, response format
        malformed) is ignored by L{txyubikey.client.YubiKeyVerifier.verify},
        which contains
        """
        self.client.validation_servers = [str(i) for i in range(5)]
        d = self.client.verify(self.otp)
        ordered = [val for key, val in sorted(self.deferreds.iteritems(),
                                              key=(lambda duo: duo[0]))]
        for i in range(4):
            ordered[i].errback(Exception('failed connection'))
        ordered[-1].callback(mock.MagicMock(code=200))

        response, server = self.successResultOf(d)
        self.assertEqual(server, '4')

    def test_verify_failure_if_all_fail(self):
        """
        If every server fails, L{txyubikey.client.YubiKeyVerifier.verify} fails
        also.
        """
        self.client.validation_servers = [str(i) for i in range(5)]
        d = self.client.verify(self.otp)
        ordered = [val for key, val in sorted(self.deferreds.iteritems(),
                                              key=(lambda duo: duo[0]))]
        for i in range(5):
            ordered[i].errback(Exception('failed connection'))

        f = self.failureResultOf(d)
        self.assertTrue(f.check(client.YubiKeyVerificationError))
