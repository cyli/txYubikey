"""
Client that verifies a Yubico OTP against a validation server.

Only the v2 protocol is supported (see
https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20)
"""
from cStringIO import StringIO
from hashlib import sha1
import hmac
import re
from urllib import urlencode
from urlparse import urlunsplit
from uuid import uuid4

from twisted.internet.defer import Deferred, DeferredList, fail
from twisted.internet.protocol import Protocol


_otp_re = re.compile("^\S{32,48}$")
_nonce_re = re.compile("^\w{16,40}$")


class _BodyReader(Protocol):
    def __init__(self, deferred):
        self.deferred = deferred
        self.buffer = StringIO()

    def dataReceived(self, data):
        self.buffer.write(data)

    def connectionLost(self, reason):
        self.deferred.callback(self.buffer.getvalue())


def generate_nonce():
    """
    A method to generate a nonce to send to the validation server.  As
    specified by the protocol, the nonce must be between 16 and 40
    alphanumeric characters long with random unique data.

    @returns: a random C{str} nonce between 16 and 40 characters long
    """
    return uuid4().hex


class YubiKeyVerificationError(Exception):
    """
    Error to be raised when the YubiKey fails to validate.
    """


class YubiKeyVerifier(object):
    """
    An object that can be used to verify YubiKey OTP's.  For more
    information, please see:

    1. https://code.google.com/p/yubikey-val-server-php/wiki/GettingStartedWritingClients

    2. https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20

    3. http://www.yubico.com/develop/open-source-software/web-api-clients/server/

    @ivar agent: The agent to use to verify against the validation server.
        Note that if the agent does not validate ssl certificates, the api key
        really should be provided so that requests are response signatures are
        validated.
    @type agent: L{twisted.web.client.Agent} or a L{twisted.web.client.Agent}
        wrapper

    @ivar verifier_id: Specifies the requestor so that the end-point can
        retrieve correct shared secret for signing the response.
    @type verifier_id: C{str}

    @ivar api_key: The API key that will be used to sign the request and
        the response (if given)
    @type api_key: C{str} or C{None}

    @ivar nonce_generator: a callabale that generates a nonce - if not
        provided defaults to L{generate_nonce}.  The generator must produces
        nonces that are alphanumeric and be between 16 and 40 characters long.
    @type nonce_generator: C{callable}

    @ivar validation_servers: a list of network locations to one or more
        validation servers - if none are provided, the Yubico validation
        servers are used (api.yubico.com, api2.yubico.com, api3.yubico.com,
        api4.yubico.com, and api5.yubico.com)
    @type validation_servers: C{iterable}

    @ivar scheme: "http" or "https" - defaults to 'https'
    @type scheme: C{str}
    """
    def __init__(self, agent, verifier_id, api_key=None, nonce_generator=None,
                 validation_servers=None, scheme="https"):
        self.agent = agent
        self.verifier_id = verifier_id
        self.api_key = api_key.decode('base64')
        self.scheme = scheme

        self.generate_nonce = nonce_generator
        if nonce_generator is None:
            self.generate_nonce = generate_nonce

        self.validation_servers = validation_servers
        if validation_servers is None:
            self.validation_servers = (
                'api.yubico.com', 'api2.yubico.com', 'api3.yubico.com',
                'api4.yubico.com', 'api5.yubico.com')

    def _maybe_sign_query(self, query_dict):
        """
        From: https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20

        The protocol uses HMAC-SHA-1 signatures. The HMAC key to use is the
        client API key.

        Generate the signature over the parameters in the message. Each
        message contains a set of key/value pairs, and the signature is always
        over the entire set (excluding the signature itself), and sorted in
        alphabetical order of the keys. More precisely, to generate a message
        signature do:

        Alphabetically sort the set of key/value pairs by key order.

        Construct a single line with each ordered key/value pair concatenated
        using '&', and each key and value contatenated with '='. Do not add
        any linebreaks. Do not add whitespace. For example: `a=2&b=1&c=3`.
        Apply the HMAC-SHA-1 algorithm on the line as an octet string using
        the API key as key.

        Base 64 encode the resulting value according to RFC 4648, for example,
        `t2ZMtKeValdA+H0jVpj3LIichn4=`. Append the value under key 'h' to the
        message.

        @param query_dict: C{dict} of query keys and values to maybe sign. If
            C{self.api_key} is not C{None}, then the signature will be added to
            the dictionary under the key name C{h}

        @return: C{None}
        """
        if self.api_key is not None:
            if 'h' in query_dict:
                del query_dict['h']

            sorted_pairs = sorted(query_dict.iteritems(),
                                  key=(lambda duo: duo[0]))
            unsigned_message = "&".join(["=".join(p) for p in sorted_pairs])
            hmac_obj = hmac.new(self.api_key, unsigned_message, sha1)
            query_dict['h'] = hmac_obj.digest().encode('base64')

    def _verify_response(self, response, orig_otp, orig_nonce):
        """
        Check that the response is a valid response to our request - that is,
        the otp that was returned is the otp we sent originally, that the
        nonce that was sent was the nonce we had originally, and that the
        signature (if C{self.api_key} is not C{None}) is valid

        The response looks like:

        otp=....\r\n
        h=...\r\n ...
        """
        response_dict = dict([line.strip().split('=', 1) for line in
                              response.split('\n') if line.strip('\r')])

        if 'otp' in response_dict and response_dict['otp'] != orig_otp:
            raise YubiKeyVerificationError(
                "Received response that does not match the OTP that was "
                "sent to be verified.")

        if 'nonce' in response_dict and response_dict['nonce'] != orig_nonce:
            raise YubiKeyVerificationError(
                "Received response that does not match the OTP that was "
                "sent to be verified.")

        signature = response_dict['h']

        self._maybe_sign_query(response_dict)

        if signature.decode('base64') != response_dict['h'].decode('base64'):
            raise YubiKeyVerificationError(
                "Received a response whose signature is invalid")

        return response_dict

    def _query_server(self, netloc, query_dict, query_string=None):
        """
        Hit a validation server URl and attempt to get a response.
        """
        def _check_for_200(response):
            if response.code != 200:
                raise Exception(str(response.code))
            return response

        def _deliver_response(response):
            deferred = Deferred()
            response.deliverBody(_BodyReader(deferred))
            return deferred

        if query_string is None:
            query_string = urlencode(query_dict)

        url = urlunsplit((self.scheme, netloc, 'wsapi/2.0/verify',
                         query_string, ''))
        d = self.agent.request('GET', url)
        d.addCallback(_check_for_200)
        d.addCallback(_deliver_response)
        d.addCallback(self._verify_response, query_dict['otp'],
                      query_dict['nonce'])
        return d

    def _request_from_all_servers(self, query_dict):
        """
        From: http://www.yubico.com/develop/open-source-software/web-api-clients/server/

        Yubico now operates multiple validation servers in different
        geographical locations. Clients will query all servers in parallel and
        wait for answers. Servers will not respond positively until it has
        synchronized the new OTP counter with the other servers, and the
        client will wait until it has received one positive response (i.e.,
        OTP is valid) or until it has received one negative response (i.e.,
        OTP is replayed).

        @param query_dict: C{dict} of query keys and values
        """
        query_string = urlencode(query_dict)

        deferred_list = [
            self._query_server(netloc, query_dict, query_string=query_string)
            for netloc in self.validation_servers]

        def _check_results(results):
            """
            See if validation failed
            """
            if isinstance(results, list):
                # this means that none of the requests succeeded, since
                # otherwise the result would be a two-tuple
                for i, one_result in enumerate(results):
                    print '{0}: {1}'.format(
                        self.validation_servers[i],
                        str(one_result[1]))
                    deferred_list[i].addErrback(lambda _: None)

                raise YubiKeyVerificationError(
                    "Could not successfully GET from any of the validation "
                    "servers.")

            # results must be a two-tuple
            blob, index = results
            return (blob, self.validation_servers[index])

        # TODO: do something about the giant stack of errors
        d = DeferredList(deferred_list, fireOnOneCallback=True)
        return d.addCallback(_check_results)

    def verify(self, otp, timestamp=None, sl=None, timeout=None):
        """
        Verifies an OTP against the validation servers provided to the
        verifier.

        It queries all servers in parallel and waits for answers. Servers will
        not respond positively until it has synchronized the new OTP counter
        with the other servers, and this will wait until it has received one
        valid (200, otp and nonce match, and signature is correct) response,
        positive (i.e., OTP is valid) or negative (i.e., OTP is replayed).

        Note that signature validation errors may occur, due to implementation
        details on the Yubico validation servers, if invalid parameters
        are passed - e.g. if an OTP is provided one whose characters are
        outside the ModHex alphabet).

        See https://github.com/Yubico/yubikey-val/issues/8

        @param otp: The OTP from the YubiKey.
        @type otp: C{str}

        @param timestamp: Whether to request timestamp and session counter
            information the response.  If not provided, lets the server decide.
        @type timestamp: C{boolean} or C{None}

        @param sl: A value 0 to 100 indicating percentage of syncing required
            by client, or strings "fast" or "secure" to use server-configured
            values; if None, let the server decide.  Defaults to None.  If
            provided, will be coerced to an int between 0 and 100.
        @type sl: C{int} or C{None}

        @param timeout: Number of seconds to wait for sync responses; if None,
            let the server decide. Defaults to None.  If provided, will be
            coerced to an int.
        @type timeout: C{int} or C{None}

        @return: L{twisted.internet.defer.Deferred} that fires with a C{tuple}
            of the positive (status == 'OK') or negative (status != 'OK')
            response JSON from the validation server, and the
            validation server the response came from.

        @raises: A L{YubiKeyVerificationError} failure if unsuccessful (not
            that the OTP was rejected, but that a failure occured during
            validation)
        """

        query_dict = {
            'id': self.verifier_id,
            'otp': otp,
            'nonce': self.generate_nonce()
        }

        if timestamp is not None:
            query_dict['timestamp'] = int(bool(timestamp))
        if sl is not None:
            query_dict['sl'] = max(0, min(100, int(sl)))
        if timeout is not None:
            query_dict['timeout'] = int(timeout)

        if _otp_re.search(otp) is None:
            return fail(YubiKeyVerificationError(
                "OTP needs to be between 32 and 48 characters long"))

        if _nonce_re.search(query_dict['nonce']) is None:
            return fail(YubiKeyVerificationError(
                "Nonce generator produced an invalid nonce"))

        self._maybe_sign_query(query_dict)
        return self._request_from_all_servers(query_dict)
