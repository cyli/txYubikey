from __future__ import print_function

import json

from twisted.internet import reactor
from twisted.python import log

from txyubikey.client import YubiKeyVerifier


def print_result(result):
    blob, server = result
    print("Got result from {0}".format(server))
    print(json.dumps(blob, sort_keys=True, indent=4))


def run_verification(verifier):
    incoming = raw_input("OTP ('q' to quit): ")
    if incoming.strip().lower() == 'q':
        reactor.stop()
        return

    d = verifier.verify(incoming)
    d.addCallback(print_result)
    d.addErrback(print)
    d.addBoth(lambda _: reactor.callLater(0, run_verification, verifier))
    return d


if __name__ == "__main__":
    with open('apikey.json', 'rb') as f:
        config = json.load(f, 'ascii')

    api_key = config.get('secretKey', None)
    if api_key:
        api_key = api_key.encode("ASCII")

    verifier = YubiKeyVerifier(config['clientId'], api_key, logger=log)

    run_verification(verifier)

    reactor.run()
