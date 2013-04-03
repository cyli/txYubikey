from zope.interface import Attribute, implementer

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import (
    ICredentials, IUsernamePassword, UsernamePassword)
from twisted.cred.error import UnauthorizedLogin


class ICapabilityAuth(ICredentials):
    """
    This credential represents a single token/string/hash that itself, if
    valid, grants authentication.
    """
    capability = Attribute(
        "The capability which itself, if valid, grants authentication.")


@implementer(ICapabilityAuth)
class CapabilityAuth(object):
    """
    Implementation of L{ICapabilityAuth}
    """
    def __init__(self, capability):
        self.capability = capability


@implementer(ICredentialsChecker)
class YubiKeyAuth(object):
    """
    YubiKey credentials checker that returns the YubiKey ID as the avatar ID
    if the OTP is valid

    @ivar verifier: L{txyubikey.client.YubiKeyVerifier}

    @ivar timestamp: see args to L{txyubikey.client.YubiKeyVerifier.verify}
    @ivar sl: see args to L{txyubikey.client.YubiKeyVerifier.verify}
    @ivar timeout: see args to L{txyubikey.client.YubiKeyVerifier.verify}
    """
    credentialInterface = (ICapabilityAuth,)

    def __init__(self, verifier, timestamp=None, sl=None, timeout=None):
        self.verifier = verifier
        self.timestamp = timestamp
        self.sl = sl
        self.timeout = timeout

    def requestAvatarId(self, credentials):
        """
        @param credentials: a L{ICapabilityAuth} provider for which the
            C{credentials.capability} is a YubiKey OTP

        @return: a L{twisted.internet.defer.Deferred} which will fire with the
            YubiKey ID if the OTP is valid, or errback with an
            C{UnauthorizedLogin} if it is not

        @see: L{twisted.cred.credentials}
        """
        def _normalize_failure(failure):
            raise UnauthorizedLogin()

        return (self.verifier.verify(credentials.capability,
                                     timestamp=self.timestamp,
                                     sl=self.sl, timeout=self.timeout)
                .addErrback(_normalize_failure))


@implementer(ICredentialsChecker)
class YubiKeyOneFactorAuth(object):
    """
    A wrapper for another L{IUsernamePassword} checker and a L{YubiKeyAuth}.
    The password should be the YubiKey OTP, and will be authenticated by
    the L{YubiKeyAuth}.  The YubiKey ID that gets returned will be checked as
    the password along with the username by the L{IUsernamePassword} checker.

    @ivar yubikeyauth: an instance of L{YubiKeyAuth}
    @ivar usernamepassword: an instance of a L{IUsernamePassword} checker
    """
    credentialInterfaces = (IUsernamePassword,)

    def __init__(self, yubikeyauth, usernamepassword):
        self.yubikeyauth = yubikeyauth
        self.usernamepassword = usernamepassword

    def requestAvatarId(self, credentials):
        """
        @param credentials: a L{IUsernamePassword} provider

        @return: a Deferred which will fire with a username returned by the
            L{IUsernamePassword} checker or fire a Failure(UnauthorizedLogin).

        @see: L{twisted.cred.credentials}
        """
        def _construct_username_password(password):
            return UsernamePassword(credentials.username, password)

        capability = CapabilityAuth(credentials.password)

        return (self.yubikeyauth.requestAvatarId(capability)
                .addCallback(_construct_username_password)
                .addCallback(self.usernamepassword.requestAvatarId))
