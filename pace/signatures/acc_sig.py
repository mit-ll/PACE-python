## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Classes for various signature algorithms
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   9 Jul 2014  ZS    Original file
## **************

from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from pycryptopp.publickey import ecdsa
from pycryptopp.publickey import ed25519

from hashlib import sha256
from abc import ABCMeta, abstractmethod

import hmac
import os
import logging
import base64


class AbstractAccSig(object):
    """ Defines the interface for accumulo code to sign data and
        verify signatures. This is needed because the PyCrypt
        library's interface is not shared by all cryptographic
        libraries, nor is it the most intuitive interface.
    """

    __metaclass__ = ABCMeta

    name = ''

    @abstractmethod
    def sign(msg, privkey):
        """ Input:
            msg - the message to sign
            privkey - the private key of the corresponding crypto algorithm

            Returns:
            The result of signing msg with privkey.
        """
        pass

    @abstractmethod
    def verify(msg, signature, pubkey):
        """ Input:
            msg - the message to verify the signature of
            signature - the signature to test against msg
            pubkey - a public key of the corresponding crypto algorithm

            Returns:
            True if signature verifies against msg with pubkey,
            False otherwise
        """
        pass


    @abstractmethod
    def test_keys():
        """ Returns:
            test_pubkey: the public key to use for testing
            test_privkey: the private key to use for testing
        """
        pass

    @classmethod
    def parse_key(cls, s):
        """ Parse a key string into its internal representation.
            By default, this is not implemented and raises an exception.
            
            Input:

            s: the ASCII string to parse the key from, including header
               and footer.

            Returns:
            The corresponding public key.
        """

        raise NotImplementedError(
            'ERROR: parse_key() not implemented for class %s' %cls.name)

    @classmethod
    def serialize_key(cls, key):
        """ Serialize a key into a string to store in a file.
            By default, this is not implemented and raises an exception.
            
            Input:

            key: the key to create the key from.

            Returns:
            A string representation of the key, including header and footer.

            Raises:
            KeyParseError, if the key cannot be parsed
            NotImplementedError, if this is not implemented for the
                class calling it
        """

        raise NotImplementedError(
            'ERROR: serialize_key() not implemented for class %s' %cls.name)

class KeyParseError(Exception):
    def __init__(self, msg):
        self.msg = msg

class PKCS1_PSS_AccSig(AbstractAccSig):
    """ AccSig for PKCS1_PSS (RSA signatures)
    """

    name = 'RSASSA-PSS'

    @staticmethod
    def sign(msg, privkey):
        signer = PKCS1_PSS.new(privkey)
        return signer.sign(SHA256.new(msg))

    @staticmethod
    def verify(msg, signature, pubkey):
        verifier = PKCS1_PSS.new(pubkey)
        return verifier.verify(SHA256.new(msg), signature)

    @staticmethod
    def test_keys():
        with open(os.path.dirname(os.path.realpath(__file__)) + 
                  '/keys/test_pubkey_3072.rsa') as pubkey:
            with open(os.path.dirname(os.path.realpath(__file__)) + 
                      '/keys/test_privkey_3072.rsa') as privkey:
                test_pubkey = RSA.importKey(pubkey.read())
                test_privkey = RSA.importKey(privkey.read())

        return test_pubkey, test_privkey

    @staticmethod
    def parse_key(s):
        try:
            return RSA.importKey(s)
        except ValueError:
            raise KeyParseError('Problem parsing RSASSA-PSS key')

    @staticmethod
    def serialize_key(key):
        return key.exportKey()

class PKCS1_v1_5_AccSig(AbstractAccSig):
    """ AccSig for PKCS1_v1_5 (RSA signatures)
    """

    name = 'RSASSA_PKCS1-v1_5'

    @staticmethod
    def sign(msg, privkey):
        signer = PKCS1_v1_5.new(privkey)
        return signer.sign(SHA256.new(msg))

    @staticmethod
    def verify(msg, signature, pubkey):
        verifier = PKCS1_v1_5.new(pubkey)
        return verifier.verify(SHA256.new(msg), signature)

    @staticmethod
    def test_keys():
        with open(os.path.dirname(os.path.realpath(__file__)) +
                  '/keys/test_pubkey_3072.rsa') as pubkey:
            with open(os.path.dirname(os.path.realpath(__file__)) +
                      '/keys/test_privkey_3072.rsa') as privkey:
                test_pubkey = RSA.importKey(pubkey.read())
                test_privkey = RSA.importKey(privkey.read())

        return test_pubkey, test_privkey
        
    @staticmethod
    def parse_key(s):
        try:
            return RSA.importKey(s)
        except ValueError:
            raise KeyParseError('Problem parsing RSASSA_PKCS1-v1_5 key')

    @staticmethod
    def serialize_key(key):
        return key.exportKey()


class PyCryptopp_ECDSA_AccSig(AbstractAccSig):
    """ AccSig for elliptic curve cryptography signatures, using the
        ecdsa module. Uses 256-bit signing keys.
    """

    name = 'PyCryptopp_ECDSA'

    @staticmethod
    def sign(msg, privkey):
        return privkey.sign(SHA256.new(msg).digest())

    @staticmethod
    def verify(msg, signature, pubkey):
        return pubkey.verify(SHA256.new(msg).digest(), signature)

    @staticmethod
    def test_keys():
        test_privkey = ecdsa.SigningKey("testseedtestseedtestseedtestseed")
        test_pubkey = test_privkey.get_verifying_key()
        return test_pubkey, test_privkey

    @staticmethod
    def parse_key(s):
        lines = s.split('\n')
        keystr64 = ''.join(lines[1:-2])

        try:
            keystr = base64.b64decode(keystr64)
        except TypeError:
            raise KeyParseError('Error decoding base64 keystring for ECDSA key')

        try:
            return ecdsa.VerifyingKey(keystr)
        except ecdsa.Error:
            raise KeyParseError('Error parsing ECDSA key')

    @staticmethod
    def serialize_key(key):
        ser = key.serialize()
        ser64 = base64.b64encode(ser)
        return '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' %ser64


class Symmetric_HMAC_SHA256_AccSig(AbstractAccSig):
    """ AccSig for symmetric key MACs (not asymmetric signatures).
        
        Using symmetric key crypto requires different trust assumptions
        (namely, that all clients have a shared secret that the server does
        not know about), but empirically runs 2-3 orders of magnitude
        faster than the public key algorithms. See hybrid/prelim.py for
        benchmarks comparing it to PyCrypto++'s ECDSA implementation.
    """

    name = 'HMAC-SHA256'

    @staticmethod
    def sign(msg, privkey):
        return hmac.new(privkey, msg, sha256).digest()

    @staticmethod
    def verify(msg, signature, pubkey):
        return signature == hmac.new(pubkey, msg, sha256).digest()

    @staticmethod
    def test_keys():
        key = b'thisisathirtytwobytestringtotest'
        return key, key
