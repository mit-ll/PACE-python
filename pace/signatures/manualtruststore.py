## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Manual trust store for key lookup
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  24 Jun 2015  CS    Original file
## **************

from pace.signatures.vars import SIGNATURE_FUNCTIONS
from pace.pki.abstractpki import AbstractPKI, PKILookupError
from pace.signatures.signaturepki import SignatureMixin, SigTuple
from pace.signatures.acc_sig import KeyParseError

ACCEPTABLE_PREFIXES = ['-----BEGIN PUBLIC KEY-----\n',
                       '-----BEGIN RSA PUBLIC KEY-----\n',
                       '-----BEGIN ECDSA PUBLIC KEY-----\n']

ACCEPTABLE_SUFFIXES = ['-----END PUBLIC KEY-----\n',
                       '-----END RSA PUBLIC KEY-----\n',
                       '-----END ECDSA PUBLIC KEY-----\n']

class ManualTrustStore(AbstractPKI, SignatureMixin):
    """ Uses a manually populated file to provide a static list of users
        and their keys.
    """

    @staticmethod
    def _aggregate_pem_string(f):
        line = f.readline()

        if line not in ACCEPTABLE_PREFIXES:
            raise TrustStoreCreationException(
                'Public key improperly formatted: no BEGIN PUBLIC KEY line')

        pemstring = ''

        while line != '':
            pemstring += line
            line = f.readline()
            if line in ACCEPTABLE_SUFFIXES:
                pemstring += line
                return pemstring

        raise TrustStoreCreationException(
            'Public key improperly formatted: no END PUBLIC KEY line')

    def _parse_file(self, f):
        line = f.readline()
        while line != '':
            name = line.strip()
            alg = f.readline().strip()

            try:
                alg_fn = SIGNATURE_FUNCTIONS[alg]
            except KeyError:
                raise TrustStoreCreationException(
                    'Unknown signature algorithm ' + alg)

            pem_string = ManualTrustStore._aggregate_pem_string(f)

            try:
                pubkey = alg_fn.parse_key(pem_string)
            except KeyParseError as kpe:
                raise TrustStoreCreationException(kpe.msg)

            self.store[name] = (alg_fn, pubkey)
            
            line = f.readline()

    def __init__(self, path):
        self.store = {}
        try:
            with open(path, 'r') as f:
                self._parse_file(f)
        except IOError as e:
            raise TrustStoreCreationException(
                'Provided trust store file %s not readable; aborting' %path)

    def get_profile(self, name):
        try:
            fn, pubkey = self.store[name]
            return SigTuple(pubkey, fn.name)
        except KeyError:
            raise PKILookupError(
                'ERROR: User %s not found in trust store.' %name)

    @staticmethod
    def create_store_file(keys, path):
        """ Create a file that is parseable into a manual trust store
            from a dictionary of key mappings.

            Arguments:

            keys - a dictionary that maps user IDs to (algorithm, publickey)
                   tuples, where `algorithm` is an algorithm class as defined
                   in acc_sig.py, and `publickey` is a public key for that
                   signature algorithm.
            path - the path to write the trust store file to.

        """

        try:
            with open(path, 'w') as f:
                for userid, (alg_fn, pubkey) in keys.iteritems():
                    keystr = alg_fn.serialize_key(pubkey)
                    algstr = alg_fn.name
                    f.write(userid.strip() + '\n')
                    f.write(algstr.strip() + '\n')
                    f.write(keystr.strip() + '\n')
        except IOError:
            raise TrustStoreCreationException(
                'Could not open file %s for writing out a trust store.' %path)
                

class TrustStoreCreationException(Exception):
    def __init__(self, msg):
        self.msg = msg
