## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Definitions for PKIs for signature creation/verification
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  29 Dec 2014  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from collections import namedtuple

from pace.pki.abstractpki import PKILookupError
from pace.signatures.vars import ALL_SIGNATURES

class SignatureMixin(object):
    """ Mixin to use for PKI implementations that support
        lookup of verifying keys and signature algorithms.
    """

    def get_verifying_key(self, identifier):
        """
        Arguments:
        identifier - unique to a single user that is used 
        to map between a user and their security profile, which 
        may take the form of an X509 certificate or something
        similiar
 
        Returns: 
        verifying_key - the verifying key of the user
        signature_scheme - the name of the signature algorithm
        used by the user, as a string.
        """

        profile = self.get_profile(identifier)
        return profile.verifying_key, profile.signature_scheme

# Bare minimum namedtuple class to satisfy the SignatureMixin mixin
SigTuple = namedtuple('SigTuple', 'verifying_key, signature_scheme')

class DummySignaturePKI(SignatureMixin):
    def __init__(self):
        self.signers = dict(
            (sc.name+'ID', (sc.test_keys()[0], sc.name))
            for sc in ALL_SIGNATURES)

    def get_profile(self, identifier):
        try:
            return SigTuple(*self.signers[identifier])
        except KeyError:
            raise PKILookupError('ERROR: identifier %s not found' %identifier)

