## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Verification code for accumulo clients
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Dec 2014  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import base64
import logging

from pace.signatures.vars import SIGNATURE_FUNCTIONS, MAX_ERROR_LEN
from pace.signatures.signconfig import VisibilityFieldConfig, VerificationException

from pace.signatures.signaturepki import SignatureMixin

class AccumuloVerifier(object):

    def __init__(self, get_key, conf=VisibilityFieldConfig()):
        """ Class for verifying Accumulo entries. Keeps track of various
            configuration options for signatures on this instance.

            Arguments:
            get_key - either a PKI instance (see pki.abstract_key_management.py)
                      or the public key to use to verify the signature.
            conf - The configuration object for the accumulo instance this
                   object will be verifying entries from
                   (Default: VisibilityFieldConfig(), which looks for signatures
                   in the visibility field)
        """
        self.get_key = get_key
        self.conf = conf


    def verify_entry(self, raw_entry, table=None):
        """ Verify that a single string was signed using the provided key.

            keyword arguments:
            raw_entry - the (un-decoded) entry in the table
            table - the name of the table the entry is in, if expecting the
                    table to be part of the signature, and None if the table
                    name was not included. Default: None.
            returns:
            The entry with the signature metadata parsed out.

            Raises VerificationException if the entry fails to verify.
        """

        entry, cell = self.conf._split_entry(raw_entry)

        if table is not None:
            cell_string = ','.join([table, entry.cell_string])
        else:
            cell_string = entry.cell_string

        if isinstance(self.get_key, SignatureMixin):
            key, signame = self.get_key.get_verifying_key(entry.metadata)
        else:
            key = self.get_key
            signame = entry.metadata

        try:
            sigf = SIGNATURE_FUNCTIONS[signame]
        except KeyError: 
            # didn't recognize signature algorithm, so failed to verify
            raise VerificationException(
                "unrecognized signing algorithm: " +
                entry.metadata[:MAX_ERROR_LEN], cell)
        
        sig = base64.b64decode(entry.sig)
        AccumuloVerifier._verify_signature(sig, cell_string, key, sigf, cell)

        return entry

    @staticmethod
    def _verify_signature(sig, data, key, sigf, cell):
        """ Verifies that the given signature comes from the right entity
            
            Input:
            sig - the signature to check
            data - the data to check against sig
            key - the public key to check the signature against
            sigf - the signing function to use
            cell - the metadata-less cell to return if there was an error

            Raises an exception with a string explaining the error if the
            signature fails to verify, and returns (no value) if the
            verification succeeds.
        """

        #verify the message
        verified = sigf.verify(data, sig, key)

        if not verified:
            raise VerificationException("Failed to verify the signature", cell)

    @staticmethod
    def _verify_signature_bool(sig, data, key, sigf, cell):
        """ Wrapper for _verify_signature that returns a boolean value rather
            than maybe raising an exception, throwing away any error message
            and cell returned in the failure case.
        """

        try:
            AccumuloVerifier._verify_signature(sig, data, key, sigf, cell)
        except VerificationException as ve:
            logging.debug("Error: " + ve.msg)
            return False

        return True


