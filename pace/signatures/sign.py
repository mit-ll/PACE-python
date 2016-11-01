## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Signature code for accumulo clients
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Jun 2014  ZS    Original file
## **************
""" This module implements cell signatures for Accumulo. These functions allow 
    a user to sign entries before ingestion and to verify the signatures at
    read time. The signature is stored at the end of the column visibility
    field.
"""

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import base64
import logging

from pace.signatures.acc_sig import PyCryptopp_ECDSA_AccSig
from pace.signatures.vars import SIGNATURE_FUNCTIONS, MAX_ERROR_LEN
from pace.signatures.signconfig import VisibilityFieldConfig

class AccumuloSigner:
    """ Class for signing accumulo entries. Keeps track of various constants
        (private key, signature functions, max error length).
    """

    def __init__(self,
                 privkey,
                 sig_f=PyCryptopp_ECDSA_AccSig,
                 default_visibility='default',
                 signerID=None,
                 conf=VisibilityFieldConfig()):
        """ Arguments:

            self - the object to be initialized
            privkey - the private key to use to sign entries
            sig_f - the signature function to use (default: ECDSA)
            default_visibility - the value to use in the visibility field in
                                 the case where the visibility field was
                                 originally empty (default: 'default')
            signerID - the string representing the entity signing this batch,
                       or None if no such string is to be added (default: None)
            conf - a configuration object (as defined in signconfig.py)
                   specifying various properties of the signature (default:
                   VisibilityFieldConfig(), which stores the signature in
                   the visibility field)
        """

        self.privkey = privkey
        self.sig_f = sig_f
        self.default_visibility = default_visibility
        self.signerID = signerID
        self.conf = conf

    def sign_mutation(self, mutation, table=None):
        """ Sign all entries for a mutation

            keyword arguments:
            mutation - an Accumulo mutation object with some number of entries
            table - the table the mutation is part of, if signing the mutation
                    with the table name, and None otherwise. Default: None
        """
        # If the signer has an ID string they want to keep track of, make sure
        # to write it.
        if self.signerID:
            base_metadata = self.signerID
        else:
            base_metadata = self.sig_f.name

        #iterate through all entries in the mutation
        for u in mutation.updates:
            # Add a visibility field if one does not already exist, and parenthesize it to
            # make sure Accumulo will be able to parse the result. (e.g. if visibility was A&B,
            # need to make the new one (A&B)|<metadata>, since A&B|<metadata> is ambiguous)
            if not u.colVisibility:
                vis = '(' + self.default_visibility + ')'
                u.colVisibility = vis
            else:
                vis = '(' + u.colVisibility + ')'
                u.colVisibility = vis
            entry_tup = (mutation.row, u.colFamily, u.colQualifier, vis,
                         u.deleteCell, u.value)
            cell_string = str(entry_tup)

            if table is not None:
                cell_string = ','.join([table, cell_string])
                
            encoded = self.sign_entry(cell_string)

            self.conf._add_signature(mutation, u, base_metadata, encoded)

    
    def sign_entry(self, cell_string):
        """ Sign a single string.

            keyword arguments:
            cell_string - the message to sign, as a string

            returns:
            sig - the signature as a python string encoded in base 64
        """
        try:
            encoded = self.sign_data(cell_string)
        except ValueError:
            raise SigningException(
                    "The RSA key length is not sufficient for provided hash \
                    algorithm.")
        except TypeError:
            raise SigningException("The RSA key has no private half.")

        return base64.b64encode(encoded)

    def sign_data(self, data):
        """ Signs some data with the object's private key
            
            Input:
            data - the data to be signed

            Returns the signature of the data by self
        """
        #TODO: inline this, or figure out how to make sure python does it for us
        
        #sign the message
        return self.sig_f.sign(data, self.privkey)

class SigningException(Exception):
    """ Exception raised when unable to verify a signature.
        
        Attributes:
            msg - error message associated with the failure
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg
