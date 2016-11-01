## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ES
##  Description: Key wrapping and unwrapping
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  15 July 2015  ES    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def wrap_key(sk, RSA_pk):
    """ Generates a keywrap.

        Arguments:
        sk (string) - the key to be encrypted
        RSA_pk (_RSAobj) - the user's RSA public key
       
        Returns:
        A string, an RSA-OAEP encryption of key `sk' under public key `RSA_pk'
    """

    cipher = PKCS1_OAEP.new(RSA_pk)
    return cipher.encrypt(sk)

def unwrap_key(keywrap, RSA_sk):
    """ Unwraps a keywrap.

        Arguments:
        keywrap (string) - the wrapped key
        RSA_sk (_RSAobj) - the user's RSA private key

        Returns:
        A string, the RSA-OAEP decryption of `keywrap' under private key 
        `RSA_sk'
    """

    cipher = PKCS1_OAEP.new(RSA_sk)
    return cipher.decrypt(keywrap)
