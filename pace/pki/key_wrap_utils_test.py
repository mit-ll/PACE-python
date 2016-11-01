## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ES
##  Description: Key wrapping and unwrapping tests
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  20 July 2015 ES   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import time
import random

from Crypto.PublicKey import RSA
from pace.pki.key_wrap_utils import wrap_key, unwrap_key
from pace.common.pacetest import PACETestCase

class KeyWrapUtilsTests(PACETestCase):
    
    def setUp(self):
        random.seed(int(time.time()))

    def test_valid_enc_dec(self):
        """ Check that we can unwrap a key using the private key 
            corresponding to the public key used to wrap the key.
        """
        RSA_key = RSA.generate(3072)
        RSA_pk = RSA_key.publickey()
        for i in range(self.num_iters):
            sk = format(random.getrandbits(128), 'b')
            keywrap = wrap_key(sk, RSA_pk)
            try:
                decrypted_key = unwrap_key(keywrap, RSA_key)
            except ValueError as e:
                self.assertTrue(False, 'Error: %s' %e.msg)
            else:
                self.assertEqual(decrypted_key, sk, 
                                 'Failed to unwrap original key')

    def test_invalid_enc_dec(self):
        """ Check that we cannot unwrap a key using a private key that does
            not correspond to the public key used to wrap the key.
        """
        RSA_key = RSA.generate(3072)
        RSA_pk = RSA_key.publickey()
        for i in range(self.num_iters):
            sk = format(random.getrandbits(128), 'b')
            keywrap = wrap_key(sk, RSA_pk)
            other_key = RSA.generate(3072)
            try:
                decrypted_key = unwrap_key(keywrap, other_key)
            except ValueError:
                self.assertTrue(True, 'error')
            else:
                self.assertNotEqual(decrypted_key, sk,
                                    'Decryption succeeded with invalid key')
    
