## **************
##  Copyright 2016 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ES
##  Description: Test vectors for PACE pycrypto implementation of AES modes of 
##  operation: CBC, CFB, OFB, and CTR. Test vectors are from NIST SP 800-38A.
##  CBC tests do not test the padding scheme; test plaintexts are whole blocks.
##  Test vectors for GCM and SIV are not included. For GCM, the test vectors 
##  available in NIST's ``The Galois/Counter Mode of Operation'' document are 
##  not applicable because their IVs are not 128 bits, while pycrypto 
##  requires IVs to be 128 bits. For SIV, the test vectors available in RFC 5297
##  include ``associated data'' input, which is not supported by pycrypto's 
##  implementation.
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Jan 2016  ES    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from binascii import unhexlify

from pace.common.pacetest import PACETestCase
from pace.encryption.AES_encrypt import Pycrypto_AES_CFB, Pycrypto_AES_CBC, \
    Pycrypto_AES_OFB, Pycrypto_AES_CTR

KEY_128 = unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
KEY_192 = unhexlify('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b')
KEY_256 = unhexlify('603deb1015ca71be2b73aef0857d7781'+
                    '1f352c073b6108d72d9810a30914dff4')
PLAINTEXT = unhexlify('6bc1bee22e409f96e93d7e117393172a' +
                      'ae2d8a571e03ac9c9eb76fac45af8e51' +
                      '30c81c46a35ce411e5fbc1191a0a52ef' +
                      'f69f2445df4f9b17ad2b417be66c3710')
IV = unhexlify('000102030405060708090a0b0c0d0e0f')
INIT_COUNTER = unhexlify('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')

class AESTests(PACETestCase):

    def test_CBC_AES128(self):
        expected_ct = unhexlify('7649abac8119b246cee98e9b12e9197d' + 
                                '5086cb9b507219ee95db113a917678b2' + 
                                '73bed6b8e3c1743b7116e69e22229516' + 
                                '3ff1caa1681fac09120eca307586e1a7')
        actual_ct = Pycrypto_AES_CBC._encrypt(PLAINTEXT, KEY_128, IV)
        self.assertEqual(IV + expected_ct, actual_ct[:-16])

        #test decrypt
        actual_pt = Pycrypto_AES_CBC._decrypt(actual_ct, KEY_128)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_CBC_AES192(self):
        expected_ct = unhexlify('4f021db243bc633d7178183a9fa071e8' +
                                'b4d9ada9ad7dedf4e5e738763f69145a' +
                                '571b242012fb7ae07fa9baac3df102e0' +
                                '08b0e27988598881d920a9e64f5615cd')
        actual_ct = Pycrypto_AES_CBC._encrypt(PLAINTEXT, KEY_192, IV)
        self.assertEqual(IV + expected_ct, actual_ct[:-16])

        #test decrypt
        actual_pt = Pycrypto_AES_CBC._decrypt(actual_ct, KEY_192)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_CBC_AES256(self):
        expected_ct = unhexlify('f58c4c04d6e5f1ba779eabfb5f7bfbd6' + 
                                '9cfc4e967edb808d679f777bc6702c7d' + 
                                '39f23369a9d9bacfa530e26304231461' +
                                'b2eb05e2c39be9fcda6c19078c6a9d1b')
        actual_ct = Pycrypto_AES_CBC._encrypt(PLAINTEXT, KEY_256, IV)
        self.assertEqual(IV + expected_ct, actual_ct[:-16])

        #test decrypt
        actual_pt = Pycrypto_AES_CBC._decrypt(actual_ct, KEY_256)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_OFB_AES128(self):
        #test encrypt
        expected_ct = unhexlify('3b3fd92eb72dad20333449f8e83cfb4a'+
                                '7789508d16918f03f53c52dac54ed825'+
                                '9740051e9c5fecf64344f7a82260edcc'+
                                '304c6528f659c77866a510d9c1d6ae5e')
        actual_ct = Pycrypto_AES_OFB._encrypt(PLAINTEXT, KEY_128, IV)
        self.assertEqual(IV + expected_ct, actual_ct)
        
        #test decrypt
        actual_pt = Pycrypto_AES_OFB._decrypt(actual_ct, KEY_128)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_OFB_AES192(self):
        #test encrypt
        expected_ct = unhexlify('cdc80d6fddf18cab34c25909c99a4174'+
                                'fcc28b8d4c63837c09e81700c1100401'+
                                '8d9a9aeac0f6596f559c6d4daf59a5f2'+
                                '6d9f200857ca6c3e9cac524bd9acc92a')
        actual_ct = Pycrypto_AES_OFB._encrypt(PLAINTEXT, KEY_192, IV)
        self.assertEqual(IV + expected_ct, actual_ct)
        
        #test decrypt
        actual_pt = Pycrypto_AES_OFB._decrypt(actual_ct, KEY_192)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_OFB_AES256(self):
        #test encrypt
        expected_ct = unhexlify('dc7e84bfda79164b7ecd8486985d3860'+
                                '4febdc6740d20b3ac88f6ad82a4fb08d'+
                                '71ab47a086e86eedf39d1c5bba97c408'+
                                '0126141d67f37be8538f5a8be740e484')
        actual_ct = Pycrypto_AES_OFB._encrypt(PLAINTEXT, KEY_256, IV)
        self.assertEqual(IV + expected_ct, actual_ct)
        
        #test decrypt
        actual_pt = Pycrypto_AES_OFB._decrypt(actual_ct, KEY_256)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_CTR_AES128(self):
        #test encrypt
        expected_ct = unhexlify('874d6191b620e3261bef6864990db6ce'+
                                '9806f66b7970fdff8617187bb9fffdff'+
                                '5ae4df3edbd5d35e5b4f09020db03eab'+
                                '1e031dda2fbe03d1792170a0f3009cee')
        actual_ct = Pycrypto_AES_CTR._encrypt(PLAINTEXT, KEY_128, INIT_COUNTER)
        self.assertEqual(str(INIT_COUNTER) + expected_ct, actual_ct)
        
        #test decrypt
        actual_pt = Pycrypto_AES_CTR._decrypt(actual_ct, KEY_128)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_CTR_AES192(self):
        #test encrypt
        expected_ct = unhexlify('1abc932417521ca24f2b0459fe7e6e0b'+
                                '090339ec0aa6faefd5ccc2c6f4ce8e94'+
                                '1e36b26bd1ebc670d1bd1d665620abf7'+
                                '4f78a7f6d29809585a97daec58c6b050')
        actual_ct = Pycrypto_AES_CTR._encrypt(PLAINTEXT, KEY_192, INIT_COUNTER)
        self.assertEqual(str(INIT_COUNTER) + expected_ct, actual_ct)
        
        #test decrypt
        actual_pt = Pycrypto_AES_CTR._decrypt(actual_ct, KEY_192)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_CTR_AES256(self):
        #test encrypt
        expected_ct = unhexlify('601ec313775789a5b7a7f504bbf3d228'+
                                'f443e3ca4d62b59aca84e990cacaf5c5'+
                                '2b0930daa23de94ce87017ba2d84988d'+
                                'dfc9c58db67aada613c2dd08457941a6')
        actual_ct = Pycrypto_AES_CTR._encrypt(PLAINTEXT, KEY_256, INIT_COUNTER)
        self.assertEqual(str(INIT_COUNTER) + expected_ct, actual_ct)
        
        #test decrypt
        actual_pt = Pycrypto_AES_CTR._decrypt(actual_ct, KEY_256)
        self.assertEqual(PLAINTEXT, actual_pt)

    def test_CFB8_AES128(self):
        #test encrypt
        plaintext = PLAINTEXT[:18]
        expected_ct = unhexlify('3b79424c9c0dd436bace9e0ed4586a4f32b9')
        actual_ct = Pycrypto_AES_CFB._encrypt(plaintext, KEY_128, IV)
        self.assertEqual(IV + expected_ct, actual_ct)

        #test decrypt
        actual_pt = Pycrypto_AES_CFB._decrypt(actual_ct, KEY_128)
        self.assertEqual(plaintext, actual_pt)

    def test_CFB8_AES192(self):
        #test encrypt
        plaintext = PLAINTEXT[:18]
        expected_ct = unhexlify('cda2521ef0a905ca44cd057cbf0d47a0678a')
        actual_ct = Pycrypto_AES_CFB._encrypt(plaintext, KEY_192, IV)
        self.assertEqual(IV + expected_ct, actual_ct)

        #test decrypt
        actual_pt = Pycrypto_AES_CFB._decrypt(actual_ct, KEY_192)
        self.assertEqual(plaintext, actual_pt)

    def test_CFB8_AES256(self):
        #test encrypt
        plaintext = PLAINTEXT[:18]
        expected_ct = unhexlify('dc1f1a8520a64db55fcc8ac554844e889700')
        actual_ct = Pycrypto_AES_CFB._encrypt(plaintext, KEY_256, IV)
        self.assertEqual(IV + expected_ct, actual_ct)

        #test decrypt
        actual_pt = Pycrypto_AES_CFB._decrypt(actual_ct, KEY_256)
        self.assertEqual(plaintext, actual_pt)
