## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Unit tests for manualtruststore.py
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  24 Jun 2015  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random
import shutil

from pace.common.pacetest import PACETestCase
from pace.signatures.manualtruststore import ManualTrustStore, TrustStoreCreationException
from pace.signatures.vars import SIGNATURE_FUNCTIONS
from pace.signatures.acc_sig import PKCS1_v1_5_AccSig as v15
from pace.signatures.acc_sig import PKCS1_PSS_AccSig as PSS
from pace.signatures.acc_sig import PyCryptopp_ECDSA_AccSig as ECDSA

ABS_PATH = os.path.dirname(__file__)
TEST_STORE = ABS_PATH + '/keys/test_store'
TMP_PATH = ABS_PATH + '/tmp'
WRITE_STORE = TMP_PATH + '/test_written_store'


class TrustStoreTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

    def test_create_store(self):
        path = TEST_STORE
        try:
            ts = ManualTrustStore(path)
        except TrustStoreCreationException as tsce:
            self.assertTrue(False, tsce.msg)
        self.assertTrue(ts != None)

    def test_use_store(self, path=TEST_STORE):
        ts = ManualTrustStore(path)

        pubkey1, scheme1name = ts.get_verifying_key('user1')
        realpub1, _ = v15.test_keys()

        scheme1 = SIGNATURE_FUNCTIONS[scheme1name]

        self.assertEqual(scheme1, PSS)
        self.assertEqual(scheme1.serialize_key(pubkey1),
                         PSS.serialize_key(realpub1))

        pubkey2, scheme2name = ts.get_verifying_key('user2')
        realpub2, _ = PSS.test_keys()

        scheme2 = SIGNATURE_FUNCTIONS[scheme2name]

        self.assertEqual(scheme2, v15)
        self.assertEqual(scheme2.serialize_key(pubkey2),
                         v15.serialize_key(realpub2))

        pubkey3, scheme3name = ts.get_verifying_key('user3')
        realpub3, _ = ECDSA.test_keys()

        scheme3 = SIGNATURE_FUNCTIONS[scheme3name]

        self.assertEqual(scheme3, ECDSA)
        self.assertEqual(scheme3.serialize_key(pubkey3),
                         ECDSA.serialize_key(realpub3))

    def test_store_file(self):
        """ Test the writing out of a dictionary-based store to a file.
        """

        if os.path.exists(TMP_PATH):
            self.assertTrue(False, 'ERROR: tmp file or directory already exists. Delete and try again.')

        os.mkdir(TMP_PATH)

        path = WRITE_STORE

        pk1, _ = PSS.test_keys()
        pk2, _ = v15.test_keys()
        pk3, _ = ECDSA.test_keys()

        store = {'user1' : (PSS, pk1),
                 'user2' : (v15, pk2),
                 'user3' : (ECDSA, pk3)}

        ManualTrustStore.create_store_file(store, path)
        self.test_use_store(path=path)
        
        shutil.rmtree(TMP_PATH)

    def test_bad_header_footer(self):
        """ Make sure it fails to parse a store file with a poorly
            formatted header and footer.
        """

        path = ABS_PATH + '/keys/bad_store_1'

        try:
            ts = ManualTrustStore(path)
            self.assertTrue(False, 'Succeeded to read in an invalid store')
        except TrustStoreCreationException as tsce:
            self.assertTrue(True, tsce.msg)

    def test_alg_key_mismatch(self):
        """ Make sure it fails to parse a store file where the named algorithm
            does not match the key used.
        """

        path = ABS_PATH + '/keys/bad_store_2'

        try:
            ts = ManualTrustStore(path)
            self.assertTrue(False, 'Succeeded to read in an invalid store')
        except TrustStoreCreationException as tsce:
            self.assertTrue(True, tsce.msg)

    def test_bad_footer(self):
        """ Make sure it fails to parse a store file with a poorly formatted
            footer (and correct header)
        """

        path = ABS_PATH + '/keys/bad_store_3'

        try:
            ts = ManualTrustStore(path)
            self.assertTrue(False, 'Succeeded to read in an invalid store')
        except TrustStoreCreationException as tsce:
            self.assertTrue(True, tsce.msg)

    def test_empty_key(self):
        """ Make sure it fails to parse a file with an empty key.
        """

        path = ABS_PATH + '/keys/bad_store_4'

        try:
            ts = ManualTrustStore(path)
            self.assertTrue(False, 'Succeeded to read in an invalid store')
        except TrustStoreCreationException as tsce:
            self.assertTrue(True, tsce.msg)

        path = ABS_PATH + '/keys/bad_store_4b'

        try:
            ts = ManualTrustStore(path)
            self.assertTrue(False, 'Succeeded to read in an invalid store')
        except TrustStoreCreationException as tsce:
            self.assertTrue(True, tsce.msg)

