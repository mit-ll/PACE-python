## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ES
##  Description: Key generation tests
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  30 July 2015 ES   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import struct
import math
import time
import random
import ConfigParser
import shutil
import hmac
from hashlib import sha1
from binascii import unhexlify

from Crypto.PublicKey import RSA
from pace.common.pacetest import PACETestCase
from pace.pki.keygen import KeyGen
from pace.pki.keystore import DummyKeyStore,KeyInfo
from pace.pki.attrusermap import LocalAttrUserMap
from pace.pki.userattrmap import LocalUserAttrMap
import pace.pki.key_wrap_utils as utils
from pace.pki.abstractpki import PKILookupError

ABS_PATH = os.path.dirname(__file__)
TMP_PATH = ABS_PATH + '/tmp'

class KeyGenTests(PACETestCase):
    @classmethod
    def setUpClass(cls):
        os.mkdir(TMP_PATH)

    def setUp(self):
        random.seed(int(time.time()))
        self.num_users = 10
        self.num_keys = 10

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TMP_PATH)

    def test_HMAC_SHA1(self):
        """ Implements HMAC-SHA1 test cases from RFC 2202 to check that 
            pycrypto's HMAC and its usage in generate_key are correct.
            Does not test generate_key itself.
        """

        # Test case 1
        key = unhexlify('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
        data = "Hi There"
        digest = unhexlify('b617318655057264e28bc0b6fb378c8ef146be00')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)

        # Test case 2
        key = "Jefe"
        data = "what do ya want for nothing?"
        digest = unhexlify('effcdf6ae5eb2fa2d27416d5f184df9c259a7c79')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)

        # Test case 3
        key = unhexlify('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        data = '\xdd' * 50
        digest = unhexlify('125d7342b9ac11cd91a39af48aa17b4f63f175d3')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)

        # Test case 4
        key = unhexlify('0102030405060708090a0b0c0d0e0f10111213141516171819')
        data = '\xcd' * 50
        digest = unhexlify('4c9007f4026250c6bc8414f9bf50c86c2d7235da')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)
        
        # Test case 5
        key = unhexlify('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c')
        data = 'Test With Truncation'
        digest = unhexlify('4c1a03424b55e07fe7f27be1d58bb9324a9a5a04')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)

        # Test case 6
        key = '\xaa' * 80
        data = 'Test Using Larger Than Block-Size Key - Hash Key First'
        digest = unhexlify('aa4ae5e15272d00e95705637ce8a3b55ed402112')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)

        # Test case 7
        key = '\xaa' * 80
        data = 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data'
        digest = unhexlify('e8e99d0f45237d786d6bbaa7965c7808bbff1a91')
        h = hmac.new(key, data, sha1)
        self.assertEqual(h.digest(), digest)

    def test_HKDF_expand(self):
        """ Implements HMAC-based key derivation function (HKDF) test cases 
            from RFC 5869 to check that the iterated usage of HMAC-SHA1 in 
            generate_key correctly implements the ``expand'' step of HKDF.
            Does not test generate_key itself.
        """

        #Test case 4 (Test cases 1-3 are for SHA-256)
        msk = unhexlify('9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243')
        info = unhexlify('f0f1f2f3f4f5f6f7f8f9')
        keylen = 42
        output = unhexlify('085a01ea1b10f36933068b56efa5ad81' + 
                           'a4f14b822f5b091568a9cdd4f155fda2' +
                           'c22e422478d305f3f896')
        self.assertEqual(output, self.HKDF_extract(msk, info, keylen))

        #Test case 5
        msk = unhexlify('8adae09a2a307059478d309b26c4115a224cfaf6')
        info = unhexlify('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
                         'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
                         'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
                         'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
                         'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
        keylen = 82
        output = unhexlify('0bd770a74d1160f7c9f12cd5912a06eb' + 
                           'ff6adcae899d92191fe4305673ba2ffe' + 
                           '8fa3f1a4e5ad79f3f334b3b202b2173c' +
                           '486ea37ce3d397ed034c7f9dfeb15c5e' +
                           '927336d0441f4c4300e2cff0d0900b52' +
                           'd3b4')
        self.assertEqual(output, self.HKDF_extract(msk, info, keylen))

        #Test case 6
        msk = unhexlify('da8c8a73c7fa77288ec6f5e7c297786aa0d32d01')
        info = ''
        keylen = 42
        output = unhexlify('0ac1af7002b3d761d1e55298da9d0506' + 
                           'b9ae52057220a306e07b6b87e8df21d0' +
                           'ea00033de03984d34918')
        self.assertEqual(output, self.HKDF_extract(msk, info, keylen))

        #Test case 7
        msk = unhexlify('2adccada18779e7c2077ad2eb19d3f3e731385dd')
        info = ''
        keylen = 42
        output = unhexlify('2c91117204d745f3500d636a62f64f0a' +
                           'b3bae548aa53d423b0d1f27ebba6f5e5' +
                           '673a081d70cce7acfc48')
        self.assertEqual(output, self.HKDF_extract(msk, info, keylen))

    def HKDF_extract(self, msk, key_info, keylen):
        """ Generates a pseudorandom key in a similar way to generate_key, 
            except that the master secret key is passed in instead of set in a 
            constructor, and key info is passed in instead of constructed from 
            attr, vers, metadata, keylen arguments. Enables testing on HKDF 
            test vectors.
        """
        h = hmac.new(msk, digestmod=sha1)
        num_blocks = int(math.ceil((keylen*1.0)/h.digest_size))
        key = ''
        block = ''
        for i in xrange(num_blocks):
            block_num = bytes(bytearray(struct.pack('>i', i+1)))[-1]
            h = hmac.new(msk, block + key_info + block_num, sha1)
            block = h.digest()
            key += block
        return key[:keylen]

    def test_negative_keylen(self):
        """ Check that negative key lengths raise an exception.
        """
        keygen = KeyGen('Sixteen byte key')
        self.assertRaises(ValueError, keygen._generate_key, 'attr', 1, 'metadata', -1)
        
    def test_keylen(self):
        """ Check that generated keys are of expected length.
        """
        
        keygen = KeyGen('Sixteen byte key')
        for i in xrange(65):
            key = keygen._generate_key('attr', 1, 'metadata', i)
            self.assertEqual(i, len(key))

    def test_equal_inputs(self):
        """ Check that the same inputs result in the same key.
        """

        keygen = KeyGen('Sixteen byte key')
        key1 = keygen._generate_key('attr', 1, 'metadata', 16)
        key2 = keygen._generate_key('attr', 1, 'metadata', 16)
        self.assertEqual(key1, key2)

    def test_diff_inputs(self):
        """ Check that different inputs result in different keys.
        """

        keygen = KeyGen('Sixteen byte key')

        key1 = keygen._generate_key('attr1', 1, 'metadata', 16)
        key2 = keygen._generate_key('attr2', 1, 'metadata', 16)
        self.assertNotEqual(key1, key2)

        key1 = keygen._generate_key('attr', 2, 'metadata', 16)
        key2 = keygen._generate_key('attr', 3, 'metadata', 16)
        self.assertNotEqual(key1, key2)

        key1 = keygen._generate_key('attr', 1, 'metadata1', 16)
        key2 = keygen._generate_key('attr', 1, 'metadata2', 16)
        self.assertNotEqual(key1, key2)

    def test_diff_keygens(self):
        """ Check that key generators with different master secret keys result
            in different keys.
        """
        
        keygen1 = KeyGen('Sixteen byte key')
        keygen2 = KeyGen('sixteen byte key')
        key1 = keygen1._generate_key('attr', 1, 'metadata', 16)
        key2 = keygen2._generate_key('attr', 1, 'metadata', 16)
        self.assertNotEqual(key1, key2)

    def test_diff_keylens_same_info(self):
        """ Check that keys generated for the same attribute, version, and 
            metadata but different key lengths do not have a common prefix 
            of the shorter key length.
        """
        keygen = KeyGen('Sixteen byte key')
        key1 = keygen._generate_key('attr', 1, 'metadata', 16)
        key2 = keygen._generate_key('attr', 1, 'metadata', 32)
        self.assertNotEqual(key1, key2[:16])

    def test_initialize_single(self):
        """ Check that a key generated, wrapped with a user's public key, and 
            stored in a keystore can be retrieved and unwrapped with the user's
            secret key.
        """
        
        RSA_key = RSA.generate(3072)
        RSA_pk = RSA_key.publickey()       
        keygen = KeyGen('Sixteen byte key')
        keystore = DummyKeyStore()
        orig_key = keygen._generate_key('attr', 1, 'meta', 16)
        keygen.initialize_users(
            {'userid': (RSA_pk, [('attr', 1, 'meta', 16)])}, keystore)
        keywrap = keystore.retrieve('userid', 'attr', 1, 'meta')
        self.assertEqual(utils.unwrap_key(keywrap, RSA_key), orig_key)
    
    def test_initialize_diff_users_same_info(self):
        """ Check that two different users can recover the same key for the 
            same attribute, version, metadata, key length combination.
        """
        
        RSA_key1 = RSA.generate(3072)
        RSA_pk1 = RSA_key1.publickey()
        RSA_key2 = RSA.generate(3072)
        RSA_pk2 = RSA_key2.publickey()
        keygen = KeyGen('Sixteen byte key')
        keystore = DummyKeyStore()
        keygen.initialize_users(
            {'user1': (RSA_pk1, [('attr', 1, 'meta', 16)]),
             'user2': (RSA_pk2, [('attr', 1, 'meta', 16)])}, keystore)
        keywrap1 = keystore.retrieve('user1', 'attr', 1, 'meta')
        keywrap2 = keystore.retrieve('user2', 'attr', 1, 'meta')
        self.assertEqual(utils.unwrap_key(keywrap1, RSA_key1), 
                         utils.unwrap_key(keywrap2, RSA_key2))
    
    def test_initialize_empty(self):
        """ Check that a key generated from empty string inputs, wrapped with a
            user's public key, and stored in a keystore can be retrieved and 
            unwrapped with the user's secret key.
        """
        
        RSA_key = RSA.generate(3072)
        RSA_pk = RSA_key.publickey()       
        keygen = KeyGen('Sixteen byte key')
        keystore = DummyKeyStore()

        params = [('', 'attr', 1, 'meta'), 
                  ('userid', '', 1, 'meta'),
                  ('userid', 'attr', 0, 'meta'),
                  ('userid', 'attr', 1, ''),
                  ('', '', 0, '')]
        
        for userid, attr, vers, meta in params:
            orig_key = keygen._generate_key(attr, vers, meta, 16)
            keygen.initialize_users(
                {userid: (RSA_pk, [(attr, vers, meta, 16)])}, keystore)
            keywrap = keystore.retrieve(userid, attr, vers, meta)
            self.assertEqual(utils.unwrap_key(keywrap, RSA_key), orig_key)

    def test_initialize_many(self):
        """ Check that multiple keys generated, wrapped with users' public keys,
            and stored in a keystore can be retrieved and unwrapped with the 
            users' secret keys.
        """
             
        keygen = KeyGen('Sixteen byte key')
        keystore = DummyKeyStore()

        key_infos = [('attr'+str(i), i, 'meta'+str(i), 16) 
                     for i in xrange(self.num_keys)]
        
        users = {}
        RSA_sks = {}
        for i in xrange(self.num_users):
            userid = 'user'+str(i)
            RSA_key = RSA.generate(3072)
            RSA_sks[userid] = RSA_key
            RSA_pk = RSA_key.publickey()
            
            info = random.sample(key_infos, random.randint(1, len(key_infos)))
            users[userid] = (RSA_pk, info)

        keygen.initialize_users(users, keystore)

        for userid in users:
            RSA_pk, info = users[userid]
            for attr, vers, meta, keylen in info:
                keywrap = keystore.retrieve(userid, attr, vers, meta)
                self.assertEqual(utils.unwrap_key(keywrap, RSA_sks[userid]), 
                                 keygen._generate_key(attr, vers, meta, keylen))

    def create_configs_from_dict(self, user_info, filename):
        """ Takes in a dictionary of user info, generates RSA key pair files, 
            and creates a configuration file. For each user, the RSA public and 
            private keys are written to a temporary directory in files 
            [userid]_pubkey.pem and [userid]_privkey.pem respectively, where 
            [userid] is replaced with the user's ID.

            Arguments:
            user_info ({string: [(string, string, string, integer)]}): 
                a dictionary mapping user IDs to lists of tuples each containing
                an attribute, version, metadata, and key length (in bytes)
            filename: the name of the configuration file to create
        """
        f = open(filename, 'w')
        for userid, key_infos in user_info.iteritems():
            RSA_key = RSA.generate(3072)
            sk_file = open(TMP_PATH + '/' + userid + '_privkey.pem', 'w')
            sk_file.write(RSA_key.exportKey())
            sk_file.close()

            RSA_pk = RSA_key.publickey()
            pk_file = open(TMP_PATH + '/' + userid + '_pubkey.pem', 'w')
            pk_file.write(RSA_pk.exportKey())
            pk_file.close()
            
            f.write('[' + userid + ']\n')
            f.write('public_key: ' + userid + '_pubkey.pem\n')
            f.write('key_info: ')
            for attr, vers, meta, keylen in key_infos:
                info_string = '|'.join([attr, str(vers), meta, str(keylen)])
                f.write('\t' + info_string + '\n')              
        f.close()
    
    def test_init_many_from_file(self):
        """ Check that multiple keys generated, wrapped with users' public keys,
            and stored in a keystore can be retrieved and unwrapped with the 
            users' secret keys when input comes from a configuration file.
        """        
        keygen = KeyGen('Sixteen byte key')
        keystore = DummyKeyStore()

        user_info = {'user1': [('attr1', 1, 'AES_GCM', 16),
                               ('attr2', 1, 'AES_GCM', 16),
                               ('attr3', 2, 'AES_GCM', 16)],
                     'user2': [('attr2', 1, 'AES_GCM', 16),
                               ('attr4', 2, 'AES_GCM', 16)],
                     'user3': [('attr1', 1, 'AES_GCM', 16),
                               ('attr4', 2, 'AES_GCM', 16)]}
        
        self.create_configs_from_dict(user_info, 
                                      TMP_PATH + '/user_info_test.cfg')

        keygen.init_from_file(TMP_PATH + '/user_info_test.cfg', keystore)
        
        for userid in user_info:
            key_infos = user_info[userid]
            f = open(TMP_PATH + '/' + userid + '_privkey.pem', 'r')
            RSA_sk = RSA.importKey(f.read())
            f.close()
            for attr, vers, meta, keylen in key_infos:
                keywrap = keystore.retrieve(userid, attr, vers, meta)
                self.assertEqual(utils.unwrap_key(keywrap, RSA_sk), 
                                 keygen._generate_key(attr, vers, meta, keylen))

    def test_nonexistent_publickey_file(self):
        """ Check that creating a dictionary from a configuration file that does
            not exist raises an IOError.
        """
        keygen = KeyGen('Sixteen byte key')

        f = open(TMP_PATH + '/user_info_nonexistent.cfg', 'w')
        f.write('[userA]\n')
        f.write('public_key: user1_nonexistent.pem\n')
        f.write('key_info: attr1|v1|AES_GCM|16')
        f.close()

        try:
            users = keygen.file_to_dict(TMP_PATH+'/user_info_nonexistent.cfg')
        except IOError:
            self.assertTrue(True, 'error')
        else:
            self.assertTrue(False, 
                            'No error raised on a nonexistent public key file')
        
    def test_revocation(self):
        """ Tests that revoking an attribute from a user removes the appropriate
            entries from the keystore and the attr-user map and generates wraps
            of new keys of the correct length for the correct set of users.
        """

        keygen = KeyGen('Sixteen byte key')
        ks = DummyKeyStore()
        attr_user_dict = {'A': ['user1', 'user2', 'user3'],
                          'B': ['user1', 'user2']}
        attr_user_map = LocalAttrUserMap(attr_user_dict)
        user_attr_dict = {'user1': ['A', 'B'],
                          'user2': ['A', 'B'],
                          'user3': ['A']}
        user_attr_map = LocalUserAttrMap(user_attr_dict)

        user_sks = {}
        user_pks = {}
        for i in range(1, 4):
            userid = 'user' + str(i)
            RSA_key = RSA.generate(3072)
            user_sks[userid] = RSA_key
            RSA_pk = RSA_key.publickey()
            user_pks[userid] = RSA_pk

        key_infos = {'user1': [KeyInfo('A', 1, 'meta1', 'keywrap1', 16),
                               KeyInfo('A', 1, 'meta2', 'keywrap2', 16),
                               KeyInfo('B', 1, 'meta1', 'keywrap4', 16),
                               KeyInfo('B', 1, 'meta2', 'keywrap5', 16)],
                     'user2': [KeyInfo('A', 1, 'meta2', 'keywrap6', 16),
                               KeyInfo('A', 1, 'meta3', 'keywrap7', 16),
                               KeyInfo('B', 1, 'meta1', 'keywrap8', 16), 
                               KeyInfo('B', 1, 'meta2', 'keywrap9', 16)],
                     'user3': [KeyInfo('A', 1, 'meta1', 'keywrap10', 16),
                               KeyInfo('A', 1, 'meta2', 'keywrap11', 16),
                               KeyInfo('A', 1, 'meta3', 'keywrap12', 16)]}
        for user in key_infos:
            ks.batch_insert(user, key_infos[user])
        
        #revoke an attribute from a user
        keygen.revoke('user1', 'A', ks, attr_user_map, user_attr_map, user_pks)

        #check that keywraps for revoked user/attr were removed from keystore
        for i in range(1, 3):
            self.assertRaises(PKILookupError, ks.retrieve, 'user1', 'A', 1, 'meta'+str(i))

        #check that revoked user/attr were removed from maps
        self.assertEqual(set(attr_user_map.users_by_attribute('A')), 
                         set(['user2', 'user3']))
        self.assertEqual(user_attr_map.attributes_by_user('user1'), ['B'])

        #check that metadatas for revoked attr have correct version numbers
        self.assertEqual(ks.retrieve_latest_version_number('meta1', 'A'), 2)
        self.assertEqual(ks.retrieve_latest_version_number('meta2', 'A'), 2)
        self.assertEqual(ks.retrieve_latest_version_number('meta3', 'A'), 1)
        
        #check that other users with revoked attr got new keywraps that decrypt 
        #to keys of the correct length
        kw22 = ks.retrieve_latest_version('user2', 'meta2', 'A').keywrap
        kw31 = ks.retrieve_latest_version('user3', 'meta1', 'A').keywrap
        kw32 = ks.retrieve_latest_version('user3', 'meta2', 'A').keywrap

        self.assertEqual(len(utils.unwrap_key(kw22, user_sks['user2'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw31, user_sks['user3'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw32, user_sks['user3'])), 16)

        #check that other keys for revoked user are still unchanged
        self.assertEqual(ks.retrieve_latest_version(
                'user1', 'meta1', 'B').keywrap, 'keywrap4')
        self.assertEqual(ks.retrieve_latest_version(
                'user1', 'meta2', 'B').keywrap, 'keywrap5')

        #revoke an attribute from a user and update key lengths
        keylens = {'meta1': 24, 'meta2': 32}
        keygen.revoke('user1', 'B', ks, attr_user_map, user_attr_map, user_pks,
                      keylens)
        
        #check that new keys for other users have updated key lengths
        kw21 = ks.retrieve_latest_version('user2', 'meta1', 'B').keywrap
        kw22 = ks.retrieve_latest_version('user2', 'meta2', 'B').keywrap
        self.assertEqual(len(utils.unwrap_key(kw21, user_sks['user2'])), 24)
        self.assertEqual(len(utils.unwrap_key(kw22, user_sks['user2'])), 32)
    
    def test_revocation_all_attrs(self):
        """ Tests that revoking all of a user's attributes removes the 
            appropriate entries from the keystore and the user/attr maps and 
            generates wraps of new keys for the correct set of users.
        """
        keygen = KeyGen('Sixteen byte key')
        ks = DummyKeyStore()
        attr_user_dict = {'A': ['user1', 'user2', 'user3'],
                          'B': ['user1', 'user2'],
                          'C': ['user1', 'user3']}
        attr_user_map = LocalAttrUserMap(attr_user_dict)
        user_attr_dict = {'user1': ['A', 'B', 'C'],
                          'user2': ['A', 'B'],
                          'user3': ['A', 'C']}
        user_attr_map = LocalUserAttrMap(user_attr_dict)

        user_sks = {}
        user_pks = {}
        for i in range(1, 4):
            userid = 'user' + str(i)
            RSA_key = RSA.generate(3072)
            user_sks[userid] = RSA_key
            RSA_pk = RSA_key.publickey()
            user_pks[userid] = RSA_pk

        key_infos = {'user1': [KeyInfo('A', 1, 'meta1', 'keywrap1', 16),
                               KeyInfo('A', 1, 'meta2', 'keywrap2', 16),
                               KeyInfo('B', 1, 'meta1', 'keywrap4', 16),
                               KeyInfo('B', 1, 'meta2', 'keywrap5', 16),
                               KeyInfo('C', 1, 'meta1', 'keywrap6', 16),
                               KeyInfo('C', 1, 'meta2', 'keywrap7', 16)],
                     'user2': [KeyInfo('A', 1, 'meta2', 'keywrap8', 16),
                               KeyInfo('A', 1, 'meta3', 'keywrap9', 16),
                               KeyInfo('B', 1, 'meta1', 'keywrap10', 16), 
                               KeyInfo('B', 1, 'meta2', 'keywrap11', 16)],
                     'user3': [KeyInfo('A', 1, 'meta1', 'keywrap12', 16),
                               KeyInfo('A', 1, 'meta2', 'keywrap13', 16),
                               KeyInfo('A', 1, 'meta3', 'keywrap14', 16),
                               KeyInfo('C', 1, 'meta1', 'keywrap15', 16),
                               KeyInfo('C', 1, 'meta2', 'keywrap16', 16)]}
  
        for user in key_infos:
            ks.batch_insert(user, key_infos[user])
        
        #revoke all attributes from a user
        keygen.revoke_all_attrs('user1', ks, attr_user_map, user_attr_map, 
                                user_pks)

        #check that keywraps for revoked user were removed from keystore
        for i in range(1, 3):
            self.assertRaises(PKILookupError, ks.retrieve, 'user1', 'A', 1, 'meta'+str(i))
            self.assertRaises(PKILookupError, ks.retrieve, 'user1', 'B', 1, 'meta'+str(i))
            self.assertRaises(PKILookupError, ks.retrieve, 'user1', 'C', 1, 'meta'+str(i))
        
        #check that updated user/attr maps are correct
        self.assertEqual(set(attr_user_map.users_by_attribute('A')), 
                         set(['user2', 'user3']))
        self.assertEqual(attr_user_map.users_by_attribute('B'), ['user2'])
        self.assertEqual(attr_user_map.users_by_attribute('C'), ['user3'])
        self.assertEqual(user_attr_map.attributes_by_user('user1'), [])
        self.assertEqual(set(user_attr_map.attributes_by_user('user2')), 
                         set(['A', 'B']))
        self.assertEqual(set(user_attr_map.attributes_by_user('user3')),
                         set(['A', 'C']))

        #check that metadatas for revoked attrs have correct version numbers
        self.assertEqual(ks.retrieve_latest_version_number('meta1', 'A'), 2)
        self.assertEqual(ks.retrieve_latest_version_number('meta2', 'A'), 2)
        self.assertEqual(ks.retrieve_latest_version_number('meta3', 'A'), 1)
        self.assertEqual(ks.retrieve_latest_version_number('meta1', 'B'), 2)
        self.assertEqual(ks.retrieve_latest_version_number('meta2', 'B'), 2)

        #check that other users with revoked attrs got new keywraps that decrypt
        #to keys of the correct length
        kw_2_2_A = ks.retrieve_latest_version('user2', 'meta2', 'A').keywrap
        kw_3_1_A = ks.retrieve_latest_version('user3', 'meta1', 'A').keywrap
        kw_3_2_A = ks.retrieve_latest_version('user3', 'meta2', 'A').keywrap
        kw_2_1_B = ks.retrieve_latest_version('user2', 'meta1', 'B').keywrap
        kw_2_2_B = ks.retrieve_latest_version('user2', 'meta2', 'B').keywrap
        kw_3_1_C = ks.retrieve_latest_version('user3', 'meta1', 'C').keywrap
        kw_3_2_C = ks.retrieve_latest_version('user3', 'meta2', 'C').keywrap

        self.assertEqual(len(utils.unwrap_key(kw_2_2_A, user_sks['user2'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw_3_1_A, user_sks['user3'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw_3_2_A, user_sks['user3'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw_2_1_B, user_sks['user2'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw_2_2_B, user_sks['user2'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw_3_1_C, user_sks['user3'])), 16)
        self.assertEqual(len(utils.unwrap_key(kw_3_2_C, user_sks['user3'])), 16)

        #revoke all attributes from a user and update some key lengths
        keylens = {'meta2': 24}
        keygen.revoke_all_attrs('user2', ks, attr_user_map, user_attr_map, 
                                user_pks, keylens)
        
        #check that new keys for other users have correct key lengths
        kw_3_2_A = ks.retrieve_latest_version('user3', 'meta2', 'A').keywrap
        kw_3_3_A = ks.retrieve_latest_version('user3', 'meta3', 'A').keywrap
        self.assertEqual(len(utils.unwrap_key(kw_3_2_A, user_sks['user3'])), 24)
        self.assertEqual(len(utils.unwrap_key(kw_3_3_A, user_sks['user3'])), 16)
