## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Unit tests for acc_encrypt
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  23 Dec 2014  ATLH   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import logging
import unittest
from StringIO import StringIO
from pyaccumulo import Mutation, Cell, Range
from pace.encryption.encryption_exceptions import EncryptionException, DecryptionException
from pace.encryption.acc_encrypt import AccumuloEncrypt, ConfigurationException
from pace.encryption.encryption_pki import DummyEncryptionPKI
from pace.pki.accumulo_keystore import AccumuloKeyStore
from pace.encryption.AES_encrypt import Pycrypto_AES_CFB
from pace.common.fakeconn import FakeConnection 

class AccumuloCryptTest(unittest.TestCase):
    
    def setUp(self):
        # Keep the same PKI around, since it generates a new RSA key
        # for key wraps each time
        self.pki = DummyEncryptionPKI()
    
    def test_error_handling(self):
        '''
        Tests error handling of configuration sections
        '''
        not_valid_section = StringIO('[row]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colSection]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB'
                        '[colFamily]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB')
        self.assertRaises(ConfigurationException, AccumuloEncrypt, not_valid_section, self.pki)         
             
        no_encryption = StringIO('[row]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        '[colFamily]\n'+\
                        'key_id = Identity\n'+\
                        'encryption = Identity')
        self.assertRaises(ConfigurationException, AccumuloEncrypt, no_encryption, self.pki)  
           
        
        no_key_id = StringIO('[row]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colFamily]\n'+\
                        'encryption = Pycrypto_AES_CFB')
        self.assertRaises(ConfigurationException, AccumuloEncrypt, no_key_id, self.pki)    
           
        algorithm_not_supported = StringIO('[row]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_RSA\n'+\
                        '[colFamily]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB')
        self.assertRaises(ConfigurationException, AccumuloEncrypt, algorithm_not_supported, self.pki)   
     
   
    def test_encryptor_dict(self):
        '''
        Tests the format of the created encryptor_dict
        '''
        all_sections = StringIO('[row]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colQualifier]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colFamily]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colVisibility]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[value]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB')

        ac = AccumuloEncrypt(all_sections, self.pki)
        encryptor_dict = ac.encrypt_dict
        keys = ['row','colQualifier','colFamily','colVisibility',
                'value']
        for k in keys:
            self.assertTrue(k in encryptor_dict, '%s is not in dictionary' % k)
            encryptor = encryptor_dict[k]
            self.assertEqual(encryptor.encryption, Pycrypto_AES_CFB )
            self.assertEqual(encryptor.cell_sections, [k])
    
    def test_with_accumulo_conn(self):
        '''
        Tests the interplay with a fake accumulo connection 
        '''
        all_sections = '[row]\n'+\
                        'key_id = table1\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colQualifier]\n'+\
                        'key_id = table1\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colFamily]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[colVisibility]\n'+\
                        'key_id = table1\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        '[value]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB'
        #create mutation
        mut = Mutation('row1')
        mut.put(cf='cf1',cq='cq1', cv='cv1', ts = 12345, val = 'val1')
        mut.put(cf='cf2',cq='cq2', cv='', ts = 67890, val = 'val2')
        ae = AccumuloEncrypt(StringIO(all_sections), self.pki)
        enc_muts = ae.encrypt(mut)
        
        #write mutation along fake connection
        conn = FakeConnection()
        conn.create_table('enc_test')
        conn.write('enc_test', enc_muts[0])
        conn.write('enc_test', enc_muts[1])
        
        #create ground truth
        conn.create_table('ground')
        conn.write('ground', mut)
        
        #retrieve encrypted mutation 
        dec_cells = []
        for c in conn.scan('enc_test'):
            dec_cells.append(ae.decrypt(c))
            
        gt_cells = []
        for c in conn.scan('ground'):
            gt_cells.append(c)
            
        self.assertEqual(sorted(gt_cells), sorted(dec_cells))
        
    def _run_search(self, config, row, cols, correct_cells):
        '''
        Tests the encrypting search functionality
        '''
        #create range & mutation to search for             
        mut1 = Mutation('arow')
        mut1.put(cf='cf1',cq='cq1', cv='', ts = 1, val = 'val1')
        mut1.put(cf='cf2',cq='cq2', cv='', ts = 2, val = 'val2')
        mut1.put(cf='cf1',cq='cq1', cv='', ts = 3, val = 'val3')
        mut1.put(cf='cf2',cq='cq3', cv='', ts = 4, val = 'val4')
        mut1.put(cf='cf3',cq='cq4', cv='', ts = 5, val = 'val5')
        mut2 = Mutation('brow')
        mut2.put(cf='cf1',cq='cq1', cv='', ts = 6, val = 'val1')
        mut2.put(cf='cf2',cq='cq2', cv='', ts = 7, val = 'val2')
        ae = AccumuloEncrypt(StringIO(config), self.pki)
        enc_muts1 = ae.encrypt(mut1)
        enc_muts2 = ae.encrypt(mut2)
        enc_row, enc_cols = ae.encrypt_search(row, cols)
        
        #write mutation along fake connection
        conn = FakeConnection()
        conn.create_table('enc_test')
        for mut in enc_muts1 + enc_muts2:
            conn.write('enc_test', mut)

        #retrieve encrypted mutation with search
        dec_cells = []
        for c in conn.scan('enc_test', 
                           scanrange=Range(srow=enc_row, erow=enc_row,
                                           sinclude=True, einclude=True),
                           cols=enc_cols):
            dec_cells.append(ae.decrypt(c))
            
        self.assertEqual(sorted(dec_cells), sorted(correct_cells))
        
    def test_det_row_search(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'encryption = Pycrypto_AES_SIV\n'
        self._run_search(config,
                         'brow',
                         None,
                         [Cell('brow','cf1','cq1','',6,'val1'),
                          Cell('brow','cf2','cq2','',7,'val2')]) 
    
    def test_unencrypted_search(self):
        config = '[colFamily]\n'+\
                'key_id = Pycrypto_AES_CBC\n'+\
                'cell_sections = colFamily\n'+\
                'encryption = Pycrypto_AES_CBC\n'
                
        self._run_search(config,
                         'brow',
                         None,
                         [Cell('brow','cf1','cq1','',6,'val1'),
                          Cell('brow','cf2','cq2','',7,'val2')]) 
        
    def test_det_row_cf_search(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colFamily]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colFamily\n'+\
                'encryption = Pycrypto_AES_SIV\n'
                
        self._run_search(config,
                         'brow',
                         [['cf1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
        self._run_search(config,
                         'arow',
                         [['cf1'],['cf3']],
                         [Cell('arow','cf1','cq1','',1,'val1'),
                          Cell('arow','cf1','cq1','',3,'val3'),
                          Cell('arow','cf3','cq4','',5,'val5')])
        
    def test_det_cf_search(self):
        config = '[colFamily]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colFamily\n'+\
                'encryption = Pycrypto_AES_SIV\n'       
        
        self._run_search(config,
                         'brow',
                         [['cf1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])

        self._run_search(config,
                         'brow',
                         [['cf1','cq1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
    
        self._run_search(config,
                         'arow',
                         [['cf1'],['cf3']],
                         [Cell('arow','cf1','cq1','',1,'val1'),
                          Cell('arow','cf1','cq1','',3,'val3'),
                          Cell('arow','cf3','cq4','',5,'val5')])
        
    def test_det_cq_search(self):
        config = '[colQualifier]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colQualifier\n'+\
                'encryption = Pycrypto_AES_SIV\n'
        
    
        self._run_search(config,
                         'brow',
                         [['cf1','cq1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
        
    def test_det_row_cf_cq_search(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colFamily]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colFamily\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colQualifier]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colQualifier\n'+\
                'encryption = Pycrypto_AES_SIV\n'
        
    
        self._run_search(config,
                         'brow',
                         [['cf1','cq1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
        
    def test_det_cf_cq_search(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colFamily]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colFamily,colQualifier\n'+\
                'encryption = Pycrypto_AES_SIV\n'
        
        self._run_search(config,
                         'brow',
                         [['cf1','cq1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
        
    def test_det_cq_cf_search(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colQualifier]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colFamily,colQualifier\n'+\
                'encryption = Pycrypto_AES_SIV\n'
        
        self._run_search(config,
                         'brow',
                         [['cf1','cq1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
        
    def test_det_cf_cq_switch_search(self):
        config = '[colQualifier]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colFamily\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colFamily]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colQualifier\n'+\
                'encryption = Pycrypto_AES_SIV\n'
        
        self._run_search(config,
                         'brow',
                         [['cf1','cq1']],
                         [Cell('brow','cf1','cq1','',6,'val1')])
        
    def test_non_det_row(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_CBC\n'+\
                'encryption = Pycrypto_AES_CBC\n'
        ae = AccumuloEncrypt(StringIO(config), self.pki)
        self.assertRaises(EncryptionException, ae.encrypt_search, 'arow', [['cf1']])
    
    def test_det_non_det_search(self):
        config = '[row]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'encryption = Pycrypto_AES_SIV\n'+\
                '[colFamily]\n'+\
                'key_id = Pycrypto_AES_CBC\n'+\
                'cell_sections = colFamily\n'+\
                'encryption = Pycrypto_AES_CBC\n'+\
                '[colQualifier]\n'+\
                'key_id = Pycrypto_AES_SIV\n'+\
                'cell_sections = colQualifier\n'+\
                'encryption = Pycrypto_AES_CBC\n'
        
        self._run_search(config,
                         'brow',
                         None,
                         [Cell('brow','cf1','cq1','',6,'val1'),
                          Cell('brow','cf2','cq2','',7,'val2')])
        
    
                          
        
        
                    
    
        
        
        
        
        
        
        
        
        
        
        
        
        
        
