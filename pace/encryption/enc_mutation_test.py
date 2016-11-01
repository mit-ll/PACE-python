## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Unit tests for cell code 
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  19 Dec 2014  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import logging
import unittest
import ConfigParser
import StringIO as stringio
from pyaccumulo import Mutation, Cell, Range

from pace.encryption.enc_mutation import EncMutation, EncCell, EncRange
from pace.encryption.acc_encrypt import AccumuloEncrypt
from pace.encryption.encryption_pki import DummyEncryptionPKI
from pace.encryption.encryption_exceptions import EncryptionException, DecryptionException


class EncStructureTest(unittest.TestCase):

    def setUp(self):
        #Set up encryptor_dict
        config = stringio.StringIO(
                        '[row]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'encryption = Pycrypto_AES_CFB\n'+\
                        'cell_sections = row\n'+\
                        '[colFamily]\n'+\
                        'key_id = Pycrypto_AES_CFB\n'+\
                        'cell_sections = colFamily,colQualifier\n'+\
                        'encryption = Pycrypto_AES_CFB')
        config_identity = stringio.StringIO(
                        '[row]\n'+\
                        'key_id = Identity\n'+\
                        'encryption = Identity\n'+\
                        'cell_sections = row\n'+\
                        '[colFamily]\n'+\
                        'key_id = Identity\n'+\
                        'cell_sections = colFamily\n'+\
                        'encryption = Identity')
        
        config_det = stringio.StringIO(
                        '[row]\n'+\
                        'key_id = Pycrypto_AES_SIV\n'+\
                        'encryption = Pycrypto_AES_SIV\n'+\
                        'cell_sections = row\n'+\
                        '[colFamily]\n'+\
                        'key_id = Pycrypto_AES_SIV\n'+\
                        'cell_sections = colFamily,colQualifier\n'+\
                        'encryption = Pycrypto_AES_SIV')

        # Use a consistent PKI
        self.pki = DummyEncryptionPKI()
        
        self.encryptor_dict = self._create_encryptor_dict(config)
        self.encryptor_dict_identity = self._create_encryptor_dict(config_identity)
        self.encryptor_dict_det = self._create_encryptor_dict(config_det)
        
        #Sample mutation
        mut = Mutation('abcd')
        mut.put(cf='cf1',cq='cq1', cv='cv1', ts = '12345', val = 'val1')
        self.mut = mut
        
        #complex Sample mutation
        c_mut = Mutation('abcd')
        c_mut.put(cf='cf1',cq='cq1', cv='cv1', ts = '12345', val = 'val1')
        c_mut.put(cf='cf2', val='val2')
        c_mut.put(cf='cf3',cq='cq3', val = 'val3')
        c_mut.put(val = 'val4')
        self.c_mut = c_mut
        
        
        
    def _create_encryptor_dict(self, config):   
        config_parser = ConfigParser.ConfigParser()
        config_parser.readfp(config)
        key_object = self.pki
        return AccumuloEncrypt._config_to_encryptor(config_parser,
                                                  key_object)
    @staticmethod
    def _mutations_equal(list_mut, mut2):
        '''
        list_mut - list of mutations
        mut2 - the original mutation
        
        Returns if the list of mutations produced by a plaintext 
        mutation is the same as the original
        '''
        equal = True
        equal &= len(list_mut) == len(mut2.updates)
        for (mut, update) in zip(list_mut, mut2.updates):
            equal &= mut.row == mut2.row
            equal &= mut.updates[0] == update
        return equal
    
    
    def test_encrypt_mutation(self):
        '''
        Tests encryption functionality of EncMutation
        when encryption is identity function 
        '''
        enc_mut = EncMutation(self.mut,self.encryptor_dict_identity).encrypt()
        self.assertTrue(self._mutations_equal(enc_mut, self.mut),
                             "Mutation is not correctly handled during encryption process")

    def test_encrypt_overwrite(self):
        """
        Tests the fact information is overwritten if encrypted and not
        a target location
        """
        enc_mut = EncMutation(self.mut, self.encryptor_dict).encrypt()
        self.assertTrue(len(enc_mut) == 1)
        for u in enc_mut[0].updates:
            self.assertEqual(u.colQualifier, '', "colQualifier was not overwritten correctly") 
            
    def test_row_different(self):
        """
        Tests that the row value produced is different if deterministic encryption is not
        used
        """
        enc_muts = EncMutation(self.c_mut, self.encryptor_dict).encrypt()
        self.assertTrue(len(enc_muts) == 4)
        row_ids = set()
        for mut in enc_muts:
            row_ids.add(mut.row)
        self.assertTrue(len(row_ids) == 4)
        
    def test_row_same(self):
        """
        Tests that the row value produced is same if deterministic encryption is 
        used
        """
        enc_muts = EncMutation(self.c_mut, self.encryptor_dict_det).encrypt()
        self.assertTrue(len(enc_muts) == 4)
        row_ids = set()
        for mut in enc_muts:
            row_ids.add(mut.row)
        self.assertTrue(len(row_ids) == 1)
          
    def test_encrypt_decrypt_mutation(self):
        '''
        Tests encrypt then decrypt functionality of EncMutation
        '''
        enc_mut = EncMutation(self.mut, self.encryptor_dict).encrypt()
        self.assertTrue(len(enc_mut) == 1)
        dec_mut = EncMutation(enc_mut[0], self.encryptor_dict).decrypt()
        self.assertTrue(self._mutations_equal([dec_mut], self.mut),
                             "Mutation is not correctly handled during encryption and decryption process")
          
        
    def test_decrypt_cell(self):
        '''
        Tests decryption functionality of EncCell when 
        decryption is identity function
        '''
        cell = Cell('row','cf','cq','cv',1234,'val')
        dec_cell = EncCell.decrypt(cell, self.encryptor_dict_identity)
        self.assertEqual(cell, dec_cell,
                         str(dec_cell) + " was not correctly handled during decyption process " +\
                         "should be " + str(cell))
    
    def test_encrypt_decrypt_cell(self):
        '''
        Tests encrypt then decrypt functionality of EncCell
        '''
        cell = Cell('row','cf','cq','cv',1234,'val')
        enc_cell = EncCell.encrypt(cell, self.encryptor_dict)
        dec_cell = EncCell.decrypt(enc_cell, self.encryptor_dict)
        self.assertEqual(cell, dec_cell, 
                         str(dec_cell) + " was not correctly encrypted and decrypted " +\
                         "should be " + str(cell))
        
    def test_get_and_split_values(self):
        '''
        Tests get_values_by_cell_string and split_values_by_cell_string
        '''
        mut = EncMutation(self.mut,self.encryptor_dict)
        values = EncMutation.concatenate_cell_section_values(mut, ['colFamily','colQualifier'])
        self.assertEqual(values, ['cf1+cq1'])
        
        split_values = EncMutation.split_values(values)
        self.assertEqual(split_values, [('cf1',),('cq1',)])
        
        cell = Cell('row','cf','cq','cv',1234,'val')
        value = EncCell.get_value_by_cell_string(cell._asdict(), ['colFamily', 'colQualifier'])
        self.assertEqual(value, 'cf+cq')
        
        split_value = EncCell.split_value_by_cell_string(value)
        self.assertEqual(split_value,['cf','cq'])
       
    
