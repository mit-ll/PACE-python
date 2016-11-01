## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Unit tests for cell code 
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   7 Jan 2014  ATLH   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import string
import logging
import unittest
import ConfigParser
import StringIO as stringio
from nose.tools import eq_, assert_raises, assert_equal, assert_not_equal, assert_true
from pyaccumulo import Mutation, Cell 

from pace.encryption.encryption_pki import DummyEncryptionPKI
from pace.encryption.acc_encrypt import AccumuloEncrypt
from pace.encryption.enc_mutation import EncMutation, EncCell 
from pace.encryption.enc_classes import ALGORITHMS, AES_ALGORITHMS, IV_AES_ALGORITHMS,\
                                       LENGTHBOUND_AES_ALGORITHMS, AUTH_ALGORITHMS, DET_ALGORITHMS
from pace.encryption.encryption_exceptions import DecryptionException
from pace.encryption.AES_encrypt import Pycrypto_AES_Base

def _create_encryptor_dict(config): 
    '''
    Helper function that parses a config file and creates a key 
    object before creating an encryptor dict that can be passed
    into and EncMutation. 
    '''  
    config_parser = ConfigParser.ConfigParser()
    config_parser.readfp(config)
    key_object = DummyEncryptionPKI()
    return AccumuloEncrypt._config_to_encryptor(config_parser,
                                              key_object)

def _mutations_equal(mut1, mut2):
    return mut1.row == mut2.row and mut2.updates == mut1.updates 

def _decrypt_mutations_equal(list_mut, mut2):
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

def _check_versioning(encClass):
    """
    Test the encryptions classes are properly dealing with versions.
    Versions are pulled from the DummyEncryptionPKI in encryption_pki.py
    """
    groundtruth = {"Pycrypto_AES_CFB": '3',
                  "Pycrypto_AES_CBC": '1',
                  "Pycrypto_AES_OFB": '3',
                  "Pycrypto_AES_CTR": '1',
                  "Pycrypto_AES_GCM": '2',
                  "Pycrypto_AES_CFB": '3',
                  "Pycrypto_AES_SIV": '1'}
    config = stringio.StringIO(
                        '[value]\n'+\
                        'key_id = '+ encClass.name +'\n'+\
                        'cell_sections = value\n'+\
                        'encryption = ' + encClass.name)
    encryptor_dict = _create_encryptor_dict(config)
    mut = Mutation('abcdefghijklmnopqrstuvwxyz')
    mut.put(val='val2')
    enc_muts = EncMutation(mut, encryptor_dict).encrypt()
    assert_true(len(enc_muts) == 1)
    enc_mut = enc_muts[0]
    assert_true(enc_mut.updates[0].value.rsplit('ver',1)[-1] == groundtruth[encClass.name],
                'Not grabbing the most recent version of the key')

def _check_malformed_ciphertext_version(encClass):
    """
    Tests error handling in the case where the ciphertext does 
    not contain 'ver'
    """
    config = stringio.StringIO(
                        '[colFamily]\n'+\
                        'key_id = '+ encClass.name +'\n'+\
                        'cell_sections = colFamily,colQualifier\n'+\
                        'encryption = ' + encClass.name)
    encryptor_dict = _create_encryptor_dict(config)
    
    mut = Mutation('abcdefghijklmnopqrstuvwxyz')
    mut.put(cf='cf1',cq='cq1', cv='a&b', ts = '12345', val = 'val1')
    mut.put(cv='c|d',cf='cf2',val='val2')
    enc_mut = EncMutation(mut, encryptor_dict)
    assert_raises(DecryptionException, enc_mut.decrypt)
    
    
def _check_encrypt_decrypt_mutation(encClass):
    '''
    Tests the encrypt then decrypt functionality of the various algorithms 
    on mutations 
    '''
    config = stringio.StringIO(
                        '[colFamily]\n'+\
                        'key_id = '+ encClass.name +'\n'+\
                        'cell_sections = colFamily,colQualifier\n'+\
                        'encryption = ' + encClass.name)
    encryptor_dict = _create_encryptor_dict(config)
    
    mut = Mutation('abcdefghijklmnopqrstuvwxyz')
    mut.put(cf='cf1',cq='cq1', cv='a&b', ts = '12345', val = 'val1')
    mut.put(cf='cf2',cq='cq2', cv='a&b', ts = '12345', val = 'val2')
    
    enc_muts = EncMutation(mut, encryptor_dict).encrypt()
    dec_muts = []
    for enc_mut in enc_muts:
        dec_muts.append(EncMutation(enc_mut, encryptor_dict).decrypt())
    assert_true(_decrypt_mutations_equal(dec_muts, mut),
                "Mutation is not correctly handled during encryption and decryption process")
        
    assert_true(not _mutations_equal(enc_mut, mut), 
                "Encryption algorithm was identity function.")

def _check_encrypt_decrypt_cell(encClass): 
    '''
    Tests the encrypt then decryption functionality of the various algorithms
    on cells
    '''
    config = stringio.StringIO(
                        '[colFamily]\n'+\
                        'key_id = '+ encClass.name +'\n'+\
                        'encryption = ' + encClass.name)
    encryptor_dict = _create_encryptor_dict(config)   
      
    cell = Cell('row','cf','cq','(a&b)|c',1234,'val')
    
    enc_cell = EncCell.encrypt(cell, encryptor_dict)
    dec_cell = EncCell.decrypt(enc_cell, encryptor_dict)
    eq_(cell, dec_cell, 
        str(dec_cell) + " was not correctly encrypted and decrypted " +\
        "should be " + str(cell))   

def _check_ciphertext_length(encClass):
    key = b'Sixteen byte key'
    ciphertext = ''.join(random.choice(string.ascii_uppercase + string.digits) 
                         for _ in range(25))
    assert_raises(DecryptionException, encClass._decrypt, ciphertext, key)
    
def _check_iv_material(encClass):      
    key = b'Sixteen byte key'
    ciphertext = ''.join(random.choice(string.ascii_uppercase + string.digits) 
                         for _ in range(15))
    assert_raises(DecryptionException, encClass._decrypt, ciphertext, key)  
        
def _check_key_length(encClass):
    k_short = b'ShortKey'
    ciphertext = '1'+''.join(random.choice(string.ascii_uppercase + string.digits) 
                         for _ in range(31))
    assert_raises(ValueError, encClass._encrypt, ciphertext, k_short)

def _check_authentication(encClass):
    key_one = b"Sixteen Byte keySixteen Byte Key"
    key_two = b"sIXTEEN BYTE KEYSixteen Byte Key"
    plaintext = "This is the sample plaintext"
    ciphertext = encClass._encrypt(plaintext, key_one)
    assert_raises(ValueError, encClass._decrypt, ciphertext, key_two)
        
def _check_determinism(encClass):
    key = b"Sixteen Byte keySixteen Byte Key"
    plaintext_one = "This is a sample, shall we test?"
    plaintext_two = "this is a different sample"
    
    ciphertext_one = encClass._encrypt(plaintext_one, key)
    ciphertext_two = encClass._encrypt(plaintext_one, key)
    ciphertext_three = encClass._encrypt(plaintext_two, key)
    
    assert_equal(ciphertext_one, ciphertext_two)
    assert_not_equal(ciphertext_one, ciphertext_three)
    
    
def test_all_encryption_algorithms():
    
    for encClass in ALGORITHMS.values():
        yield _check_encrypt_decrypt_mutation, encClass
        yield _check_encrypt_decrypt_cell, encClass

def test_aes_encryption_algorithms():
    
    #test error handling aes alogirthms 
    for encClass in LENGTHBOUND_AES_ALGORITHMS.values():
        yield _check_ciphertext_length, encClass
    
    for encClass in IV_AES_ALGORITHMS.values():
        yield _check_iv_material, encClass 
        
    for encClass in AES_ALGORITHMS.values():
        yield _check_key_length, encClass 
        yield _check_versioning, encClass
        yield _check_malformed_ciphertext_version, encClass 
        
def test_authenticated_algorithms():
    
    for encClass in AUTH_ALGORITHMS.values():
        yield _check_authentication, encClass
        
def test_deterministic_algorithms():
    
    for encClass in DET_ALGORITHMS.values():
        yield _check_determinism, encClass


def test_aes_padding():
    '''
    Tests the padding and unpadding functions of AES class
    '''
    for n in xrange(1,100):
        s = ''.join(random.choice(string.ascii_uppercase + string.digits) 
                         for _ in range(n))
        padded_string = Pycrypto_AES_Base._pad(s)
        eq_(len(padded_string) % 16, 0, 
            'Padded string %s of length %d is not a multiple of 16.' % (padded_string, len(padded_string)))
        eq_(s, Pycrypto_AES_Base._strip_pad(padded_string),
            "Padding is not correctly stripped from padded string")
    
