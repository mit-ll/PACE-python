## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Unit tests for secret_vis_tree.py
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  6 Mar 2015  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import unittest
from Crypto import Random 
from pace.encryption.acc_encrypt import Encryptor, Keytor
from pace.encryption.AES_encrypt import Pycrypto_AES_CBC
from pace.encryption.visibility.vis_parser import VisParser
from pace.encryption.encryption_pki import DummyEncryptionPKI
from pace.pki.abstractpki import PKILookupError
from pace.encryption.visibility.secret_vis_tree import SecretVisNode, SecretVisTree, SecretVisParser, SecretVisTreeEncryptor

class DummyKeys(object):
    def __init__(self, terms):
        self.keys={'a':'A',
                   'b':'B',
                   'c':'C',
                   'd':'D',
                   'e':'E'}
        self.terms = terms
        
    def get_current_attribute_key(self, algorithm, attribute):
        if attribute not in self.terms:
            raise PKILookupError('Nope')
        return self.keys[attribute]
    
    def get_attribute_key(self, algorithm, attribute, version=1):
        if attribute not in self.terms:
            raise PKILookupError('Nope')
        return self.keys[attribute]
    
class SecretVisTreeTest(unittest.TestCase):
    
    def test_optimal_path(self):
        '''
        Test the optimal path functionality
        '''
        expressions = [('a&b',['a','b'],'a&b'),
                       ('a&b&c', ['a','b'],''),
                       ('a|b', ['a'], 'a'),
                       ('a|b|c',['a','b'], 'a'),
                       ('(a&b)|c',['a','b'], '(a&b)'),
                       ('(a&b)|c',['c'], 'c'),
                       ('(a|b)&c',['a','c'], '(a)&c'),
                       ('(a|b)&c',['a'], ''),
                       ('(a&b)|(b&c)',['b','c'],'(b&c)'),
                       ('(a|b)&(c|d)',['a','d'],'(a)&(d)'),
                       ('((a&b)|c)&(d|e)',['c','e'],'(c)&(e)')]
        
        parser = VisParser()
        share_parser = SecretVisParser()
        for (e, t, g) in expressions:
            vis_tree = parser.parse(e)
            share_tree = SecretVisTree(vis_tree.root,
                                       vis_tree.expression, 
                                       secret=Random.get_random_bytes(16))
            share_tree.compute_shares()
            share_tree.set_attributes(vis_tree)
            (match, opt_tree, keys) = share_tree.optimal_decryption_tree(Keytor('VIS_AES_CBC',DummyKeys(terms=t),16),
                                                                     encrypted=False) 
            self.assertEqual(g, opt_tree.__str__(),   
                             "Optimal tree for %s: %s should be %s" % 
                             (e,opt_tree.__str__(),g))
            
    def test_compute_shares(self):
        '''
        Tests computing the shares
        '''
        expressions = ['a&b',
                       'a&b&c',
                       'a|b',
                       'a|b|c',
                       '(a&b)|c',
                       '(a|b)&c',
                       'a|(b&c)',
                       'a&(b|c)',
                       '(a&b)|(b&c)',
                       '(a|b)&(c|d)',
                       '"test&|"&b',
                       '((a&b)|c)&(d|e)']
        parser = VisParser()
        for e in expressions:
            tree = parser.parse(e)
            secret = Random.get_random_bytes(16)
            secret_tree = SecretVisTree(tree.root, e, secret=secret)
            secret_tree.compute_shares()
            
            #Test for correct share
            self.assertTrue(secret_tree.verify_shares(), 
                            "Shares %s did not verify for expression %s." %
                             (secret_tree.print_shares(), e))
           
            #Test for incorrect share
            secret_tree.root.share = 0 
            self.assertFalse(secret_tree.verify_shares(), 
                            "Shares %s did incorrectly verify for expression %s." %
                             (secret_tree.print_shares(), e))


    def test_encrypt_decrypt(self):
        '''
        Tests encrypting and decrypting the shares 
        '''
        DummyPKI = DummyEncryptionPKI()
        
        expressions = ['a&b',
                       'a&b&c',
                       'a|b',
                       'a|b|c',
                       '(a&b)|c',
                       '(a|b)&c',
                       'a|(b&c)',
                       'a&(b|c)',
                       '(a&b)|(b&c)',
                       '(a|b)&(c|d)']
        
        
        for e in expressions:
            secret = Random.get_random_bytes(16)
            encrypted_shares = SecretVisTreeEncryptor.encrypt_secret_shares(e,
                                                                            secret,
                                                                            Keytor('VIS_AES_CBC',DummyPKI,16),
                                                                            Pycrypto_AES_CBC)
            share = SecretVisTreeEncryptor.decrypt_secret_shares(e, 
                                                          encrypted_shares,
                                                          Keytor('VIS_AES_CBC',DummyPKI,16),
                                                          Pycrypto_AES_CBC)
            self.assertEqual(share, secret)
            