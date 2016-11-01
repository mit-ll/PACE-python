## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: High level module for encrypting records
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   18 Dec 2014  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import ConfigParser
from StringIO import StringIO
from collections import namedtuple
from pace.encryption.vars import VALID_KEYS
from pace.encryption.enc_classes import ALGORITHMS
from pace.encryption.enc_mutation import EncMutation, EncCell, EncRange

Keytor = namedtuple('Keytor',['key_id','key_object','cell_key_length'])
"""
Key container object, used to encapsulate the information needed to obtain a key for a 
particular user and algorithm and/or generate a cell_key if the algorithm is a VIS_*
    key_id - the identifier passed into the key object, usually the algorithm name
    key_object - a handle on an instance of an EncryptionPKI object 
    cell_key_length - (int) for VIS_* algorithm, length in bytes 
                    (not bits) of the cell_key to be generated. 
"""

Encryptor = namedtuple('Encryptor', ['encryption', 'cell_sections', 'key_container'])
"""
Container object that is used to contain all the information to encrypt a portion of the
cell.
    encryption - class instance to be used for that particular portion of the cell
    cell_sections - the portions of the cell to encrypt, can be multiple portions 
                    of the cell
    key_container - contains a (Keytor) object which is used to extract the necessary
                    key material
"""

class ConfigurationException(Exception):
    """ Exception raised when unable to process configuration file
        
        Attributes:
            msg - error message for situation
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class AccumuloEncrypt(object):
    """High level interface for encrypting/decrypting accumulo cells. 
    Parametrized by a configuration file and a separate 
    key management object. 
    """
    def __init__(self, config, key_object):
        """
        Arguments:
        config - configuration file in the format specified
        by INI files, see README for more details. 
        key_object - key management object that meets the
        interface outlined in encryption_pki.py
        """
        self.config_parser = ConfigParser.ConfigParser()
        
        #support for StringIO for testing
        if isinstance(config, StringIO):
            self.config_parser.readfp(config)
        else:
            self.config_parser.read(config)
            
        self.key_object = key_object 
        self.encrypt_dict = self._config_to_encryptor(self.config_parser,
                                                      self.key_object)
        
    @staticmethod 
    def _config_to_encryptor(config_parser, key_object):
        '''
        Converts configuration file into associated encryptor
        objects for each part of key
        '''
        for sec in config_parser.sections():
            #make sure all sections correspond to part of key
            if sec not in VALID_KEYS:
                raise ConfigurationException(
                             "%s is not a valid part of the key" % sec) 
            #check to see if encryption specified 
            if not config_parser.has_option(sec, 'encryption'):
                raise ConfigurationException(
                             "No encryption set for %s" % sec)
            #make sure identifier information for key_object 
            if not config_parser.has_option(sec, 'key_id'):
                raise ConfigurationException(
                            "There is no key idenfier information for"+
                            "key_object")
            #make sure algorithm is supported 
            algorithm = config_parser.get(sec,'encryption')
            if algorithm not in ALGORITHMS.keys():
                raise ConfigurationException(
                       "%s is not a supported encryption algorithm" % algorithm)
             
       
        keys = config_parser.sections()
        encryptors = []
        for sec in config_parser.sections():
            #check if cell_sections exists, if not, just use the current section
            if config_parser.has_option(sec,'cell_sections'):
                cell_sections = config_parser.get(sec,'cell_sections').split(',')
            else:
                cell_sections = [sec]
            
            #check if cell_key_length has been specified, if not, use 16 bytes
            if config_parser.has_option(sec, 'cell_key_length'):
                cell_key_length = config_parser.get(sec,'cell_key_length')
                try:
                    cell_key_length = int(cell_key_length)
                except ValueError:
                    raise ConfigurationException('%s is not an valid integer for key_length' % cell_key_length)
                if cell_key_length not in [16,24,32]:
                    raise ConfigurationException('Key_length must be 16,24,or 32 bytes long')
            else:
                cell_key_length=16
                
            if not all([cell_sec in VALID_KEYS for cell_sec in cell_sections]):
                    raise ConfigurationException("At least one of cell_sections ("+\
                                                 str(cell_sections)+\
                                                 ") are not a valid part of a cell")
            encryptors.append(Encryptor(ALGORITHMS[config_parser.get(sec,'encryption')],
                                            cell_sections,
                                            Keytor(config_parser.get(sec,'key_id'), 
                                                   key_object,
                                                   cell_key_length)))
        if keys == [] or encryptors == []:
            raise ConfigurationException("Configuration was not properly parsed")
                                
        return dict(zip(keys, encryptors))
   
        
    def encrypt(self, mutation):
        """
        Arugments:
        mutation - an plaintext mutation as defined in the 
        pyaccumulo interface
        
        Returns: A list of new mutations containing the encrypted data
        as specified in the configuration file
        """
        enc_mut = EncMutation(mutation, self.encrypt_dict)
        return enc_mut.encrypt()
    
    def encrypt_search(self, row, columns = None):
        '''
        Functionality to help users to search over
        deterministically encrypted data. Can only
        be used to retrieve one row at a time.
        Because order is not guarenteed in the supported
        deterministic modes
        
        Arguments:
        row - the row to search for, this will be passed in as both
            the start and end row into 'scan'
        columns - double nested list of what columns
            to look for, where the first element in the nested list is 
            the column_family, the second is the column_qualifier. 
            It is possible to just specify the column_family.
            Defaults to None. Example:
                  [['cf1','cq1'],['cf2']]
        
        
        Returns: A tuple containing two things: 
            1) the encrypted row value if is deterministically encrypted
            2) A similarly formatted list of columns if they
                are deterministically encrypted and the value
                passed in is not None. If the columns parameter
                is None (as in the default case) None is returned 
                as the second part of the tuple. 
        '''
        return EncRange.encrypt(row, columns, self.encrypt_dict)
        
        
    def decrypt(self, cell):
        """
        Arugments:
        mutation - an cell as defined in pyaccumulo
        
        Returns: New cell containing the decrypted data
        as specified in the configuration file
        """
        return EncCell.decrypt(cell, self.encrypt_dict)

    
