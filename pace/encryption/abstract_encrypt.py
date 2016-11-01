## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Abstract class for encryption modules
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   17 Dec 2014  ATLH    Original file 
##   12 Mar 2015  ATLH    Removed AES into own file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import fractions 
from abc import ABCMeta, abstractmethod
from Crypto.Cipher import AES
from Crypto.Util import Counter, number
from Crypto import Random 
from pyaccumulo import Cell

from pace.encryption.enc_mutation import EncMutation, EncCell
from pace.encryption.vars import CELL_MUT_MAPPING
from pace.encryption.encryption_exceptions import EncryptionException, DecryptionException


class AbstractEncrypt(object):
    """Abstract interface for all encryption modules 
    that (may) interact with the Accumulo Encryption module. 
    Key management is assumed to be seperate and keys must be
    an input into this class.
    """
    __metaclass__ = ABCMeta
    
    """
    Name of algorithm as accepted in the configuration file 
    """
    name = ''
    
    @abstractmethod
    def encrypt_mutation(mutation, key, cell_sections):
        '''
        Arguments: 
        mutation - mutation as defined in encmutation (based on
              pyaccumulo interface 
        key - key in whatever format is used for particular
              encryption scheme 
        cell_sections - the list of part of the cell to be encrypted.
              Options are defined in VALID_KEYS in vars.py. 
              
        
        Returns: The ciphertext. For example if 
              cell_sections was [colFamily, colQualifier] and 
              cell_location is 'colFamily'. Let the first update 
              be cf = 'cf1', and cq = 'cq1', the resulting update
              would become cf = 'cf1|cq1' (encrypted) and cq = ''. 
              This is done for each update in the list of updates.              
        '''
        pass 
    
    @abstractmethod
    def decrypt_mutation(mutation, dec_mutation, key, cell_location, cell_sections):
        '''
        Arguments: 
        mutation - mutation as defined in encmutation (based on
              pyaccumulo interface 
        dec_mutation - the location where the decrypted information
            in mutation is stored upon decryption 
        key - key in whatever format is used for particular
              encryption scheme
        cell_location - the part of the cell where encrypted data is
              to be stored
        cell_sections - the target locations for decrypted data that
              contained at the cell_location. 
        
        Effect: The dec_mutation is modified. The encrypted data
              cell_location is decrypted and seperated into 
              the values associated with each of the cell_sections.
              These values are then placed in the cell as 
              specified by cell_sections. 
              
              For example, cell_location = 'cq' and cell_sections =
              [colFamily, colQualifier, value] and the cq for 
              the first update is 'cf1|cq1|val1' the three 
              values are separated out and the update becomes
              cf = 'cf1', cq = 'cq1', and val = 'val1'.
        ''' 
        pass 
    
    @abstractmethod
    def encrypt_row(row, key):
        """
        Arguments:
        row - (string) row to be encrypted 
        key - key in whatever format is used for particular
              encryption scheme 
              
        Returns: encrypted row used to scan the database 
        for deterministically encrypted row. 
        """
        pass
    
    @abstractmethod
    def encrypt_cols(cols, key_container,  cell_sections):
        """
        Arugments:
        cols: dictionary keyed by 'colFamily' and 'colQualifier'
            containing the respective values (defined in the 
            nested list passed into acc_encrypt) that are
            to be encrypted. If colQualifier is not specified
            in the input list, the value defaults to ''
        key_container - key container to obtain the encryption key
        cell_sections - the target locations for decrypted data that
              contained at the cell_location. 
              
        Returns: encrypted portion of the column as specified
        by cell_sections
        """
        pass

    
    @abstractmethod
    def encrypt_cell(cell, key, cell_sections):
        '''
        Arguments: 
        cell - DecCell as defined in enc_mutation (based on
              pyaccumulo interface 
        key - key in whatever format is used for particular
              encryption scheme 
        cell_sections - the list of part of the cell to be encrypted.
              Options are defined in VALID_KEYS in vars.py.
        
        Returns: encrypted portion of the cell
        '''
        pass 
    
    @abstractmethod
    def decrypt_cell(cell_dict, dec_cell, key, cell_location, cell_sections):
        '''
        Arguments: 
        cell_dict - dictionary containing field names as 
              keys, and the values to be decrypted
        dec_cell - dictionary where the decrypted values
            are placed
        key - key in whatever format is used for particular
              encryption scheme 
        cell_location - the part of the cell where encrypted data is
              to be stored 
        cell_sections - the target locations for decrypted data that
              contained at the cell_location. 
        
        Returns: The dec_cell is modified. The encrypted data
              cell_location is decrypted and seperated into 
              the values associated with each of the cell_sections.
              These values are then placed in the cell as 
              specified by cell_sections. 
        '''
        pass 
    
    
class Identity_AccEncrypt(AbstractEncrypt):    
    '''
    Identity function as encryption algorithm, used for
    testing
    '''
    name = 'Identity'
    
    @staticmethod
    def encrypt_mutation(mutation, key, cell_sections):
        ctexts = EncMutation.concatenate_cell_section_values(mutation, cell_sections)
        return ctexts
     
    @staticmethod
    def decrypt_mutation(mutation, dec_mutation, key, cell_location, cell_sections):
        ptexts = mutation[cell_location]
        split_values = EncMutation.split_values(ptexts)
        for sec, values in zip(cell_sections, split_values):
            dec_mutation[sec] = list(values)
    
    @staticmethod
    def encrypt_row(row, key_container):
        return row
    
    @staticmethod
    def encrypt_cols(cols, key_container, cell_sections):
        return cols
    
    @staticmethod
    def encrypt_cell(cell, key, cell_sections):
        return EncCell.get_value_by_cell_string(cell,cell_sections)
    
    @staticmethod
    def decrypt_cell(cell, dec_cell, key, cell_location, cell_sections):
        split_value = EncCell.split_value_by_cell_string(cell[CELL_MUT_MAPPING[cell_location]])
        for (sec, value) in zip(cell_sections, split_value):
            dec_cell[CELL_MUT_MAPPING[sec]] = value

    @staticmethod 
    def _encrypt(plaintext, key):
        return plaintext
    
    @staticmethod
    def _decrypt(ciphertext, key):
        return ciphertext
    
    @staticmethod 
    def encrypt(plaintext, key):
        return plaintext
    
    @staticmethod
    def decrypt(ciphertext, key):
        return ciphertext
    

        
