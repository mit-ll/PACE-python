## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Class for encryption via vis expression
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   12 Mar 2015  ATLH  Original File
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from Crypto import Random
from Crypto.Cipher import AES
from pyaccumulo import Cell
from pace.encryption.enc_mutation import EncMutation, EncCell
from pace.encryption.vars import CELL_MUT_MAPPING, CELL_ORDER 
from pace.encryption.AES_encrypt import Pycrypto_AES_CTR, Pycrypto_AES_OFB, \
    Pycrypto_AES_CFB, Pycrypto_AES_CBC, Pycrypto_AES_GCM
from pace.encryption.abstract_encrypt import AbstractEncrypt, \
    EncryptionException, DecryptionException, Identity_AccEncrypt
from pace.encryption.visibility.secret_vis_tree import SecretVisTreeEncryptor

class Vis_Encrypt_Mixin(AbstractEncrypt):
    
    @classmethod
    def _encrypt_with_shares(cls, plaintext, key_id, vis_expr):
        '''
        Arguments:
        plaintext - plaintext portion of the cell to be encrypted
        key_id - the keytor object,contains a key_id and handle on the key_objection 
              to obtain the keys.
        vis_expr - visibility expression of the cell to be encrypted
        
        Returns - the encrypted shares concatenated with the ciphertext
        or the field of the cell being encrypted 
        '''
        #generate a random key for the cell 
        cell_key = Random.get_random_bytes(key_id.cell_key_length)
        #break into shares and then encrypt
        encrypted_shares = SecretVisTreeEncryptor.encrypt_secret_shares(vis_expr,
                                                                 cell_key,
                                                                 key_id,
                                                                 cls.leaf_class)
        #encrypt the plaintext 
        ciphertext = cls._encrypt(plaintext, cell_key)
        return encrypted_shares + "#" + ciphertext
    
    @classmethod
    def _decrypt_with_shares(cls, ciphertext, key_id, vis_expr):
        '''
        Arguments:
        ciphertext - string that contains the encrypted shares and
          the ciphertext of the portion of the cell
        key - the keytor object, see decrypt_mutation for more details
        vis_expr - visibility expression of the cell to be encrypted
        
        Returns - the plaintext of the cell that was encrypted
        '''
        #recover the cell_key 
        encrypted_shares = ciphertext.split('#')[0] 
        ciphertext = ciphertext[len(encrypted_shares)+1:]
        cell_key = SecretVisTreeEncryptor.decrypt_secret_shares(vis_expr,
                                                         encrypted_shares,
                                                         key_id, 
                                                         cls.leaf_class)
        if cell_key is None:
            raise DecryptionException("The key object does not contain keys for the necessary attributes to decrypt this cell")

        plaintext = cls._decrypt(ciphertext, cell_key)
        return plaintext
    
    @classmethod
    def encrypt_mutation(cls, mutation, key_id, cell_sections):
        """
        Arguments: 
        mutation - mutation as defined in encmutation (based on
              pyaccumulo interface )
        key_id - Keytor object that contains the algorithm name 
              and a key_object to obtain the keys
        cell_sections - the list of part of the cell to be encrypted.
              Options are defined in VALID_KEYS in vars.py. Can't be 
              colVisibility
              
        
        Effect: The EncMutation is modified and the encrypted data 
              stored in the cell_location. For example if 
              cell_sections was [colFamily, colQualifier] and 
              cell_location is 'colFamily'. Let the first update 
              be cf = 'cf1', and cq = 'cq1', the resulting update
              would become cf = 'cf1|cq1' (encrypted) and cq = ''. 
              This is done for each update in the list of updates.   
        
        """
        ptexts = EncMutation.concatenate_cell_section_values(mutation, cell_sections)
        vis_exprs = mutation.update_dict['colVisibility']
        if not all([vis != '' for vis in vis_exprs]):
            raise EncryptionException("There are rows without visibility labels, "+\
                                      "cannot encrypt the mutation")
        ctexts = [cls._encrypt_with_shares(ptext, key_id, vis) 
                  for (ptext, vis) in zip(ptexts,vis_exprs)] 
        return ctexts
    
        
    @classmethod
    def decrypt_mutation(cls, mutation, dec_mutation, key_id, cell_location, cell_sections):
        '''
        Arguments: 
        mutation - mutation as defined in encmutation (based on
              pyaccumulo interface )
        key_id - Keytor object that contains the algorithm name 
              and a key_object to obtain the keys
        cell_location - the part of the cell where encrypted data is
              to be stored
        cell_sections - the target locations for decrypted data that
              contained at the cell_location. 
        
        Effect: The EncMutation is modified. The encrypted data
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
        ctexts = mutation[cell_location]
        vis_exprs = mutation.update_dict['colVisibility']
        if not all([vis != None for vis in vis_exprs]):
            raise DecryptionException("There are rows without visibility labels, "+\
                                      "cannot decrypt the mutation")
        ptexts = [cls._decrypt_with_shares(ctext, key_id, vis) 
                  for (ctext, vis) in zip(ctexts,vis_exprs)] 
        split_values = EncMutation.split_values(ptexts)
        for sec, values in zip(cell_sections, split_values):
            dec_mutation[sec] = list(values) 
            
    
    @classmethod
    def encrypt_cell(cls, cell_dict, key, cell_sections):
        '''
        Arguments: 
        cell_dict - dictionary indexed by cell keywords containing the
              data to encrypt
        key - Keytor object that contains the algorithm name 
              and a key_object to obtain the keys.
        cell_sections - the list of part of the cell to be encrypted.
              Options are defined in VALID_KEYS in vars.py.
        
        Returns: the ciphertext
        '''
        ptext = EncCell.get_value_by_cell_string(cell_dict,cell_sections)
        vis_expr = cell_dict['cv']
        if vis_expr == None:
            raise EncryptionException("There are rows without visibility labels, "+\
                                      "cannot encrypt the mutation")
        return cls._encrypt_with_shares(ptext, key, vis_expr)
    
    @classmethod
    def decrypt_cell(cls, cell_dict, dec_cell, key, cell_location, cell_sections):
        '''
        Arguments: 
        cell_dict - dictionary indexed by cell keywords containg the
            data to encrypt
        dec_cell - dictionary where the decrypted data is stored
        key - Keytor object that contains the algorithm name 
              and a key_object to obtain the keys
        cell_location - the part of the cell where encrypted data is
              to be stored 
        cell_sections - the target locations for decrypted data that
              contained at the cell_location. 
        
        Effect: dec_cell is mutated with the decrypted data placed
        in the necessary locations
        '''
        vis_expr = cell_dict['cv']
        if vis_expr == None:
            raise DecryptionException("There are rows without visibility labels, "+\
                                      "cannot decrypt the mutation")
        ptext = cls._decrypt_with_shares(cell_dict[CELL_MUT_MAPPING[cell_location]],
                                         key,
                                         vis_expr)
        split_value = EncCell.split_value_by_cell_string(ptext)
        for (sec, value) in zip(cell_sections, split_value):
            dec_cell[CELL_MUT_MAPPING[sec]] = value
            
    @classmethod
    def encrypt_row(row, key):
        raise NotImplementedError("CEABAC does not currently support deterministic encryption")
    
    @classmethod
    def encrypt_cols(cols, key_container, cell_location, cell_sections):
        raise NotImplementedError("CEABAC does not currently support deterministic encryption")

    
class VIS_Identity(Vis_Encrypt_Mixin,Identity_AccEncrypt):
    name = 'VIS_Identity'
    leaf_class = Identity_AccEncrypt
    
class VIS_AES_CFB(Vis_Encrypt_Mixin,Pycrypto_AES_CFB):
    name = "VIS_AES_CFB"
    leaf_class = Pycrypto_AES_CFB
    
class VIS_AES_CBC(Vis_Encrypt_Mixin,Pycrypto_AES_CBC):
    name = "VIS_AES_CBC"
    leaf_class = Pycrypto_AES_CBC

class VIS_AES_OFB(Vis_Encrypt_Mixin,Pycrypto_AES_OFB):
    name = "VIS_AES_OFB"
    leaf_class = Pycrypto_AES_OFB
    
class VIS_AES_CTR(Vis_Encrypt_Mixin,Pycrypto_AES_CTR):
    name = "VIS_AES_CTR"
    leaf_class = Pycrypto_AES_CTR

class VIS_AES_GCM(Vis_Encrypt_Mixin,Pycrypto_AES_GCM):
    name = "VIS_AES_GCM"
    leaf_class = Pycrypto_AES_GCM

