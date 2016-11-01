## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Class for AES encryption modules
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   12 Mar 2015  ATLH  Copied from abstract_encrypt.py
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import struct, fractions 
from abc import ABCMeta, abstractmethod
from Crypto.Cipher import AES
from Crypto.Util import Counter, number
from Crypto import Random 
from pyaccumulo import Cell
from pace.encryption.enc_mutation import EncMutation, EncCell, EncRange
from pace.encryption.vars import CELL_MUT_MAPPING
from pace.encryption.abstract_encrypt import AbstractEncrypt
from pace.encryption.encryption_exceptions import EncryptionException, DecryptionException


class Pycrypto_AES_Base(AbstractEncrypt):
    '''
    Wrapper for pycrypto's AES implementation. 
    Keys must be 16, 24, or 32 bytes long.
    '''   
    
    @staticmethod
    def _encrypt(plaintext, key, iv=None):
        """ Encrypt the plaintext with the key. For modes of operation that 
            require an initialization vector (IV), the IV is generated randomly
            inside the method; the IV argument should NOT be supplied except 
            for testing purposes.
            
            Arguments:
            plaintext (byte string) - the plaintext to encrypt
            key (byte string) - the AES key
            iv (optional byte string) - the initialization vector

            Returns the encrypted data as a byte string. For modes of operation 
            that use an IV, the IV is prepended to the ciphertext.
        """
        raise NotImplementedError(
            '_encrypt is not implemented')

    @staticmethod
    def _decrypt(ciphertext, key):
        """ Decrypt the ciphertext using the key.
            
            Arguments:
            ciphertext (byte string) - the ciphertext to decrypt, with the 
                IV prepended for modes of operation that use an IV.
            key (byte string) - the AES key
            
            Returns the decrypted data as a byte string.
        """
        raise NotImplementedError(
            '_decrypt is not implemented')

    @staticmethod 
    def _pad(s):
        '''
        Returns the string padded so that its length is a multiple of 16 bytes.
        
        Appends 10* at the bit level. Following ISO/IEC 9797-1 
        - padding mode 2
        '''
        pad_len = AES.block_size - (len(s) % AES.block_size) - 1
   
        padding = chr(0x80)+'\0'*pad_len
  
        return s + padding

    
    @staticmethod
    def _strip_pad(s):
        '''
        Strips the padding from the string 
        '''
        return s.rstrip('\0')[:-1]
        
    @staticmethod 
    def _is_multiple_16(s):
        """
        Ensures string's length is a multple of 16
        """
        if not (len(s) % 16) == 0:
            raise DecryptionException("Ciphertext was not a multiple of 16 in length")  
         
    @staticmethod 
    def _has_iv_material(s):
        """
        Make sure enough material for IV in ciphertext
        """
        if len(s) < AES.block_size:
            raise DecryptionException("Ciphertext did not contain enough material for an IV")    
    
    @staticmethod
    def _get_encryption_key(key_container):
        '''
        Arguments:
        
        key_container : a (keytor) object that contains a key_id 
                and the key_object handle to look up and obtain the
                keys
        
        Returns: (key,version_number) tuple where the key is the most recent encryption
        key (byte string) and the version_number is the most current version of the key (int)
                
        Raises PKILookupError if a key for the key_id is not contained in the keyobject. 
        '''
        return key_container.key_object.get_current_key(key_container.key_id)
     
    @staticmethod
    def _get_decryption_key(key_container, version):
        '''
        Arguments:
        
        key_container: a (keytor) object that contains a key_id 
                and the key_object handle to look up and obtain the
                keys
        version: (int) version of the decryption key to obtain
        
        Returns:  key is the decryption key for that version
                
        Raises PKILookupError if a key for the key_id is not contained in the keyobject. 
        '''
        return key_container.key_object.get_key(key_container.key_id, int(version))
    
    @classmethod
    def encrypt_mutation(cls, mutation, key_container, cell_sections):
        (key, version) = cls._get_encryption_key(key_container)
        ptexts = EncMutation.concatenate_cell_section_values(mutation, cell_sections)
        #add version number delineated by 'ver'  - version is int so this is fine 
        ctexts = [cls._encrypt(ptext, key)+'ver'+str(version) for ptext in ptexts] 
        return ctexts
    
    @classmethod
    def decrypt_mutation(cls, mutation, dec_mutation, key_container, cell_location, cell_sections):
        ptexts = []
        ctexts = mutation[cell_location]
        for ctext in ctexts:
            #grab the version, delineated by last instance of 'ver'
            try: 
                (ctext, version) = ctext.rsplit('ver',1)
            except ValueError:
                raise DecryptionException('Ciphertext is not properly formatted: it '+\
                                          'does not contain version information')
            key = cls._get_decryption_key(key_container, version)
            ptexts.append(cls._decrypt(ctext, key))
        split_values = EncMutation.split_values(ptexts)
        for sec, values in zip(cell_sections, split_values):
            dec_mutation[sec] = list(values)
    
    @classmethod
    def encrypt_row(cls, row, key_container):
        (key, version) = cls._get_encryption_key(key_container)
        #add version number delineated by 'ver - version is int so this is fine 
        return cls._encrypt(row,key)+'ver'+str(version)
     
    @classmethod
    def encrypt_cols(cls, cols, key_container, cell_sections):
        (key, version) = cls._get_encryption_key(key_container)
        #add version number delineated by 'ver - version is int so this is fine 
        c_text = EncRange.get_value_by_cell_string(cols, cell_sections)
        return cls._encrypt(c_text,key)+'ver'+str(version)        
    
    @classmethod
    def encrypt_cell(cls, cell_dict, key_container, cell_sections):
        (key, version) = cls._get_encryption_key(key_container)
        ptext = EncCell.get_value_by_cell_string(cell_dict,cell_sections)
        #add version number delineated by 'ver' - version is int so this is fine 
        return cls._encrypt(ptext, key)+'ver'+str(version)

    
    @classmethod
    def decrypt_cell(cls, cell_dict, dec_cell, key_container, cell_location, cell_sections):
        #grab the version, delineated by last instance of 'ver'
        try: 
            (ctext,version) = cell_dict[CELL_MUT_MAPPING[cell_location]].rsplit('ver',1)
        except ValueError:
                raise DecryptionException('Ciphertext is not properly formatted: it '+\
                                          'does not contain version information')
        key = cls._get_decryption_key(key_container,version)
        ptext = cls._decrypt(ctext, key)
        split_value = EncCell.split_value_by_cell_string(ptext)
        for (sec, value) in zip(cell_sections, split_value):
            dec_cell[CELL_MUT_MAPPING[sec]] = value
    
    @classmethod
    def encrypt(cls, string, key):
        return cls._encrypt(string, key)
    
    @classmethod
    def decrypt(cls, string, key):
        return cls._decrypt(string, key)
        

class Pycrypto_AES_CFB(Pycrypto_AES_Base):
    '''
    Cipher Feedback Mode with 8-bit segments (pycrypto's default segment length)
    
    Wrapper for pycrypto's AES implementation. 
    Keys must be 16, 24, or 32 bytes long.
    
    IV is needed, must be random for each new
    encryption but can be made public
    '''
    
    name = 'Pycrypto_AES_CFB'
    
    @staticmethod
    def _encrypt(plaintext, key, iv=None):
        #Deal with the case when field is empty
        if plaintext is None:
            plaintext = ''
        if iv is not None and len(iv) != AES.block_size:
            raise EncryptionException('IV size must equal cipher block size')
        if iv is None:
            iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(str(plaintext))
    
    @staticmethod
    def _decrypt(ciphertext, key):
        #error handling
        Pycrypto_AES_Base._has_iv_material(ciphertext)
        
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(str(ciphertext[AES.block_size:]))     
    
class Pycrypto_AES_CBC(Pycrypto_AES_Base):
    '''
    Cipher Block Chaining 
    
    Wrapper for pycrypto's AES implementation. 
    Keys must be 16, 24, or 32 bytes long.
    
    IV is needed, must be random and can be 
    made public. The plaintext must be a 
    multiple of 16 bytes long. 
    '''
    
    name = 'Pycrypto_AES_CBC'
    
    @staticmethod
    def _encrypt(plaintext, key, iv=None):
        #Deal with the case when field is empty
        if plaintext is None:
            plaintext = ''
        if iv is not None and len(iv) != AES.block_size:
            raise EncryptionException('IV size must equal cipher block size')
        if iv is None:
            iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(Pycrypto_AES_Base._pad(plaintext))
    
    @staticmethod
    def _decrypt(ciphertext, key):
        #error handling 
        Pycrypto_AES_Base._has_iv_material(ciphertext)
        Pycrypto_AES_Base._is_multiple_16(ciphertext)
        
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return Pycrypto_AES_Base._strip_pad(cipher.decrypt(str(ciphertext[AES.block_size:])))
    
class Pycrypto_AES_OFB(Pycrypto_AES_Base):
    '''
    Output Feedback 
    
    Wrapper for pycrypto's AES implementation. 
    Keys must be 16, 24, or 32 bytes long.
    
    IV is needed, must be random for each new
    encryption but can be made public.
    '''
    
    name = 'Pycrypto_AES_OFB'
    
    @staticmethod
    def _encrypt(plaintext, key, iv=None):
        #Deal with the case when field is empty
        if plaintext is None:
            plaintext = ''
        if iv is not None and len(iv) != AES.block_size:
            raise EncryptionException('IV size must equal cipher block size')
        if iv is None:
            iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        return iv + cipher.encrypt(plaintext)
    
    @staticmethod
    def _decrypt(ciphertext, key):
        #error handling 
        Pycrypto_AES_Base._has_iv_material(ciphertext)    
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_OFB, iv)
        return cipher.decrypt(str(ciphertext[AES.block_size:]))
    
class Pycrypto_AES_CTR(Pycrypto_AES_Base):
    '''
    Counter
    
    Wrapper for pycrypto's AES implementation. 
    Keys must be 16, 24, or 32 bytes long.
    
    Counter value is needed, this should not
    be reused with the same key. Counter can
    be public.

    NIST SP 800-38A recommends generating the initial counter by setting the 
    leading 64 bits to be a message nonce and the remaining 64 bits to be a 
    block counter (starting at 1). We generate the message nonce as a 64-bit 
    random value but do not keep state to check that nonces are unique across
    messages for the same key.
    '''
    
    name = 'Pycrypto_AES_CTR'
    
    @staticmethod
    def _encrypt(plaintext, key, init_ctr=None):
        """Optional initial counter argument, to be used only for testing 
           purposes, must be the AES block length (16 bytes).
        """

        #Deal with the case when field is empty
        if plaintext is None:
            plaintext = ''

        if init_ctr is not None:
            if len(init_ctr) != AES.block_size:
                raise EncryptionException('Initial counter must be ' + 
                                          str(AES.block_size) + ' bytes')
            else:
                #Convert counter bytes to an integer (an unsigned long long), 
                #in two steps because unpack takes 8-byte (not 16-byte) input
                int1 = struct.unpack('>Q', init_ctr[:AES.block_size//2])[0]
                int2 = struct.unpack('>Q', init_ctr[AES.block_size//2:])[0]
                init_ctr_int = int1 * 2**(AES.block_size*4) + int2

        if init_ctr is None:
            #Generate 64-bit nonce randomly
            nonce = Random.new().read(AES.block_size//2)
            #Set remaining 64 bits to be a block counter starting at 1
            init_ctr = struct.pack('15s', nonce) + '\x01'
            #Compute integer version of initial counter by scaling nonce by 
            #64 bits and adding 1
            init_ctr_int = struct.unpack('>Q', nonce)[0]*2**(AES.block_size*4)+1

        ctr = Counter.new(AES.block_size*8, initial_value = init_ctr_int)
        cipher = AES.new(key, AES.MODE_CTR, counter = ctr) 
        return init_ctr + cipher.encrypt(plaintext)
    
    @staticmethod
    def _decrypt(ciphertext, key):
        #error handling
        Pycrypto_AES_Base._has_iv_material(ciphertext)
        try: 
            nonce = struct.unpack('>Q', ciphertext[:AES.block_size//2])[0]
            block_ctr = struct.unpack(
                '>Q', 
                ciphertext[AES.block_size//2 : AES.block_size])[0]
            init_ctr = nonce * 2**(AES.block_size*4) + block_ctr
        except ValueError:
            raise DecryptionException("Value for the start counter value is not an integer.")
        
        ctr = Counter.new(AES.block_size*8, initial_value = init_ctr)
        cipher = AES.new(key, AES.MODE_CTR, counter = ctr)
        return cipher.decrypt(str(ciphertext[AES.block_size:])) 
    
    
class Pycrypto_AES_GCM(Pycrypto_AES_Base):
    '''
    Galois Counter Mode 
    Wrapper for pycrypto's AES implementation. 
    Keys must be 16, 24, or 32 bytes long.
    
    Nonce is needed, should not be used again
    with the same key but does not need to be
    random. 
    
    Authenticated mode of encryption, generates
    a digest and raises a ValueError if the 
    ciphertext and digest to do not verify. 
    '''
    
    name = 'Pycrypto_AES_GCM'
    
    @staticmethod
    def _encrypt(plaintext, key, iv=None):
        #Deal with the case when field is empty
        if plaintext is None:
            plaintext = ''
        if iv is not None and len(nonce) != AES.block_size:
            raise EncryptionException('IV size must equal cipher block size')
        if iv is None:    
            iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_GCM, nonce = iv) 
        (cipher_text, digest) = cipher.encrypt_and_digest(plaintext)
        return iv + cipher_text + digest 

    @staticmethod
    def _decrypt(ciphertext, key):
        #error handling 
        Pycrypto_AES_Base._has_iv_material(ciphertext)
        
        nonce = ciphertext[:AES.block_size]
        digest = ciphertext[-AES.block_size:]
        cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
        cipher_text = str(ciphertext[AES.block_size:-AES.block_size])
        return cipher.decrypt_and_verify(cipher_text, digest)
    
class Pycrypto_AES_SIV(Pycrypto_AES_Base):
    '''
    Synthetic IV 
    
    Wrapper for pycrypto's AES SIV implementation.
    Deterministic mode of encryption, so no nonce
    used. 
    
    Keys must be either 32 bytes or 64 bytes long.
    The message does not need to be padded to a 
    multiple of 16 bytes.
  
    Authenticated mode of encryption, generates
    a digest and raises a ValueError if the 
    ciphertext and digest do not verify. 
    '''
    
    name = "Pycrypto_AES_SIV"
    
    @staticmethod
    def _encrypt(plaintext, key):
        if plaintext is None:
            plaintext = ''
        cipher = AES.new(key, AES.MODE_SIV)
        cipher_text, digest = cipher.encrypt_and_digest(plaintext)
        return cipher_text + digest 
        
    @staticmethod
    def _decrypt(ciphertext, key):
        #error handling
        Pycrypto_AES_Base._has_iv_material(ciphertext)
        
        digest = ciphertext[-AES.block_size:]
        ciphertext = str(ciphertext[:-AES.block_size])
    
        cipher = AES.new(key, AES.MODE_SIV)
        return cipher.decrypt_and_verify(ciphertext, digest)
     
    
