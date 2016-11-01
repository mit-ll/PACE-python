## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Definition of encrypted mutation and cells 
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   19 Dec 2014  ATLH    Original file
##   30 Dec 2014  ATLH    Added EncCell
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import itertools
import copy
from collections import defaultdict
from pyaccumulo import Mutation, Cell, Range
from operator import methodcaller

from pace.encryption.encryption_exceptions import EncryptionException, DecryptionException
from pace.encryption.vars import DELIN_CHAR, CELL_MUT_MAPPING, DET_ALGORITHMS, VALID_KEYS, CELL_ORDER

class EncMutation(Mutation): 
    '''
    Contains the data structures and logic for 
    applying encryptors to a mutation 
    '''
    def __init__(self, mut, encryptor_dict):
        '''
        Arguments
        mut - mutation as defined in pyaccumulo
             interface 
        encryptor_dict - dictionary keyed by cell location
             containing a tuple of the encryptor class and 
             key_id used for encryption or decryption. Also
             contains the key object for retrieving the key
        '''
        self._encrypted = False
        self._num_updates = len(mut.updates)
        self.encryptor_dict = encryptor_dict 
        
        #lists of updates grouped by cell location 
        self.update_dict = {}
        self.update_dict['row'] = [mut.row] * len(mut.updates)
        self.update_dict['colFamily'] = [u.colFamily for u in mut.updates]
        self.update_dict['colQualifier'] = [u.colQualifier for u in mut.updates]
        self.update_dict['colVisibility'] = [u.colVisibility for u in mut.updates]
        self.update_dict['timestamp'] = [u.timestamp for u in mut.updates]
        self.update_dict['value'] = [u.value for u in mut.updates]
        self.update_dict['deleteCell'] = [u.deleteCell for u in mut.updates]
    
    #methods to allow object to be treated as dict
    def __getitem__(self, key):
        return self.update_dict[key]
    
    def __setitem__(self, key, value):
        self.update_dict[key] = value 
        
    def __iter__(self):
        for list in [self.update_dict['row'],
                     self.update_dict['colFamily'],
                     self.update_dict['colQualifier'],
                     self.update_dict['colVisibility'],
                     self.update_dict['timestamp'],
                     self.update_dict['value'],
                     self.update_dict['deleteCell']]:
            yield list
        
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.update_dict == other.update_dict
        else:
            return False
        
    def __ne__(self, other):
        return not self.__eq__(other)
        
    @staticmethod   
    def concatenate_cell_section_values(mutation, cell_sections):
        '''
        Arguments:
        mutation - Mutation which one wants to extract
        the list of all the same cell locations
        cell_sections - the location(s) that need to be 
        extracted from the mutation
        
        Returns: a list of all of the cell locations 
        for that mutation (taking into account all of
        the cell's updates). If there is more then one
        location, it is a list of the value concatenated
        by the DELIN_CHAR character. 
        
        For example: 
            mut = Mutation('abcd')
            mut.put(cf='cf1',cq='cq1', cv='cv1', ts = '12345', val = 'val1')
            mut.put(cf='cf2',val='val2')
        and 
            cell_sections = [colFamily, value]
        this function would return: 
            ['cf1|val1','cf2|val2']
        '''
        sections = [mutation[sec] for sec in cell_sections]
        return [DELIN_CHAR.join(map(str, u)) for u in zip(*sections)]
    
    @staticmethod
    def split_values(values):
        '''
        Arguments:
        values - A list of values constructed by 
        get_values_by_cell_string in which individual entries
        are made of cell values concatenated by the DELIN_CHAR
        
        Returns: A list of tuples, the first list consisting of 
        the first values marked by the DELIN_CHAR, the second list
        the second values in the entries, and so on. For example
        the list ['a|b|c', "1|2|3"] would return [(a,1), (b, 2), 
        (c, 3)]. 
        '''
        return zip(*map(methodcaller('split', DELIN_CHAR), values))
    
    def _remove_unencrypted_cell_sections(self, updates):
        """
        Compares the list of targeted locations (where encrypted
        values are stored) to the locations that are actually 
        encrypted as part of subsets. If there are any locations
        that were included in part of a subset that weren't over
        written with encrypted data, it removes the original,
        unencrypted data, and replaces it with a list of empty
        strings as long as the original list of updates.
        """
        source_locations = set()
        target_locations = set()
        for (cell_string, encryptor) in self.encryptor_dict.items():
            source_locations.update(encryptor.cell_sections)
            target_locations.add(cell_string)
        
        for sec in (source_locations - target_locations):
            updates[sec] = list(itertools.repeat("", self._num_updates))
            
        return updates
            
    def _get_key(self, key_id):
        """
        Helper function that acquires the key from the key object for
        encryption/decryption. Raises PKI Lookup error if the key_id
        does not return a key for this particular user
        """
        return self._key_object.get_key(key_id)
    
    def encrypt(self):
        '''
        Returns a list of new mutations. Each portion of the cell that 
        has an associated encryptor is encrypted. 
        ''' 
        #only want to encrypt the values once
        if not self._encrypted:
            self._encrypted = True 
            enc_updates = self.update_dict.copy()
            for (cell_string, encryptor) in self.encryptor_dict.items():
                enc_updates[cell_string] = encryptor.encryption.encrypt_mutation(self, 
                                                      encryptor.key_container,
                                                      encryptor.cell_sections)     
            self.update_dict = self._remove_unencrypted_cell_sections(enc_updates)
            
        #TODO: in the case where the row is deterministically encrypted
        # update to only produce one mutation
        muts = []
        for (row, cf,cq,cv,ts,v,dc) in zip(*self):
            mut = Mutation(row)
            mut.put(cf,cq,cv,ts,v,dc) 
            muts.append(mut)
        return muts
    
    def decrypt(self):
        '''
        Returns a new mutation. Each portion of the cell that 
        has an associated encryptor is decrypted. Mostly 
        used for testing.
        '''
        dec_updates = self.update_dict.copy()
        for (cell_string, encryptor) in self.encryptor_dict.items():
            encryptor.encryption.decrypt_mutation(self, 
                                                  dec_updates,
                                                  encryptor.key_container,
                                                  cell_string,
                                                  encryptor.cell_sections)
        
        self.update_dict = dec_updates
        #only should be one cell since each encrypted mutation only contains one cell
        assert len(self.update_dict['row']) == 1
        mut = Mutation(self.update_dict['row'][0])
        for (row, cf,cq,cv,ts,v,dc) in zip(*self):
            mut.put(cf,cq,cv,ts,v,dc) 
        return mut
 
#create a default empty dictionary with the empty string as default
#used in EncRange 
def constant_empty():
    return itertools.repeat('').next

 
class EncRange(Range):
    '''
    Contains the logic for encrypting and decrypting a range object only
    in the case where the algorithm is deterministic, otherwise does not
    change the contents of the range
    '''
    
    @staticmethod
    def get_value_by_cell_string(cols, cell_sections):
        '''
        Arguments:
        cols - col dictionary which one wants to extract
        the list of all the same cell locations
        cell_sections - the location(s) that need to be 
        extracted from the dict
  
        Returns: a string of all of the cell_sections 
        for the range concatenated by the DELIN_CHAR
        '''
        return DELIN_CHAR.join([str(cols[sec]) for sec in cell_sections])
    
    @staticmethod
    def split_value_by_cell_string(value):
        return value.split(DELIN_CHAR)
    
    @staticmethod
    def _remove_unencrypted_cell_sections(encryptor_dict, col_dict):
        """
        Compares the list of targeted locations (where encrypted
        values are stored) to the locations that are actually 
        encrypted as part of subsets. If there are any locations
        that were included in part of a subset that weren't over
        written with encrypted data, it removes the original,
        unencrypted data, and replaces it with a list of empty
        strings as long as the original list of updates.
        """
        source_locations = set()
        target_locations = set()
        for (cell_string, encryptor) in encryptor_dict.items():
            source_locations.update(encryptor.cell_sections)
            target_locations.add(cell_string)
        
        for sec in (source_locations - target_locations):
            col_dict[sec] = ''
            
    @staticmethod
    def _valid_configuration(encryptor_dict):
        """
        Arguments:
        encryptor_dict - dictionary keyed by cell location
             containing a tuple of the encryptor class and also
             contains the key object for retrieving the key
             
        Returns: True/False whether the configuration is valid 
        for searching. For example, in the case where
        non-deterministic encryption appears
        in the ordering before either deterministic or no encryption
        an false is returned. For example:
        
            Row: no encryption
            ColFamily: Deterministic 
            ColQualifier: CTR_MODE
        
        would return true, but:
        
            Row: CTR_MODE
            ColFamily: Deterministc
            ColQualifier: No encryption
        would.
        """
        det_encryptions = 0
        for cell_string in VALID_KEYS:
            
            #case of no encryption
            try:
                encryptor = encryptor_dict[cell_string]
            except KeyError:
                det_encryptions += 1
                continue 
            
            #case of non-deterministic encryption
            if encryptor.encryption.name not in DET_ALGORITHMS:
                break
            
            det_encryptions +=1
    
        return det_encryptions != 0

    @staticmethod
    def encrypt(row, cols, encryptor_dict):
        '''
        Arguments:
        row - the row to search for, this will be passed in as both
            the start and end row into 'scan'
        cols - double nested list of what columns
            to look for, where the first element in the 
            column_family, the second is the column_qualifier. 
            Defaults to None. Example:
                  [['cf1','cq1'],['cf2','cq2']]
        encryptor_dict - dictionary keyed by cell location
             containing a tuple of the encryptor class and also
             contains the key object for retrieving the key
        
        Returns: (encrypted_start_row, encrypt_end_row, encrypted_col_list)
        as per the the configuration specifies. If it does not specify 
        any of the above values, they are left unchanged.
        
        In the case where non-deterministic encryption appears
        in the ordering before either deterministic or no encryption
        an error is raised. For example:
        
            Row: no encryption
            ColFamily: Deterministic 
            ColQualifier: CTR_MODE
        
        would not raise an error, but:
        
            Row: CTR_MODE
            ColFamily: Deterministc
            ColQualifier: No encryption
            
        would. 
        '''
        if not EncRange._valid_configuration(encryptor_dict):
            raise EncryptionException('Cannot encrypt a range object in which the configuration '+\
                                      'has the leading portion of the key not either unencrypted ' +\
                                      'or deterministically encrypted.')
       
        #check to see if the row is being encrypted
        if encryptor_dict.has_key('row'):
            encryptor = encryptor_dict['row']
            row = encryptor.encryption.encrypt_row(row, encryptor.key_container)       
            
        enc_cols = []
        if cols == None:
            return (row, None)
        
        
        for col in cols:
            col_dict = defaultdict(constant_empty())
            for (key, value) in zip(['colFamily','colQualifier'], col):
                col_dict[key]=value
            enc_col = col_dict.copy()
            for cell_string in ['colFamily', 'colQualifier']:
                try:
                    encryptor = encryptor_dict[cell_string]
                except KeyError:
                    continue 

                enc_col[cell_string] = encryptor.encryption.encrypt_cols(col_dict, 
                                                 encryptor.key_container,
                                                 encryptor.cell_sections)
            #convert back into a list 
            EncRange._remove_unencrypted_cell_sections(encryptor_dict, enc_col)
            if not enc_col.has_key('colQualifier'):
                enc_cols.append([enc_col['colFamily']])
            else: 
                enc_cols.append([enc_col['colFamily'], enc_col['colQualifier']])
                
        return (row, enc_cols)
    
    
class EncCell(Cell):
    '''
    Contains the logic for encrypting and decrypting a single cell
    '''
    @staticmethod
    def get_value_by_cell_string(cell, cell_sections):
        return DELIN_CHAR.join([str(cell[CELL_MUT_MAPPING[sec]]) for sec in cell_sections])
    
    @staticmethod
    def split_value_by_cell_string(value):
        return value.split(DELIN_CHAR)
        
    
    @staticmethod 
    def encrypt(cell, encryptor_dict):
        '''
        Arguments:
        cell - cell to be encrypted
        encryptor_dict - dictionary keyed by cell location
             containing a tuple of the encryptor class and also
             contains the key object for retrieving the key
        Returns new cell with all locations in cell encrypted
        that are noted in encryptor_dict
        '''
        cell_dict = cell._asdict()
        enc_cell = cell_dict.copy()
        for (cell_string, encryptor) in encryptor_dict.items():
            enc_cell[CELL_MUT_MAPPING[cell_string]] = encryptor.encryption.encrypt_cell(cell_dict, 
                                                     encryptor.key_container, 
                                                     encryptor.cell_sections)
        return Cell(*[enc_cell[field] for field in CELL_ORDER])
  
    @staticmethod 
    def decrypt(cell, encryptor_dict):
        '''
        Arguments:
        cell - cell to be encrypted
        encryptor_dict - dictionary keyed by cell location
             containing a tuple of the encryptor class and also
             contains the key object for retrieving the key
        Returns new cell with all locations in cell decrypted
        that are noted in encryptor_dict
        '''
        cell_dict = cell._asdict()
        dec_cell = cell_dict.copy()
        for (cell_string, encryptor) in encryptor_dict.items():
            encryptor.encryption.decrypt_cell(cell_dict, 
                                              dec_cell,
                                              encryptor.key_container,
                                              cell_string,
                                              encryptor.cell_sections)
        return Cell(*[dec_cell[field] for field in CELL_ORDER])
            


        
