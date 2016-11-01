## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Benchmark framework for encryption code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  20 Jan 2015  ATLH    Original file - Based on signature benchmarker 
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
from pyaccumulo import Accumulo, Mutation, Range
import time, datetime
import string
import cProfile
import StringIO
import pstats

from pace.encryption.acc_encrypt import AccumuloEncrypt
from pace.encryption.enc_classes import ALGORITHMS
from pace.encryption.encryption_pki import DummyEncryptionPKI
from pace.common.common_utils import generate_data, sanitize, Timer

class Benchmarker(object):
    """
    Class that contains logic for benchmarking PACE encryption code
    """
    
    def __init__(self,
                 conn=None,
                 pki=None,
                 logger=None):
        """
        Arguments:
            conn - connection to the Accumulo instance, defaults to localhost
            pki - pki object used, default is DummyEncryptionPKI
            logger - the output of the benchmarking is logged here
        """
        if conn is None:
            self.conn = Accumulo(host='localhost',
                                        port=42424,
                                        user='root',
                                        password='secret')
        else:
            self.conn = conn
            
        if pki is None:
            self.pki = DummyEncryptionPKI(conn=self.conn)
        else:
            self.pki = pki   
        self.logger = logger
    
    def _process_profile(self, profiler):
        buffer_for_results = StringIO.StringIO()        
        stats = pstats.Stats(profiler, stream=buffer_for_results)
        stats.strip_dirs().sort_stats('time').print_stats(10)
    
        msg = buffer_for_results.getvalue()
        return msg
    
    def _random_string(self, length=10):
        """
        Generates a random string of length lengths
        """
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))   
    
    def _generate_data(self, vis, num_entries, num_rows):
        """
        Arguments:
            vis - Visibility label used for the cells 
            num_entries - the number of total cells generated
            num_rows - the number of rows that num_entries are broken up into
        
        Returns: a list of num_rows mutations with total number of cells
        of num_entries
        """
        mutations = []
        #row size
        rsize = num_entries/num_rows
        for r in range(num_rows):
            mutation = Mutation(self._random_string())
            for r in range(rsize):
                mutation.put(cf=self._random_string(),
                      cq=self._random_string(),
                      cv=vis,
                      val=self._random_string(20))
            mutations.append(mutation)
        return mutations
        
    def _write_and_encrypt_data(self, 
                                table, 
                                encryptor, 
                                vis,
                                encrypt=True,
                                num_entries=50000,
                                num_rows=1000,
                                profile = False):
        """
        Arguments:
            table - the table to write the data to
            encryptor - the encryption object used to encrypt the mutations
            vis - the visibility label used in the mutations
            encrypt - to encrypt the data or not, if False it represents the baseline
            num_entries - the total number of cells generated
            num_rows - the number of rows that num_entries that are broken up into
            profile - to profile the code or not 
        
        Results:
            Logs the timing into the output file
        """
        #delete table if it exists and recreate it 
        if self.conn.table_exists(table): 
            self.conn.delete_table(table)
        
        self.conn.create_table(table)
        
        mutations = self._generate_data(vis, num_entries, num_rows)
        wr = self.conn.create_batch_writer(table)
        
        encryption_time = 0
        communication_time = 0
        profiler_string = ''
        
        if encrypt:
            if profile:
                pr = cProfile.Profile()
                pr.enable()
            enc_mutations = []
            for m in mutations:
                with Timer() as t:
                    enc_mut = encryptor.encrypt(m)
                enc_mutations += enc_mut
                encryption_time += t.msecs
            if profile:
                pr.disable()
                profiler_string = self._process_profile(pr)
        else:
            enc_mutations = mutations
        for mut in enc_mutations: 
            with Timer() as t:
                wr.add_mutation(mut)
            communication_time += t.msecs
             
        wr.close()
    
        return (encryption_time, communication_time, profiler_string)
    
    
    def _decrypt_data(self,  table, decryptor, decrypt=True, profile=False):  
        """
        Arguments:
            table - the table to read from
            decryptor - the decryption object used to encrypt the mutations
            decrypt - to decrypt the data or not, if False it represents the baseline
            profile - to profile code or not
        
        Results:
            Logs the timing into the output file
        """
        if not self.conn.table_exists(table): 
            return (False, 0, 0)
            
        cells = []  
        with Timer() as t:  
            for entry in self.conn.scan(table, auths=['a','b','c','d','e']):
                cells.append(entry)
        communication_time = t.msecs
        
        decryption_time = 0
        dec_error = 0
        profiler_string = ''

        if decrypt:
            if profile:
                pr = cProfile.Profile()
                pr.enable()
            for cell in cells:
                with Timer() as t:
                    try:
                        dec_entry = decryptor.decrypt(entry)
                    except DecryptionException as ve:
                        dec_error += 1
                decryption_time += t.msecs
            if profile:
                pr.disable()
                profiler_string = self._process_profile(pr)
                
        success = dec_error < 1 and len(cells) > 0

        return (success, decryption_time, communication_time, profiler_string)

    def run_test(self,
                 config_file,
                 table="encrypt_test",
                 vis='a&b',
                 num_entries=1000,
                 num_rows=100,
                 encrypt=True,
                 decrypt=True,
                 profile=False):
        """
        Arguments:
            config_file - configuration file to be used
            table - the table to write the data to
            vis - the visibility label used in the mutations
            decrypt - to decrypt the data or not, if False it represents the baseline
            encrypt - to encrypt the data or not, if False it represents the baseline
            num_entries - the total number of cells generated
            num_rows - the number of rows that num_entries that are broken up into
            profile - whether to profile the code 
        
        Results:
            Logs the timing into the output file
        """
        
        table = sanitize(table)

        self.logger.info("Running with %d cells and %d rows" % (num_entries, num_rows))
        
        if encrypt:
            encryptor = AccumuloEncrypt(config_file, self.pki)
            (encryption_time, communication_time, profile_string) = self._write_and_encrypt_data(table, 
                                                                                encryptor, 
                                                                                vis,
                                                                                True,   
                                                                                num_entries,
                                                                                num_rows,
                                                                                profile)
            
            self.logger.info('Encryption & communication timing for %s: %d, %d' % 
                             (config_file, encryption_time, communication_time))
            if profile:
                self.logger.info("Profile for %s is : %s" % (config_file, profile_string))
        if decrypt:
            decryptor = AccumuloEncrypt(config_file, self.pki)
            (sucess, decryption_time, communication_time, profile_string) = self._decrypt_data(table, decryptor, True, 
                                                                               profile)
            if sucess:
                self.logger.info('Decryption & communication timing for %s: %d, %d' %
                                 (config_file, decryption_time, communication_time))
                if profile:
                    self.logger.info("Profile for %s is : %s" % (config_file, profile_string))
            else:
                self.logger.info("Was not able to sucessfully decrypt for %s" % (config_file))
            
        if not encrypt and not decrypt:
            (encryption_time, communication_time, _) = self._write_and_encrypt_data(table, 
                                                                                None, 
                                                                                vis,
                                                                                False,   
                                                                                num_entries,
                                                                                num_rows)
            self.logger.info('Communication timing for writing to baseline: %d' % (communication_time))
            
            (sucess, decryption_time, communication_time, _) = self._decrypt_data(table, None, False)
            self.logger.info('Communication timing for reading from baseline: %d' % (communication_time))


