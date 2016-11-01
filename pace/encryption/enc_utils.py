## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Utility functions for testing the encryption code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  20 Jan 2015  ATLH    Original file - based on sign_utils
## **************
""" Utility functions and tests for mass encryption/decryption of rows written to
    Accumulo. 
    Any randomized test should use the same seed so that they are equivalent.
"""

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import time, datetime

from pyaccumulo import Accumulo, Mutation, Range
from pace.encryption.encryption_exceptions import DecryptionException
from pace.common.common_utils import generate_data, sanitize

from pace.common import common_utils

def sanitize(string):
    return common_utils.sanitize(string)

def generate_data(filename,
                  seed, 
                  num_entries=50000, 
                  num_rows=1000, 
                  vis_length=9, 
                  row_length=9):
    
    common_utils.generate_data(filename, seed, default_vis = 'a&b', 
                               num_entries = num_entries,
                               num_rows = num_rows,
                               vis_length = vis_length,
                               row_length = row_length)

def write_and_encrypt_data(file_in, conn, table, encryptor, benchmark=False):

    #Get the lines from the file
    print "Opening file", file_in
    f = open(file_in, 'r')
    lines = f.readlines()
    f.close()
    assert lines
    print "Lines (%d) are now in memory." %len(lines)
    #create the table if it doesn't exist yet
    if not conn.table_exists(table):
        conn.create_table(table)
        print table, 'table created'
    print "Beginning write."

    wr = conn.create_batch_writer(table)
    row = '340930563???poitapeoita'
    m = None

    if benchmark:
        print "Starting encrypting..."
        start = time.clock()
         
    mutations = []
    for l in lines:
        pieces = l.split('\t')
        if (row != pieces[0]):
            if m:
                mutations.append(m)
            row = pieces[0]
            m = Mutation(row)
        vis = pieces[3]  
        m.put(cf=pieces[1], cq=pieces[2], cv=vis, val=pieces[4][:-1])
    mutations.append(m)
    
    if benchmark:
        print "Starting encrypting..."
        start = time.clock()
        
    for m in mutations:
        wr.add_mutation(encryptor.encrypt(m))
        
    if benchmark:
        end = time.clock()
        print "Encrypting finished!"
       
    wr.close()

    print "Write completed."

    if benchmark:
        return (start, end)

def write_data(file_in, conn, table, benchmark=False):
    """ Just writes the data without signing it.
    """

    #Get the lines from the file
    f = open(file_in, 'r')
    lines = f.readlines()
    f.close()
    
    #create the table if it doesn't exist yet
    if not conn.table_exists(table):
        conn.create_table(table)

    wr = conn.create_batch_writer(table)
    m = None
    
    mutations = []
    for l in lines:
        pieces = l.split('\t')
        row = pieces[0]
        m = Mutation(row)
        vis = None  
        m.put(cf=pieces[1], cq=pieces[2], cv=pieces[3], val=pieces[4][:-1])
        mutations.append(m)
    if benchmark:
        print "Starting writing..."
        start = time.clock()  
        
    for m in mutations:
        wr.add_mutation(m)
        
    if benchmark:
        print "Done writing ..."
        end  = time.clock()
    wr.close()
    
    if benchmark:
        return (start,end)

def decrypt_data(conn, table, decryptor, benchmark=False):
    """ Verify the signed data in a table.

        Arguments:
        conn - the connection to the accumulo server
        table - the name of the table on the server to decrypt
        decryptor - AcccumuloDecrypt object that will decrypt mutations
        benchmark - whether we're benchmarking decryption (default: False)
    """
    success = True 
    if benchmark:
        print "Starting decryption..."
        start = time.clock()
        
    count = 0 
    dec_error = 0
    for entry in conn.scan(table):
        count += 1
        try:
            dec_entry = decryptor.decrypt(entry)
        except DecryptionException as ve:
            dec_error += 1
            if dec_error < 11:  
                print "Decryption error:", ve.msg
                print "Entry was %s" % (str(entry))
            success = False

    if benchmark:
        print "Decryption finished!"
        end = time.clock()

    if success and count > 0:
        print "Decryption of all (%d) entries succeeded." %count
    elif count <= 0:
        print "WARNING: no entries to decrypt"
    else:
        print "FAILURE: %d entries failed to decrypt." % dec_error

    if benchmark:
        return (success, start, end)
    else:
        return success
    
def read_data(conn, table, benchmark=False):
    """ Read the data in a table.

        Arguments:
        conn - the connection to the accumulo server
        table - the name of the table on the server to decrypt
        benchmark - whether we're benchmarking decryption (default: False)
    """
    success = True 
    if benchmark:
        print "Starting reading..."
        start = time.clock()
        
    count = 0 
    dec_error = 0
    for entry in conn.scan(table):
        count += 1
        

    if benchmark:
        print "Reading finished!"
        end = time.clock()


    if benchmark:
        return (None, start, end)
  


