## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Utility functions for testing the signature code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Jun 2014  ZS    Original file
## **************
""" Utility functions and tests for mass verification of rows written to
    Accumulo. For unit tests, see sign_tests.py
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
from Crypto.PublicKey import RSA

from pace.signatures.sign import AccumuloSigner
from pace.signatures.verify import AccumuloVerifier, VerificationException
from pace.signatures.signconfig import VisibilityFieldConfig
from pace.common import common_utils

def sanitize(string):
    return common_utils.sanitize(string)

def generate_data(filename, 
                  seed, 
                  vis=False, 
                  default_vis="default",
                  vis_in_value=False, 
                  num_entries=50000, 
                  num_rows=1000, 
                  vis_length=9, 
                  row_length=9):
    """ Generate a tab-delimited text file with five columns:
        row, col fam, col qual, col vis, value

        keyword arguments:
        filename - name of file to which the data will be written
        seed - a string to be used as the seed for the random number generator
        visibility - if True, random column visibilities are added. If False,
            the default visibility string is added. (default False)
        default_vis - the default visibility string to use if 'visibiilty' is 
            set to False. (default "default")
        vis_in_value - if True, a random "column visibility" is generated, but
            this is appended to the value rather than column visibility. If
            True, the param vis is treated as False.
        num_entries - Number of entries written. In practice, this is a maximum,
            as the true number will be floor(num_entries/num_rows) * num_rows
        num_rows - Number of rows in the data written.
        vis_length - The length (in chars) of the random col visibility added
            (true length will be this + 2)
        row_length - Number of chars in each row ID. Numbers are zero padded to 
            reach this length.

        returns:
        the number of elements actually generated
    """
    common_utils.generate_data(filename, seed, 
                               vis = vis,
                               default_vis = default_vis, 
                               vis_in_value = vis_in_value,
                               num_entries = num_entries,
                               num_rows = num_rows,
                               vis_length = vis_length,
                               row_length = row_length)


def write_and_sign_data(file_in, conn, table, signer, benchmark=False,
                        include_table=False):

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

    signer.conf.start_batch()

    if benchmark:
        print "Starting signing..."
        start = time.clock()

    for l in lines:
        pieces = l.split('\t')
        if (row != pieces[0]):
            if m:
                if include_table:
                    signer.sign_mutation(m, table) 
                else:
                    signer.sign_mutation(m) 
                wr.add_mutation(m)
            row = pieces[0]
            m = Mutation(row)
        vis = pieces[3]
        if vis == '':
            vis = None  
        m.put(cf=pieces[1], cq=pieces[2], cv=vis, val=pieces[4][:-1])

    if benchmark:
        print "Signing finished!"
        end = time.clock()

    if include_table:
        signer.sign_mutation(m, table) 
    else:
        signer.sign_mutation(m) 

    signer.conf.end_batch()
    wr.add_mutation(m)
    wr.close()

    print "Write completed."

    if benchmark:
        return (start, end)

def write_data(file_in, conn, table):
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

    for l in lines:
        pieces = l.split('\t')
        row = pieces[0]
        m = Mutation(row)
        vis = pieces[3]
        if vis == '':
            vis = None  
        m.put(cf=pieces[1], cq=pieces[2], cv=vis, val=pieces[4][:-1])
        wr.add_mutation(m)

    wr.close()

def verify_data(conn, table, pubkey, benchmark=False, include_table=False, conf=VisibilityFieldConfig()):
    """ Verify the signed data in a table.

        Arguments:
        conn - the connection to the accumulo server
        table - the name of the table on the server to verify
        pubkey - the public key to verify the signature against
        benchmark - whether we're benchmarking the verification (default: False)
        expecting_id - whether a signer's ID is expected in the cells
                       (default: False)
        include_table - whether to include the table name in the signature
                        (default: False)

        Returns: True if all entries successfully verified, False otherwise
    """
    success = True
    count = 0
    verifier = AccumuloVerifier(pubkey, conf=conf)

    if benchmark:
        print "Starting verification..."
        start = time.clock()

    for entry in conn.scan(table):
        count += 1
        try:
            if include_table:
                verifier.verify_entry(entry, table)
            else:
                verifier.verify_entry(entry)
        except VerificationException as ve:
            print "Verification error:", ve.msg
            success = False

    if benchmark:
        print "Verification finished!"
        end = time.clock()

    if success and count > 0:
        print "Verification of all (%d) entries succeeded." %count
    elif count <= 0:
        print "WARNING: no entries to verify"
    else:
        print "FAILURE: some entries failed to verify."

    if benchmark:
        return (success, start, end)
    else:
        return success



