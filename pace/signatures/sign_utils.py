## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS, SS
##  Description: Utility functions for testing the signature code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Jun 2014  ZS    Original file
##  15 Dec 2015  SS    Added data generation functionality
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
            reach this length

        returns: the number of elements actually generated
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
    """ Given a file with data in it (as written by generate_data),
        parse the file, sign it, and write it out to the given Accumulo
        connection.

        Arguments:

        file_in - a string denoting the path of a file
        conn - the Accumulo connection to use
        table - the table to write to
        signer - the Signer (as in sign.py) to sign the data with
        benchmark - whether or not to record the time it takes to
                    sign all the provided cells (defult: False)
        include_table - whether or not to include the name of the table
                        in the signature (default: False)

        Returns:

        If benchmark=True, returns a pair (start, end) containing the times
        recorded by time.clock() at the start and end of benchmarking,
        respectively.

        Otherwise, returns nothing.
    """


    # Create table and create batch writer
    if not conn.table_exists(table):
        conn.create_table(table)
    writer = conn.create_batch_writer(table)

    # Iterate over file, sign each entry individually, and add to the writer
    with open(file_in) as f:
        lines = f.readlines()

        with common_utils.Timer() as t:

            for line in lines:

                # parse entry and put it in a mutation
                (row, col_fam, col_qual, col_vis, val) = tuple(line.rstrip('\n').split('\t'))
                mutation = Mutation(row)
                mutation.put(cf=col_fam, cq=col_qual, cv=col_vis, val=val)

                # sign and write mutation
                signer.sign_mutation(mutation, table=table if include_table else None)
                writer.add_mutation(mutation)

    writer.close()
    if benchmark:
        return (t.start, t.end)


def write_data(file_in, conn, table):
    """ Given a file with data in it (as written by generate_data),
        parse the file and write it out to the given Accumulo connection.

        Arguments:

        file_in - a string denoting the path of a file
        conn - the Accumulo connection to use
        table - the table to write to

    """

    # Create table and batch writer
    if not conn.table_exists(table):
        conn.create_table(table)
    writer = conn.create_batch_writer(table)

    # Iterate over file, add each mutation to the writer
    with open(file_in) as f:
        for line in f:
            (row, col_fam, col_qual, col_vis, val) = tuple(line.rstrip('\n').split('\t'))
            mutation = Mutation(row)
            mutation.put(cf=col_fam, cq=col_qual, cv=col_vis, val=val)
            writer.add_mutation(mutation)

    writer.close()


def verify_data(conn, table, pubkey, benchmark=False,
                                     include_table=False,
                                     conf=VisibilityFieldConfig()):
    """ Verify the signed data in a table.

        Arguments:
        conn - the connection to the accumulo server
        table - the name of the table on the server to verify
        pubkey - the public key to verify the signature against
        benchmark - whether we're benchmarking the verification (default: False)
        include_table - whether to include the table name in the signature
                        (default: False)
        conf - an instance of an implementation of the AbstractSignConfig
               class, as defined in signconfig.py
               (Default: VisibilityFieldConfig())

        Returns:
        
        If benchmark=True, returns a triple (success, start, end), as follows:
            - success: True if all entries successfully verified,
                       False otherwise
            - start, end: the times recorded by time.clock() at the start
                          and end of benchmarking, respectively.

        Otherwise, returns True if all entries successfully verified, and
        False otherwise.
    """
    success = True
    with common_utils.Timer() as t:

        verifier = AccumuloVerifier(pubkey, conf=conf)

        for entry in conn.scan(table):
            try:
                verifier.verify_entry(entry, table=table if include_table else None)
            except VerificationException:
                success = False

    return (success, t.start, t.end) if benchmark else success
