## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Framework for demoing the signature code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  06 Oct 2014  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import pyaccumulo

from pace.signatures.signconfig import VisibilityFieldConfig, ValueConfig, StreamingTableConfig
from pace.signatures.sign import AccumuloSigner
from pace.signatures.verify import AccumuloVerifier, VerificationException
from pace.signatures.acc_sig import PyCryptopp_ECDSA_AccSig

# Default elements to use
elems = [
    ('Mission A', '0200'),
    ('Mission B', '2200'),
    ('Mission C', '1000'),
    ('Mission D', '0300'),
    ('Mission E', '1100'),
]

def mutation_from_kv_tuple(tup, vis=''):
    """ Define a pyaccumulo mutation from a (key, value) formatted tuple.
    """
    row, val = tup
    print 'Inserting signed row: %s, value: %s' %(row, val)
    m = pyaccumulo.Mutation(row)
    m.put(cf='', cq='', cv=vis, val=val)
    return m

def write_file_to_table(conn, signer, table, filename, loc='vis'):
    """ Write the contents of a file to an Accumulo table.

        Arguments:
        conn - a pyaccumulo connection to an Accumulo instance
        signer - an AccumuloSigner instance
        table - the name of the table to write to
        filename - the name of the file to read the elements of
                   each line should be formatted '<key>,<value>'
    """

    if not conn.table_exists(table):
        conn.create_table(table)

    wr = conn.create_batch_writer(table)

    with open(filename, 'r') as f:
        for l in f.readlines():
            m = mutation_from_kv_tuple(l.split(','))
            signer.sign_mutation(m)
            wr.add_mutation(m)

    wr.close()

def write_list_to_table(conn, signer, table, data, vis):
    """ Write a list to an Accumulo table.

        Arguments:
        conn - a pyaccumulo connection to an Accumulo instance
        signer - an AccumuloSigner instance
        table - the name of the table to write to
        data - the list to write to the table, formatted as a list of
               (key, value) tuples
    """

    if not conn.table_exists(table):
        conn.create_table(table)

    wr = conn.create_batch_writer(table)

    for tup in data:
        m = mutation_from_kv_tuple(tup, vis)
        if signer:
            signer.sign_mutation(m)
        wr.add_mutation(m)

    wr.close()

def run_insert(conn=None,
               data=elems,
               table='demo',
               signClass=PyCryptopp_ECDSA_AccSig,
               privkey=None,
               loc='val',
               default_vis='UNCLASS',
               sign=True):
    """ Insert a list into the accumulo table specified.

        Arguments:
        conn - the Accumulo connection to use. If it is 'None', will create
               a connection with default information.
        data - the list to insert into the Accumulo table
        table - the name of the table to insert to
        signClass - the signing algorithm to use, from acc_sig.py
        privkey - the private key to use. default: None, which tells it to use
                  the test key defined by 'signClass'
        default_vis - the default visibility label to use. Default: 'UNCLASS'
        sign - whether to sign the data before writing it to Accumulo.
               Default: True
    """

    if conn is None:
        conn = pyaccumulo.Accumulo(host='localhost',
                                   port=42424,
                                   user='root',
                                   password='secret')

    if loc == 'vis':
        conf = VisibilityFieldConfig()
    elif loc == 'val':
        conf = ValueConfig()
    elif loc == 'tab':
        conf = StreamingTableConfig(conn, '__sig_metadata__' + table)
    else:
        print 'ERROR: invalid signature location', loc

    if not privkey:
        _, privkey = signClass.test_keys()

    if sign:
        signer = AccumuloSigner(privkey, sig_f=signClass, conf=conf,
                                default_visibility=default_vis)
    else:
        signer = None

    write_list_to_table(conn, signer, table, data, default_vis)

def run_verify(conn=None,
               table='demo',
               signClass=PyCryptopp_ECDSA_AccSig,
               pubkey=None,
               loc='val'):
    """ Verifies that a table in an Accumulo instance has been properly signed,
        outputting the appropriate error messages if not.

        Arguments:
        conn - the Accumulo connection to use. If conn is 'None', will create
               a connection with default info.
        data - the list to insert into the Accumulo table
        table - the name of the table to insert to
        signClass - the signing algorithm to use, from acc_sig.py
        pubkey - the public key of the signer. default: None, which tells it to 
                 use the test key defined by 'signClass'
    """

    if conn is None:
        conn = pyaccumulo.Accumulo(host='localhost',
                                   port=42424,
                                   user='root',
                                   password='secret')

    if loc == 'vis':
        conf = VisibilityFieldConfig()
    elif loc == 'val':
        conf = ValueConfig()
    elif loc == 'tab':
        conf = StreamingTableConfig(conn, '__sig_metadata__' + table)
    else:
        print 'ERROR: invalid signature location', loc

    if not pubkey:
        pubkey, _ = signClass.test_keys()

    successes = 0
    total = 0

    verifier = AccumuloVerifier(pubkey, conf=conf)

    for entry in conn.scan(table):
        total = total + 1
        try:
            verifier.verify_entry(entry)
            successes = successes + 1
        except VerificationException as ve:
            if ve.cell is not None:
                print 'Error: Entry failed to verify.'
                print 'Entry row:', ve.cell.row
                print 'Entry val:', ve.cell.val
                print 'Error message:', ve.msg
                print
            else:
                print 'Error: Entry failed to verify.'
                print 'Entry row:', entry.row
                print 'Entry val:', entry.val
                print 'Error message:', ve.msg
                print

    print 'Finished, with %d successes out of %d total entries.' %(successes, total)
