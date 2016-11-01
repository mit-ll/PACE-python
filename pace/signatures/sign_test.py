## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for accumulo client signature code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Jun 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from base64 import b64encode, b64decode
from pyaccumulo import Mutation

from nose.tools import ok_, eq_
import time, datetime
import random
import logging
import StringIO

from pace.signatures.sign import AccumuloSigner, SigningException
from pace.signatures.vars import SUPPORTED_SIGNATURES, ALL_SIGNATURES
from pace.signatures.signconfig import new_config
from pace.signatures.acc_sig import PyCryptopp_ECDSA_AccSig
from pace.common.fakeconn import FakeConnection
from pace.common.pacetest import DEFAULT_NUM_ITERS, DEFAULT_SIZE
from pace.signatures.verify import AccumuloVerifier, VerificationException
from pace.signatures.signaturepki import DummySignaturePKI, SignatureMixin

PATH = os.path.dirname(__file__)

NUM_ITERS = DEFAULT_NUM_ITERS
SIZE = DEFAULT_SIZE
LOCATIONS = ['vis', 'val', 'tab']
SIGNATURES = ALL_SIGNATURES
CONFIG_FILES = [PATH+'/cfg/batch_test.cfg',
                PATH+'/cfg/stream_test.cfg',
                PATH+'/cfg/value_test.cfg']

seed = int(time.time())
random.seed(int(time.time()))

def _generate_truncation_data():
    msg = str(random.randint(1, 1000000000))
    num_equals_signs = random.randint(0, 2)

    if num_equals_signs == 1:
        msg = msg + "="
    elif num_equals_signs == 2:
        msg = msg + "=="

    return msg, num_equals_signs

def _log_sign_test_info(sigClass, signer, pubkey, data):
    logging.debug("Attempting to sign with " +
                    sigClass.name + " key")
    logging.debug('Public key: %s', pubkey)
    logging.debug('Private key: %s', signer.privkey)
    logging.debug('Data: %s', data)

def _check_verify_succeeds(sigClass):
    # Make sure we verify everything that's signed, and nothing unsigned
    # (at least, not due to any bugs in our code...)
    for i in range(0, NUM_ITERS):
        data = str(random.randint(1, 1000000000))

        pubkey, privkey = sigClass.test_keys()
        signer = AccumuloSigner(privkey, sigClass)

        _log_sign_test_info(
            sigClass, signer, pubkey, data)

        signature = signer.sign_data(data)
        ok_(
            AccumuloVerifier._verify_signature_bool(signature,
                                                   data,
                                                   pubkey,
                                                   sigClass,
                                                   None),
            "Failed to verify data against its signature")

def _check_bad_data(sigClass):
    # Make sure signatures only verify against their data
    for i in range(0, NUM_ITERS):
        data = str(random.randint(1, 1000000000))

        pubkey, privkey = sigClass.test_keys()
        signer = AccumuloSigner(privkey, sigClass)

        _log_sign_test_info(
            sigClass, signer, pubkey, data)

        signature = signer.sign_data(data)

        result = AccumuloVerifier._verify_signature_bool(
                    signature, data + data, pubkey,
                    sigClass, None)

        eq_(result, False,
            "Claims data verifies against the wrong signature.")

def _random_mutation(default_vis='default', append_vis=None):
    
    row = str(random.randint(0, 10))
    col = str(random.randint(0, 100000000))
    val = str(random.randint(0, 100000000))
    cq  = str(random.randint(0, 100000000))
    if append_vis is None:
        cv  = '|'.join([default_vis, str(random.randint(0, 100000000))])
    else:
        cv = '|'.join([default_vis, append_vis])

    m = Mutation(row)
    m.put(cf=col, cv=cv, cq=cq, val=val)

    return m

def _check_sign_and_read(sigClass, cfg_file):
    # Make sure writing & reading a signature verifies correctly with no
    # extra features, using a FakeConn in place of a live Accumulo instance.
    table_prefix = 'table'
    num_tables = 5

    pubkey, privkey = sigClass.test_keys()

    for i in range(0, NUM_ITERS):
        conn = FakeConnection()
        conf = new_config(cfg_file, conn)

        signer = AccumuloSigner(privkey, sig_f=sigClass, conf=conf)
        verifier = AccumuloVerifier(pubkey, conf=conf)

        inputs = [(table_prefix + str(random.randint(0, num_tables)),
                   _random_mutation())
                   for _ in range(SIZE)]

        conf.start_batch()

        for table, mutation in inputs:
            if not conn.table_exists(table):
                conn.create_table(table)

            signer.sign_mutation(mutation)
            conn.write(table, mutation)

        conf.end_batch()

        tables = set(table for table, _ in inputs)

        for table in tables:
            if table != '__metadata_table__':
                for entry in conn.scan(table):
                    try:
                        verifier.verify_entry(entry)
                    except VerificationException:
                        ok_(False, 'entry failed to verify')

        # reset the file so it can be reused in the next iteration
        cfg_file.seek(0)

def _check_sign_table(sigClass, cfg_file):
    # Make sure including the table's name in the signature works correctly
    table_prefix = 'table'
    num_tables = 5

    pubkey, privkey = sigClass.test_keys()

    for i in range(0, NUM_ITERS):
        conn = FakeConnection()
        conf = new_config(cfg_file, conn)

        signer = AccumuloSigner(privkey, sig_f=sigClass, conf=conf)
        verifier = AccumuloVerifier(pubkey, conf=conf)

        inputs = [(table_prefix + str(random.randint(0, num_tables)),
                   _random_mutation())
                   for _ in range(SIZE)]

        conf.start_batch()
        for table, mutation in inputs:
            if not conn.table_exists(table):
                conn.create_table(table)

            signer.sign_mutation(mutation, table=table)
            conn.write(table, mutation)
        conf.end_batch()

        tables = set(table for table, _ in inputs)

        for table in tables:
            if table != '__metadata_table__':
                for entry in conn.scan(table):
                    try:
                        verifier.verify_entry(entry, table=table)
                    except VerificationException as ve:
                        print ve.msg
                        errmsg = 'entry failed to verify'
                        if ve.cell is not None:
                            errmsg += ':\nrow: %s\nval: %s' %(ve.cell.row,
                                                              ve.cell.val)
                        ok_(False, errmsg)

        # reset the file so it can be reused in the next iteration
        cfg_file.seek(0)

def test_signer_id():
    # Make sure writing with the signer ID works
    table_prefix = 'table'
    num_tables = 5

    verifier = AccumuloVerifier(DummySignaturePKI())

    for i in range(0, NUM_ITERS):
        all_inputs = []
        tables = []
        conn = FakeConnection()
        for sc in SIGNATURES:
            pubkey, privkey = sc.test_keys()
            signer = AccumuloSigner(privkey, sig_f=sc, signerID=sc.name+'ID')
            inputs = [(table_prefix + str(random.randint(0, num_tables)),
                       _random_mutation())
                       for _ in range(SIZE)]
            all_inputs += inputs

            for table, mutation in inputs:
                if not conn.table_exists(table):
                    tables.append(table)
                    conn.create_table(table)

                signer.sign_mutation(mutation)
                conn.write(table, mutation)

        for table in tables:
            for entry in conn.scan(table):
                try:
                    verifier.verify_entry(entry)
                except VerificationException:
                    ok_(False, 'entry failed to verify')

def test_signer_id_and_table():
    # Make sure writing with the signer ID and signing the table work together
    table_prefix = 'table'
    num_tables = 5

    signers = dict((sc.name+'ID', (sc.test_keys()[0], sc)) for sc in SIGNATURES)
    verifier = AccumuloVerifier(DummySignaturePKI())

    for i in range(0, NUM_ITERS):
        all_inputs = []
        tables = []
        conn = FakeConnection()
        for sc in SIGNATURES:
            pubkey, privkey = sc.test_keys()
            signer = AccumuloSigner(privkey, sig_f=sc, signerID=sc.name+'ID')
            inputs = [(table_prefix + str(random.randint(0, num_tables)),
                       _random_mutation())
                       for _ in range(SIZE)]
            all_inputs += inputs

            for table, mutation in inputs:
                if not conn.table_exists(table):
                    tables.append(table)
                    conn.create_table(table)

                signer.sign_mutation(mutation, table=table)
                conn.write(table, mutation)

        for table in tables:
            for entry in conn.scan(table):
                try:
                    verifier.verify_entry(entry, table=table)
                except VerificationException as ve:
                    ok_(False, 'entry failed to verify: %s' %ve.msg)

def test_no_metadata():
    # Makes sure the verification code fails when there's no metadata
    table_prefix = 'table'
    num_tables = 5
    pubkey, _ = SIGNATURES[0].test_keys()
    verifier = AccumuloVerifier(pubkey)

    for i in range(0, NUM_ITERS):
        conn = FakeConnection()
        tables = []
        inputs = [(table_prefix + str(random.randint(0, num_tables)),
                   _random_mutation())
                   for _ in range(SIZE)]

        for table, mutation in inputs:
            if not conn.table_exists(table):
                tables.append(table)
                conn.create_table(table)

            conn.write(table, mutation)

        for table in tables:
            for entry in conn.scan(table):
                try:
                    verifier.verify_entry(entry)
                    ok_(False, 'unsigned entry somehow verified')
                except VerificationException:
                    ok_(True, 'success')
            
        
def test_fake_metadata():
    # Makes sure the verification code fails when there's something formatted
    # the same as metadata
    table_prefix = 'table'
    num_tables = 5
    pubkey, _ = SIGNATURES[0].test_keys()
    verifier = AccumuloVerifier(pubkey)

    for i in range(0, NUM_ITERS):
        conn = FakeConnection()
        tables = []
        inputs = [(table_prefix + str(random.randint(0, num_tables)),
                   _random_mutation(
                       append_vis=('",%s,%s,"'
                                   %(str(random.randint(0,10000000)),
                                     str(random.randint(0,10000000))))))
                   for _ in range(SIZE)]

        for table, mutation in inputs:
            if not conn.table_exists(table):
                tables.append(table)
                conn.create_table(table)

            conn.write(table, mutation)

        for table in tables:
            for entry in conn.scan(table):
                try:
                    verifier.verify_entry(entry)
                    ok_(False, 'unsigned entry somehow verified')
                except VerificationException as ve:
                    print ve.msg
                    ok_(True, 'success')

def test_misleading_signature():
    # Makes sure the verification code fails when there's no metadata, but
    # commas elsewhere in the visibility label
    table_prefix = 'table'
    num_tables = 5
    pubkey, _ = SIGNATURES[0].test_keys()
    verifier = AccumuloVerifier(pubkey)

    for i in range(0, NUM_ITERS):
        conn = FakeConnection()
        tables = []
        inputs = [(table_prefix + str(random.randint(0, num_tables)),
                   _random_mutation(
                       default_vis=('",%s,%s,"'
                                   %(str(random.randint(0,10000000)),
                                     str(random.randint(0,10000000))))))
                   for _ in range(SIZE)]

        for table, mutation in inputs:
            if not conn.table_exists(table):
                tables.append(table)
                conn.create_table(table)

            conn.write(table, mutation)

        for table in tables:
            for entry in conn.scan(table):
                try:
                    verifier.verify_entry(entry)
                    ok_(False, 'unsigned entry somehow verified')
                except VerificationException as ve:
                    print ve.msg
                    ok_(True, 'success')


def _check_parse_key(sigClass):
    pub, _ = sigClass.test_keys()

    ser = sigClass.serialize_key(pub)
    key = sigClass.parse_key(ser)

    ok_(sigClass.serialize_key(key) == sigClass.serialize_key(pub),
        'serialization and deserialization did not return the same key')


def test_all_signature_functions():

    for sigClass in SIGNATURES:
        yield _check_bad_data, sigClass
        yield _check_verify_succeeds, sigClass

        yield _check_sign_and_read, sigClass, StringIO.StringIO('[Location]')
        yield _check_sign_table, sigClass, StringIO.StringIO('[Location]')

    sigClass = PyCryptopp_ECDSA_AccSig

    for fname in CONFIG_FILES:
        with open(fname, 'r') as cfg_file:
            yield _check_sign_and_read, sigClass, cfg_file

        with open(fname, 'r') as cfg_file:
            yield _check_sign_table, sigClass, cfg_file

def test_parse_key():
    for sigClass in SUPPORTED_SIGNATURES:
        yield _check_parse_key, sigClass
