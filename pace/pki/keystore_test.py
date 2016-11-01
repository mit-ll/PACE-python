## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CAS
##  Description: Key storage tests
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Jun 2015  CAS   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import time
from unittest import TestCase
from nose.tools import ok_, eq_

from pace.common.pacetest import PACETestCase
from pace.common.fakeconn import FakeConnection
from pace.pki.abstractpki import PKILookupError, PKIStorageError
from pace.pki.keystore import DummyKeyStore, KeyInfo
from pace.pki.accumulo_keystore import AccumuloKeyStore, AccumuloAttrKeyStore

random.seed(int(time.time()))

ITERS = 10
NAMES = 10
METADATAS = 5
ATTRS = 3
VERS = 2

class DummyTest(object):
    """ Dummy test object to call assertEqual() and assertTrue()
    """
    def assertEqual(self, x, y, err=None):
        eq_(x, y, err)

    def assertTrue(self, x, err=None):
        ok_(x, err)

# NB: Functions out here are intended to be outside of the above object

def _check_write_read(self, ks):
    """ Make sure that when we write something, we can read it back.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """

    ks.insert('test', KeyInfo('', 1, 'metadata', 'keywrap', 0))
    wrap = ks.retrieve('test', '', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap')

def _check_write_read_attr(self, ks):
    """ Make sure that when we write something, we can read it back.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """

    ks.insert('test', KeyInfo('attr A', 1, 'metadata', 'keywrap', 0))
    wrap = ks.retrieve('test', 'attr A', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap')

def _check_writes_reads(self, ks_gen):
    """ Make sure reads & writes work with iterated, random data.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks_gen - a function of no arguments that, when called, generates
             a fresh object matching the AbstractKeyStore interface
    """

    for _ in xrange(ITERS):
        values = []
        ks = ks_gen()
        attr = ''       # no attr
        vers = 1     # static version

        # Generate some random user IDs
        names = ('user'+str(random.randint(0,1000000000))
                 for _ in xrange(NAMES))

       
        for name in names:
            # Generate some random metadata
            metadatas = ('meta'+str(random.randint(0,1000000000))
                         for _ in xrange(METADATAS))

            for metadata in metadatas:
                # Generate a random keywrap
                keywrap = 'key'+str(random.randint(0,1000000000))

                values.append(((name, metadata), keywrap))
                ks.insert(name, KeyInfo(attr, vers, metadata, keywrap, 0))

        for ((name, metadata), keywrap) in values:
            self.assertEqual(ks.retrieve(name, attr, vers, metadata), keywrap)

def _check_writes_reads_attr(self, ks_gen):
    """ Make sure reads & writes work with iterated, random data storing
        attribute keys.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks_gen - a function of no arguments that, when called, generates
             a fresh object matching the AbstractKeyStore interface
    """

    for _ in xrange(ITERS):
        values = []
        ks = ks_gen()

        # Generate some random user IDs
        names = ('user'+str(random.randint(0,1000000000))
                 for _ in xrange(NAMES))

       
        for name in names:
            # Generate some random metadata
            metadatas = ('meta'+str(random.randint(0,1000000000))
                         for _ in xrange(METADATAS))

            for metadata in metadatas:
                # Generate some random attributes
                attrs = ('attr'+str(random.randint(0,1000000000))
                         for _ in xrange(ATTRS))

                for attr in attrs:
                    # Generate some random versions
                    vers = (random.randint(0,1000000000)
                            for _ in xrange(VERS))

                    for vrs in vers:
                        # Generate a random keywrap
                        keywrap = 'key'+str(random.randint(0,1000000000))

                        values.append((name, attr, vrs, metadata, keywrap))
                        ks.insert(name,
                                  KeyInfo(attr, vrs, metadata, keywrap, 0))

        for (name, attr, vrs, metadata, keywrap) in values:
            self.assertEqual(ks.retrieve(name, attr, vrs, metadata), keywrap)

def _check_not_found(self, ks):
    """ Make sure a key store without an element in it raises an exception

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """
    
    try:
        ks.insert('user', KeyInfo('invalid', '1', 'version', 'string', 0))
        self.assertTrue(False, 'failed to raise error')
    except PKIStorageError:
        pass

    try:
        ks.retrieve('user', 0, 'not', 'found')
        self.assertTrue(False, 'failed to raise error')
    except PKILookupError:
        pass

    try:
        ks.retrieve('user', 0, 'still_not', 'found')
        self.assertTrue(False, 'failed to raise error')
    except PKILookupError:
        pass

    # Try looking for non-existent data in a real table
    ks.insert('user', KeyInfo('attr', 0, 'meta', 'keywrap', 0))

    try:
        ks.retrieve('user', 'newattr', 12, 'meta')
        self.assertTrue(False, 'failed to raise error')
    except PKILookupError:
        pass

    # Try fetching the latest version of a nonexistent key
    try:
        ks.retrieve_latest_version('nope', 'not', 'found')
        self.assertTrue(False, 'failed to raise error')
    except PKILookupError:
        pass

    try:
        ks.retrieve_latest_version_number('not', 'found')
        self.assertTrue(False, 'failed to raise error')
    except PKILookupError:
        pass



def _check_overlap_values(self, ks_gen):
    """ Make sure elements with some of the same identifying
        information (user ID, metadata, etc) are still correctly
        stored.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks_gen - a function of no arguments that, when called, generates
             a fresh object matching the AbstractKeyStore interface
    """

    for _ in xrange(ITERS):
        values = []
        ks = ks_gen()
        attr = ''
        vers = 1

        # Generate some random user IDs
        names = ['key'+str(random.randint(0,1000000000))
                 for _ in xrange(NAMES)]

        # Generate some random metadata
        metadatas = ['meta'+str(random.randint(0,1000000000))
                     for _ in xrange(METADATAS)]

        for name in names:
            for metadata in metadatas:
                # Generate a random keywrap
                keywrap = 'key'+str(random.randint(0,1000000000))

                values.append((name, metadata, keywrap))
                ks.insert(name, KeyInfo(attr, vers, metadata, keywrap, 0))

        for (name, metadata, keywrap) in values:
            self.assertEqual(ks.retrieve(name, attr, vers, metadata), keywrap)

def _check_overlap_values_attr(self, ks_gen):
    """ Make sure elements with some of the same identifying
        information (user ID, metadata, attribute, etc) are still
        correctly stored. Includes attribute keys.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks_gen - a function of no arguments that, when called, generates
             a fresh object matching the AbstractKeyStore interface
    """

    for _ in xrange(ITERS):
        values = []
        ks = ks_gen()

        # Generate some random user IDs
        names = ['user'+str(random.randint(0,1000000000))
                 for _ in xrange(NAMES)]

        # Generate some random metadata
        metadatas = ['meta'+str(random.randint(0,1000000000))
                     for _ in xrange(METADATAS)]

        # Generate some random attrs
        attrs = ['attr'+str(random.randint(0,1000000000))
                 for _ in xrange(ATTRS)]

        # Generate some random versions
        verss = [random.randint(0,1000000000)
                 for _ in xrange(VERS)]

        for name in names:
            for metadata in metadatas:
                for attr in attrs:
                    for vrs in verss:
                        keywrap = 'key_'+name+metadata+attr+str(vrs)

                        values.append((name, attr, vrs, metadata, keywrap))
                        ks.insert(name,
                                  KeyInfo(attr, vrs, metadata, keywrap, 0))

        for (name, attr, vrs, metadata, keywrap) in values:
            self.assertEqual(ks.retrieve(name, attr, vrs, metadata), keywrap)

def _check_batch_insert_single(self, ks):
    """ Check that batch adding of attribute keys works with a singleton.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """

    keys = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0)]
    ks.batch_insert('test', keys)
    wrap = ks.retrieve('test', 'attr A', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap')

def _check_batch_insert_double(self, ks):
    """ Check that batch adding of attribute keys works with two elements.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """

    keys = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
            KeyInfo('attr A', 2, 'metadata', 'keywarp', 0)]
    ks.batch_insert('test', keys)
    wrap = ks.retrieve('test', 'attr A', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap')
    wrap = ks.retrieve('test', 'attr A', 2, 'metadata')
    self.assertEqual(wrap, 'keywarp')

def _check_batch_insert_several(self, ks_gen):
    """ Check that batch adding of attribute keys works with several
        related elements with a few edge cases.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks_gen - a function of no arguments that, when called, generates
             a fresh object matching the AbstractKeyStore interface
    """

    # Case 1: two attr A keys, one attr B key
    ks = ks_gen()
    keys = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
            KeyInfo('attr A', 2, 'metadata', 'keywarp', 0),
            KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0)]
    ks.batch_insert('test', keys)
    wrap = ks.retrieve('test', 'attr A', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap')
    wrap = ks.retrieve('test', 'attr A', 2, 'metadata')
    self.assertEqual(wrap, 'keywarp')
    wrap = ks.retrieve('test', 'attr B', 23, 'meatdata')
    self.assertEqual(wrap, 'wheycap')

    # Case 2: attr B key has the same version string as an attr A key
    ks = ks_gen()
    keys = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
            KeyInfo('attr A', 2, 'metadata', 'keywarp', 0),
            KeyInfo('attr B', 1, 'metadata', 'newwrap', 0)]
    ks.batch_insert('test', keys)
    wrap = ks.retrieve('test', 'attr A', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap')
    wrap = ks.retrieve('test', 'attr A', 2, 'metadata')
    self.assertEqual(wrap, 'keywarp')
    wrap = ks.retrieve('test', 'attr B', 1, 'metadata')
    self.assertEqual(wrap, 'newwrap')

def _check_batch_insert_many(self, ks_gen):
    """ Check that batch adding attribute keys works for randomly
        generated data.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks_gen - a function of no arguments that, when called, generates
             a fresh object matching the AbstractKeyStore interface
    """

    for _ in xrange(ITERS):
        values = []
        ks = ks_gen()

        # Generate some random user IDs
        names = ('user'+str(random.randint(0,1000000000))
                 for _ in xrange(NAMES))

       
        for name in names:
            name_batch = []

            # Generate some random metadata
            metadatas = ('meta'+str(random.randint(0,1000000000))
                         for _ in xrange(METADATAS))

            for metadata in metadatas:
                # Generate some random attributes
                attrs = ('attr'+str(random.randint(0,1000000000))
                         for _ in xrange(ATTRS))

                for attr in attrs:
                    # Generate some random versions
                    vers = (random.randint(0,1000000000)
                            for _ in xrange(VERS))

                    for vrs in vers:
                        # Generate a random keywrap
                        keywrap = 'key'+str(random.randint(0,1000000000))

                        info = KeyInfo(attr, vrs, metadata, keywrap, 0)

                        values.append((name, info))
                        name_batch.append(info)

            ks.batch_insert(name, name_batch)

        for (usr, keyinfo) in values:
            self.assertEqual(
                ks.retrieve(usr, keyinfo.attr, keyinfo.vers, keyinfo.metadata),
                keyinfo.keywrap)

def _check_repeat_cell_key(self, ks):
    """ Make sure the second key is returned after two consecutive writes
        to the same ID and metadata.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """

    ks.insert('test', KeyInfo('', 1, 'metadata', 'keywrap1', 0))
    ks.insert('test', KeyInfo('', 1, 'metadata', 'keywrap2', 0))
    wrap = ks.retrieve('test', '', 1, 'metadata')
    self.assertEqual(wrap, 'keywrap2')

def _check_empty_fields(self, ks):
    """ Make sure key stores work with empty strings.

        Arguments:
        self - a simulator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """
    ks.insert('', KeyInfo('', 0, '', '', 0))
    wrap = ks.retrieve('', '', 0, '')
    self.assertEqual(wrap, '')

def _check_batch_retrieve(self, ks):
    """ Make sure batch retrieval works
        
        Arguments:
        self - a simuluator of a test object (see DummyTest above)
        ks - a fresh object matching the AbstractKeyStore interface
    """

    keys = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
            KeyInfo('attr A', 2, 'metadata', 'keywarp', 0),
            KeyInfo('attr B', 1, 'metadata', 'newwrap', 0),
            KeyInfo('attr B', 2, 'metadata', 'dewwrap', 0),
            KeyInfo('', 12, 'metadata', 'gluwrap', 0),
            KeyInfo('', 1, 'betadata', 'foowrap', 0),
            KeyInfo('', 1, 'gammadata', 'barwrap', 0)]
    ks.batch_insert('user', keys)

    # Case 1: test getting everything
    res = ks.batch_retrieve('user', 'metadata')
    mkeys = keys[:5]

    self.assertTrue(len(res) == len(mkeys))
    self.assertTrue(all(x in mkeys for x in res))
    self.assertTrue(all(x in res for x in mkeys))

    res = ks.batch_retrieve('user', 'betadata')
    bkeys =keys[5:6]

    self.assertTrue(len(res) == len(bkeys))
    self.assertTrue(all(x in bkeys for x in res))
    self.assertTrue(all(x in res for x in bkeys))

    res = ks.batch_retrieve('user', 'gammadata')
    gkeys =keys[6:]

    self.assertTrue(len(res) == len(gkeys))
    self.assertTrue(all(x in gkeys for x in res))
    self.assertTrue(all(x in res for x in gkeys))

    # Case 2: test non-attribute keys
    res = ks.batch_retrieve('user', 'metadata', '')

    self.assertTrue(len(res) == 1)
    self.assertTrue(all(x.attr == '' for x in res))
    self.assertTrue(keys[4] in res)

    # Case 3: test attr A
    res = ks.batch_retrieve('user', 'metadata', 'attr A')

    self.assertTrue(len(res) == 2)
    self.assertTrue(all(x.attr == 'attr A' for x in res))
    self.assertTrue(keys[0] in res)
    self.assertTrue(keys[1] in res)

    # Case 4: test attr B
    res = ks.batch_retrieve('user', 'metadata', 'attr B')

    self.assertTrue(len(res) == 2)
    self.assertTrue(all(x.attr == 'attr B' for x in res))
    self.assertTrue(keys[2] in res)
    self.assertTrue(keys[3] in res)

    # Case 5: test non-existent attr C
    try:
        res = ks.batch_retrieve('user', 'metadata', 'attr C')
        self.assertTrue(False, 'Should fail to retrieve non-existent attr')
    except PKILookupError:
        pass

def _check_most_recent(self, ks):
    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0),
            KeyInfo('A', 5, 'metadata', 'wrap5', 0),
            KeyInfo('A', 6, 'metadata', 'wrap6', 0),
            KeyInfo('A', 7, 'metadata', 'wrap7', 0),
            KeyInfo('A', 8, 'metadata', 'wrap8', 0),
            KeyInfo('A', 9, 'metadata', 'wrap9', 0),
            KeyInfo('A', 10, 'metadata', 'wrap10', 0)]

    random.shuffle(keys)

    ks.batch_insert('user', keys)

    res = ks.retrieve_latest_version(userid='user', metadata='metadata', attr='A')
    self.assertEqual(res.vers, 10)
    self.assertEqual(res.keywrap, 'wrap10')

def _check_most_recent_many(self, ks_gen):

    user = 'user'
    metadata='metadata'
    attr = 'A'

    for _ in xrange(ITERS):
        ks = ks_gen()

        versions = []

        for _ in xrange(50):
            vers = random.randint(0,10000000000000)
            keywrap = 'wrap'+str(vers)

            versions.append(vers)
            ks.insert(user, KeyInfo(attr, vers, metadata, keywrap, 0))

        res = ks.retrieve_latest_version(user, metadata, attr)
        self.assertEqual(res.vers, max(versions))
        self.assertEqual(res.keywrap, 'wrap'+str(max(versions)))

def _check_most_recent_num(self, ks):
    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0),
            KeyInfo('A', 5, 'metadata', 'wrap5', 0),
            KeyInfo('A', 6, 'metadata', 'wrap6', 0),
            KeyInfo('A', 7, 'metadata', 'wrap7', 0),
            KeyInfo('A', 8, 'metadata', 'wrap8', 0),
            KeyInfo('A', 9, 'metadata', 'wrap9', 0),
            KeyInfo('A', 10, 'metadata', 'wrap10', 0)]

    random.shuffle(keys)

    ks.batch_insert('user', keys)

    vers = ks.retrieve_latest_version_number(metadata='metadata', attr='A')
    self.assertEqual(vers, 10)

def _check_most_recent_num_many(self, ks_gen):

    user = 'user'
    metadata='metadata'
    attr = 'A'

    for _ in xrange(ITERS):
        ks = ks_gen()

        versions = []

        for _ in xrange(50):
            vers = random.randint(0,10000000000000)
            keywrap = 'wrap'+str(vers)

            versions.append(vers)
            ks.insert(user, KeyInfo(attr, vers, metadata, keywrap, 0))

        vers = ks.retrieve_latest_version_number(metadata, attr)
        self.assertEqual(vers, max(versions))

def _check_remkeys(self, ks):
    """ Make sure basic key removal functionality works.
    """

    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0)]

    ks.batch_insert('user', keys)
    ks.remove_revoked_keys('user', 'metadata', 'A')

    try:
        res = ks.batch_retrieve('user', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

def _check_remkeys_multi_user(self, ks):
    """ Make sure basic key removal functionality works when there are
        multiple users.
    """
    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0)]

    ks.batch_insert('user1', keys)
    ks.batch_insert('user2', keys)
    ks.remove_revoked_keys('user1', 'metadata', 'A')

    try:
        res = ks.batch_retrieve('user1', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

    res = ks.batch_retrieve('user2', 'metadata', 'A')
    self.assertEqual(set(res), set(keys))

def _check_remkeys_multi_attr(self, ks):
    """ Make sure basic key removal functionality works when there are
        multiple attributes.
    """
    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0),
            KeyInfo('B', 1, 'metadata', 'wrap5', 0),
            KeyInfo('B', 2, 'metadata', 'wrap6', 0),
            KeyInfo('B', 3, 'metadata', 'wrap7', 0)]

    ks.batch_insert('user', keys)
    ks.remove_revoked_keys('user', 'metadata', 'A')

    try:
        res = ks.batch_retrieve('user', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

    res = ks.batch_retrieve('user', 'metadata', 'B')
    self.assertEqual(set(res), set(keys[4:]))

def _check_remkeys_multi_meta(self, ks):
    """ Make sure basic key removal functionality works when there are
        multiple metadatas.
    """
    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0),
            KeyInfo('A', 1, 'betadata', 'wrap5', 0),
            KeyInfo('A', 2, 'betadata', 'wrap6', 0),
            KeyInfo('A', 3, 'betadata', 'wrap7', 0)]

    ks.batch_insert('user', keys)
    ks.remove_revoked_keys('user', 'metadata', 'A')

    try:
        res = ks.batch_retrieve('user', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

    res = ks.batch_retrieve('user', 'betadata', 'A')
    self.assertEqual(set(res), set(keys[4:]))

def _check_remkeys_all(self, ks):
    """ Make sure basic key removal functionality works when the dataset is
        heterogenous and there are multiple remove operations.
    """
    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0),
            KeyInfo('A', 1, 'betadata', 'wrap5', 0),
            KeyInfo('A', 2, 'betadata', 'wrap6', 0),
            KeyInfo('A', 3, 'betadata', 'wrap7', 0),
            KeyInfo('B', 1, 'metadata', 'wrap8', 0),
            KeyInfo('B', 2, 'metadata', 'wrap9', 0),
            KeyInfo('B', 3, 'metadata', 'wrap0', 0)]

    ks.batch_insert('user1', keys)
    ks.batch_insert('user2', keys)
    ks.batch_insert('user3', keys)
    ks.remove_revoked_keys('user1', 'metadata', 'A')

    try:
        res = ks.batch_retrieve('user1', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

    res = ks.batch_retrieve('user1', 'betadata', 'A')
    self.assertEqual(set(res), set(keys[4:7]))

    res = ks.batch_retrieve('user1', 'metadata', 'B')
    self.assertEqual(set(res), set(keys[7:]))

    res = ks.batch_retrieve('user2', 'metadata', 'A')
    self.assertEqual(set(res), set(keys[:4]))

    res = ks.batch_retrieve('user2', 'betadata', 'A')
    self.assertEqual(set(res), set(keys[4:7]))

    res = ks.batch_retrieve('user2', 'metadata', 'B')
    self.assertEqual(set(res), set(keys[7:]))

    ks.remove_revoked_keys('user2', 'metadata', 'A')

    try:
        res = ks.batch_retrieve('user1', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

    try:
        res = ks.batch_retrieve('user2', 'metadata', 'A')
        self.assertTrue(False, 'Should fail to retrieve deleted keys')
    except PKILookupError:
        pass

    res = ks.batch_retrieve('user1', 'betadata', 'A')
    self.assertEqual(set(res), set(keys[4:7]))

    res = ks.batch_retrieve('user1', 'metadata', 'B')
    self.assertEqual(set(res), set(keys[7:]))

    res = ks.batch_retrieve('user2', 'betadata', 'A')
    self.assertEqual(set(res), set(keys[4:7]))

    res = ks.batch_retrieve('user2', 'metadata', 'B')
    self.assertEqual(set(res), set(keys[7:]))

def _check_remkeys_random(self, ks_gen):
    """ Make sure basic key removal functionality works when the dataset is
        heterogenous and there are multiple remove operations.
    """

    for _ in xrange(ITERS):
        ks = ks_gen()
        values = []

        # Generate some random user IDs
        names = ('user'+str(random.randint(0,1000000000))
                 for _ in xrange(NAMES))

        for name in names:
            to_insert = []
            name_batch = []

            # Generate some random metadata
            metadatas = ('meta'+str(random.randint(0,1000000000))
                         for _ in xrange(METADATAS))

            for metadata in metadatas:
                meta_batch = []
                # Generate some random attributes
                attrs = ('attr'+str(random.randint(0,1000000000))
                         for _ in xrange(ATTRS))

                for attr in attrs:
                    attr_batch = []
                    # Generate some random versions
                    vers = (random.randint(0,1000000000)
                            for _ in xrange(VERS))

                    for vrs in vers:
                        # Generate a random keywrap
                        keywrap = 'key'+str(random.randint(0,1000000000))

                        info = KeyInfo(attr, vrs, metadata, keywrap, 0)

                        to_insert.append(info)
                        attr_batch.append(info)
                    meta_batch.append((attr, attr_batch))
                name_batch.append((metadata, meta_batch))

            values.append((name, name_batch))
            ks.batch_insert(name, to_insert)

        for name, name_batch in values:
            for metadata, meta_batch in name_batch:
                for attr, infos in meta_batch:
                    # Flip a coin to determine whether we remove this batch
                    if random.randint(0, 1) == 0:
                        ks.remove_revoked_keys(name, metadata, attr)
                        try:
                            res = ks.batch_retrieve(name, metadata, attr)
                            self.assertTrue(False,
                                'Should fail to retrieve deleted keys')
                        except PKILookupError:
                            pass
                    else:
                        res = ks.batch_retrieve(name, metadata, attr)
                        self.assertEqual(set(res), set(infos))

# test get_metadatas
def _check_get_metas(self, ks):
    """ Test basic get_metadatas functionality
    """

    # Test 1: one user, one metadata
    keys = [KeyInfo('A', 1, 'meta1', 'wrap1', 0),
            KeyInfo('A', 1, 'meta2', 'wrap2', 0),
            KeyInfo('A', 1, 'meta3', 'wrap3', 0),
            KeyInfo('A', 1, 'meta4', 'wrap4', 0)]

    ks.batch_insert('user1', keys)
    metas = ks.get_metadatas('user1', 'A')

    self.assertEqual(metas, set(['meta' + str(i) for i in xrange(1, 5)]))

    # Test 2: add another user
    ks.batch_insert('user2', keys)
    metas1 = ks.get_metadatas('user1', 'A')
    metas2 = ks.get_metadatas('user2', 'A')

    # Make sure old metadata info is unchanged
    self.assertEqual(metas1, set(['meta' + str(i) for i in xrange(1, 5)]))
    self.assertEqual(metas2, set(['meta' + str(i) for i in xrange(1, 5)]))

    # Test 3: add another attribute
    keys = [KeyInfo('B', 1, 'meta1', 'wrap1', 0),
            KeyInfo('B', 1, 'meta2', 'wrap2', 0)]

    ks.batch_insert('user1', keys)
    metas = ks.get_metadatas('user1', 'B')

    self.assertEqual(metas, set(['meta' + str(i) for i in xrange(1, 3)]))

def _check_get_metas_remove(self, ks):
    """ Test interaction of get_metadatas and remove_revoked_keys
    """
    keys = [KeyInfo('A', 1, 'meta1', 'wrap1', 0),
            KeyInfo('A', 1, 'meta1', 'wrap2', 0),
            KeyInfo('A', 1, 'meta2', 'wrap3', 0),
            KeyInfo('A', 1, 'meta2', 'wrap4', 0),
            KeyInfo('B', 1, 'meta1', 'wrap5', 0),
            KeyInfo('B', 1, 'meta1', 'wrap6', 0)]

    ks.batch_insert('user1', keys)
    ks.batch_insert('user2', keys)

    metas1a = ks.get_metadatas('user1', 'A')
    metas2a = ks.get_metadatas('user2', 'A')
    metas1b = ks.get_metadatas('user1', 'B')
    metas2b = ks.get_metadatas('user2', 'B')

    self.assertEqual(metas1a, set(['meta' + str(i) for i in xrange(1, 3)]))
    self.assertEqual(metas2a, set(['meta' + str(i) for i in xrange(1, 3)]))
    self.assertEqual(metas1b, set(['meta' + str(i) for i in xrange(1, 2)]))
    self.assertEqual(metas2b, set(['meta' + str(i) for i in xrange(1, 2)]))

    # Remove a set of revoked keys and make sure the metadata correctly
    # reflects this change
    ks.remove_revoked_keys('user1', 'meta1', 'A')

    metas1a = ks.get_metadatas('user1', 'A')
    metas2a = ks.get_metadatas('user2', 'A')
    metas1b = ks.get_metadatas('user1', 'B')
    metas2b = ks.get_metadatas('user2', 'B')

    self.assertEqual(metas1a, set(['meta' + str(i) for i in xrange(2, 3)]))
    self.assertEqual(metas2a, set(['meta' + str(i) for i in xrange(1, 3)]))
    self.assertEqual(metas1b, set(['meta' + str(i) for i in xrange(1, 2)]))
    self.assertEqual(metas2b, set(['meta' + str(i) for i in xrange(1, 2)]))

def _check_avoid_aliasing(self, ks):
    """ Make sure values returned by key stores don't magically change when
        their key store changes (mostly an issue for the dummy implementation)
    """
    # The dangerous set of operations is as follows:
    # 1) call x = get_metadatas()
    # 2) call remove_revoked_keys()
    # 3) interact with x

    keys = [KeyInfo('A', 1, 'metadata', 'wrap1', 0),
            KeyInfo('A', 2, 'metadata', 'wrap2', 0),
            KeyInfo('A', 3, 'metadata', 'wrap3', 0),
            KeyInfo('A', 4, 'metadata', 'wrap4', 0),
            KeyInfo('A', 1, 'betadata', 'wrap5', 0),
            KeyInfo('A', 2, 'betadata', 'wrap6', 0),
            KeyInfo('A', 3, 'betadata', 'wrap7', 0),
            KeyInfo('B', 1, 'metadata', 'wrap8', 0),
            KeyInfo('B', 2, 'metadata', 'wrap9', 0),
            KeyInfo('B', 3, 'metadata', 'wrap0', 0)]

    ks.batch_insert('user1', keys)
    ks.batch_insert('user2', keys)
    ks.batch_insert('user3', keys)

    metas = ks.get_metadatas('user1', 'A')
    self.assertEqual(set(metas), set(['metadata', 'betadata']))

    ks.remove_revoked_keys('user1', 'metadata', 'A')
    self.assertEqual(set(metas), set(['metadata', 'betadata']))


def _dummy_gen():
    return DummyKeyStore()

def _acc_gen():
    conn = FakeConnection()
    return AccumuloKeyStore(conn)

def _attr_gen():
    conn = FakeConnection()
    return AccumuloAttrKeyStore(conn)

def test_all():
    self = DummyTest()
    generators = [_dummy_gen, _acc_gen, _attr_gen]

    for gen in generators:
        yield _check_write_read, self, gen()
        yield _check_write_read_attr, self, gen()
        yield _check_writes_reads, self, gen
        yield _check_writes_reads_attr, self, gen
        yield _check_not_found, self, gen()
        yield _check_overlap_values, self, gen
        yield _check_overlap_values_attr, self, gen
        yield _check_batch_insert_single, self, gen()
        yield _check_batch_insert_double, self, gen()
        yield _check_batch_insert_several, self, gen
        yield _check_batch_insert_many, self, gen
        yield _check_repeat_cell_key, self, gen()
        yield _check_empty_fields, self, gen()
        yield _check_batch_retrieve, self, gen()
        yield _check_most_recent, self, gen()
        yield _check_most_recent_many, self, gen
        yield _check_most_recent_num, self, gen()
        yield _check_most_recent_num_many, self, gen
        yield _check_remkeys, self, gen()
        yield _check_remkeys_multi_user, self, gen()
        yield _check_remkeys_multi_attr, self, gen()
        yield _check_remkeys_multi_meta, self, gen()
        yield _check_remkeys_all, self, gen()
        yield _check_remkeys_random, self, gen
        yield _check_get_metas, self, gen()
        yield _check_get_metas_remove, self, gen()
        yield _check_avoid_aliasing, self, gen()
