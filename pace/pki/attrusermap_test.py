## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Unit tests for user-attribute and attribute-user maps
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  24 Aug 2015  CS    Original file
##  28 Aug 2015  CS    Changed file name
##   4 Sep 2015  ES    Added tests for user-attribute maps
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random

from pace.common.pacetest import PACETestCase
from pace.common.fakeconn import FakeConnection
from pace.pki.keystore import KeyInfo
from pace.pki.attrusermap import LocalAttrUserMap
from pace.pki.userattrmap import LocalUserAttrMap
from pace.pki.accumulo_keystore import AccumuloAttrKeyStore

class UserAttrTests(PACETestCase):

    def setUp(self):
        self.names = 10
        self.metadatas = 5
        self.attrs = 3
        self.vers = 2

    def test_local_store(self):
        """ Test local store on a static set of values
        """
        maps = {'a' : ['1', '2', '3'],
                'b' : ['4', '5', '6'],
                'c' : ['7', '8', '9']}

        #test attribute-to-user map
        store = LocalAttrUserMap(maps)
        for key, val in maps.iteritems():
            self.assertEqual(set(store.users_by_attribute(key)), set(val))

        #test user-to-attribute map
        store = LocalUserAttrMap(maps)
        for key, val in maps.iteritems():
            self.assertEqual(set(store.attributes_by_user(key)), set(val))

    def test_local_store_many(self):
        """ Random dictionary generation for the local store
        """
        maps = {}

        for _ in xrange(self.num_iters):

            for i in xrange(self.names):
                name = str(i)
                vals = self.generate_elems()
                maps[name] = list(vals)
            
            #test attribute-to-user map
            store = LocalAttrUserMap(maps)
            for key, val in maps.iteritems():
                self.assertEqual(set(store.users_by_attribute(key)), set(val))

            #test user-to-attribute map
            store = LocalUserAttrMap(maps)
            for key, val in maps.iteritems():
                self.assertEqual(set(store.attributes_by_user(key)), set(val))
    
    def test_acc_store(self):
        """ Test that the AccumuloAttrKeyStore correctly returns attributes and
            users on a small, hard-coded test case.
        """

        conn = FakeConnection()
        store = AccumuloAttrKeyStore(conn)

        keys1 = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
                 KeyInfo('attr A', 2, 'metadata', 'keywarp', 0),
                 KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0)]
        store.batch_insert('user1', keys1)

        keys2 = [KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0),
                 KeyInfo('attr C', 12, 'metadata', 'otherwrap', 0),
                 KeyInfo('attr D', 10, 'meatdata', 'newwrap', 0)]
        store.batch_insert('user2', keys2)

        self.assertEqual(store.users_by_attribute('attr A'), ['user1'])
        self.assertEqual(set(store.users_by_attribute('attr B')),
                         set(['user1', 'user2']))
        self.assertEqual(store.users_by_attribute('attr C'), ['user2'])
        self.assertEqual(store.users_by_attribute('attr D'), ['user2'])

        self.assertEqual(set(store.attributes_by_user('user1')),
                         set(['attr A', 'attr B']))
        self.assertEqual(set(store.attributes_by_user('user2')),
                         set(['attr B', 'attr C', 'attr D']))

    def test_acc_store_many(self):
        """ Test that the AccumuloAttrKeyStore correctly returns attributes and
            users on randomly-generated data.
        """

        for _ in xrange(self.num_iters):
            conn = FakeConnection()
            store = AccumuloAttrKeyStore(conn)
            users_by_attr = {}
            attrs_by_user = {}

            # Generate some random user IDs
            names = ('user'+str(random.randint(0,1000000000))
                     for _ in xrange(self.names))
           
            for name in names:
                if name not in attrs_by_user:
                    attrs_by_user[name] = set([])

                name_batch = []

                # Generate some random metadata
                metadatas = ('meta'+str(random.randint(0,1000000000))
                             for _ in xrange(self.metadatas))

                for metadata in metadatas:
                    # Generate some random attributes
                    attrs = ('attr'+str(random.randint(0,1000000000))
                             for _ in xrange(self.attrs))

                    for attr in attrs:
                        if attr not in users_by_attr:
                            users_by_attr[attr] = set([])
                        users_by_attr[attr].add(name)
                        attrs_by_user[name].add(attr)
                        # Generate some random versions
                        vers = (random.randint(0,1000000000)
                                for _ in xrange(self.vers))

                        for vrs in vers:
                            # Generate a random keywrap
                            keywrap = 'key'+str(random.randint(0,1000000000))

                            info = KeyInfo(attr, vrs, metadata, keywrap, 0)
                            name_batch.append(info)

                store.batch_insert(name, name_batch)

            for attr, users in users_by_attr.iteritems():
                self.assertEqual(users, set(store.users_by_attribute(attr)))

            for user, attrs in attrs_by_user.iteritems():
                self.assertEqual(attrs, set(store.attributes_by_user(user)))

    def test_empty_store(self):
        """ Make sure each attribute/user store correctly returns the empty list
            when appropriate.
        """
        conn = FakeConnection()
        acc_store = AccumuloAttrKeyStore(conn)
        loc_attr_user_map = LocalAttrUserMap({})
        loc_user_attr_map = LocalUserAttrMap({})

        self.assertEqual(loc_attr_user_map.users_by_attribute('not found'), [])
        self.assertEqual(loc_user_attr_map.attributes_by_user('not found'), [])
        self.assertEqual(acc_store.users_by_attribute('not found'), [])
        self.assertEqual(acc_store.attributes_by_user('not found'), [])

        self.assertEqual(loc_attr_user_map.users_by_attribute(''), [])
        self.assertEqual(loc_user_attr_map.attributes_by_user(''), [])
        self.assertEqual(acc_store.users_by_attribute(''), [])
        self.assertEqual(acc_store.attributes_by_user(''), [])

        loc_attr_user_map2 = LocalAttrUserMap({'a' : []})
        self.assertEqual(loc_attr_user_map2.users_by_attribute('a'), [])

        loc_user_attr_map2 = LocalUserAttrMap({'a' : []})
        self.assertEqual(loc_user_attr_map2.attributes_by_user('a'), [])

    def test_delete_from_store(self):
        """ Make sure attribute/user maps correctly delete elements.
        """

        maps = {'a' : ['1', '2', '3'],
                'b' : ['4', '5', '6'],
                'c' : ['7', '8', '9']}

        loc_attr_user_map = LocalAttrUserMap(maps)
        loc_user_attr_map = LocalUserAttrMap(maps)

        loc_attr_user_map.delete_user('a', '1')
        loc_attr_user_map.delete_user('b', '5')
        loc_attr_user_map.delete_user('c', '9')

        loc_user_attr_map.delete_attr('a', '1')
        loc_user_attr_map.delete_attr('b', '5')
        loc_user_attr_map.delete_attr('c', '9')

        delmaps = {'a' : ['2', '3'],
                   'b' : ['4', '6'],
                   'c' : ['7', '8']}

        for key, val in delmaps.iteritems():
            self.assertEqual(loc_attr_user_map.users_by_attribute(key), val)
            self.assertEqual(loc_user_attr_map.attributes_by_user(key), val)

    def test_del_acc_store(self):
        """ Make sure AccumuloAttrKeyStores correctly delete users and 
            attributes.
        """

        conn = FakeConnection()
        store = AccumuloAttrKeyStore(conn)

        keys1 = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
                 KeyInfo('attr A', 2, 'metadata', 'keywarp', 0),
                 KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0)]
        store.batch_insert('user1', keys1)

        keys2 = [KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0),
                 KeyInfo('attr C', 12, 'metadata', 'otherwrap', 0),
                 KeyInfo('attr D', 10, 'meatdata', 'newwrap', 0)]
        store.batch_insert('user2', keys2)

        store.delete_user('attr B', 'user1')
        store.delete_attr('user1', 'attr B')

        self.assertEqual(store.users_by_attribute('attr A'), ['user1'])
        self.assertEqual(store.users_by_attribute('attr B'), ['user2'])
        self.assertEqual(store.users_by_attribute('attr C'), ['user2'])
        self.assertEqual(store.users_by_attribute('attr D'), ['user2'])

        self.assertEqual(store.attributes_by_user('user1'), ['attr A'])
        self.assertEqual(set(store.attributes_by_user('user2')),
                         set(['attr B', 'attr C', 'attr D']))

    def test_aliasing_acc(self):
        """ Make sure aliasing isn't a problem (mostly relevant for local maps, 
            but testing it on AccumuloAttrKeyStore for completeness)
        """
        # Problem is as follows:
        # 1) call x = users_by_attribute()
        # 2) call delete_user()
        # 3) use x

        conn = FakeConnection()
        store = AccumuloAttrKeyStore(conn)

        keys1 = [KeyInfo('attr A', 1, 'metadata', 'keywrap', 0),
                 KeyInfo('attr A', 2, 'metadata', 'keywarp', 0),
                 KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0)]
        store.batch_insert('user1', keys1)

        keys2 = [KeyInfo('attr B', 23, 'meatdata', 'wheycap', 0),
                 KeyInfo('attr C', 12, 'metadata', 'otherwrap', 0),
                 KeyInfo('attr D', 10, 'meatdata', 'newwrap', 0)]
        store.batch_insert('user2', keys2)

        users = store.users_by_attribute('attr B')
        self.assertEqual(set(['user1', 'user2']), set(users))

        store.delete_user('attr B', 'user1')
        store.delete_attr('user1', 'attr B')
        self.assertEqual(set(['user1', 'user2']), set(users))

    def test_aliasing_loc(self):
        """ Make sure aliasing isn't a problem (mostly relevant for local maps)
        """
        # Problem is as follows:
        # 1) call x = users_by_attribute()
        # 2) call delete_user()
        # 3) use x

        maps = {'A' : ['1', '2', '3'],
                'B' : ['4', '5', '6'],
                'C' : ['7', '8', '9']}

        #test attribute-to-user map
        store = LocalAttrUserMap(maps)

        users = store.users_by_attribute('B')
        self.assertEqual(set(['4', '5', '6']), set(users))

        store.delete_user('B', '5')
        self.assertEqual(set(['4', '5', '6']), set(users))

        #test user-to-attribute map
        print maps
        store = LocalUserAttrMap(maps)

        attrs = store.attributes_by_user('B')
        self.assertEqual(set(['4', '5', '6']), set(attrs))
        store.delete_attr('B', '5')
        self.assertEqual(set(['4', '5', '6']), set(attrs))

        
