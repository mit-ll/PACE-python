## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for verification objects
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  21 Jul 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase
from hashlib import sha256

import time
import random
import bisect

from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.skiplistvo import SkipListVO
from pace.ads.skiplist.vonode import VONode, VerificationObjectException
from pace.ads.skiplist.coin import RecordedCoin, PrefixCoin, SeededCoin
from pace.ads.skiplist.elemclass import IntElem
from pace.common.pacetest import PACETestCase

class SkipListVOTest(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

        # Setup for small, hand-made tests
        self.elems = map(IntElem, [0, 5, 6, 10])
        self.sl = AuthSkipList.new(self.elems,
                                   IntElem(self.elems[0].key-1),
                                   IntElem(self.elems[-1].key+1))

        self.lower = IntElem(1)
        self.upper = IntElem(9)

        self.vo = SkipListVO.range_query(self.sl, self.lower, self.upper)

    def test_range(self):
        """ Ensure that range queries work correctly
        """
        for i in range(0, self.num_iters):
            elems = []
            
            # hacked up to avoid repeated elements in elems
            i = 0
            while i < 5:
                x = IntElem(random.randint(-50, 50))
                if x not in elems:
                    i = i + 1
                    elems.append(x)

            sl = AuthSkipList.new(elems, IntElem(-101), IntElem(101))
            
            lower = random.choice(sorted(elems)[0:2])
            upper = random.choice(sorted(elems)[3:5])

            vo = SkipListVO.range_query(sl, lower, upper)
            
            try:
                elems = vo.verify(lower, upper, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(elems,
                             [e for e in sl.to_list_of_lists()[-1]
                                if lower <= e <= upper])

    def test_big_range_query(self):
        """ Check that range queries work
        """

        lower_bound = -100000
        upper_bound = 100000
        num_elems = 1000

        for i in range(0, self.num_iters):
            elems = [random.randint(lower_bound, upper_bound)
                     for i in range(num_elems)]
            elems = map(IntElem, set(elems))
            sl = AuthSkipList.new(elems, IntElem(lower_bound-1), IntElem(upper_bound+1))
            
            for j in range(0, self.num_iters):
                lower = IntElem(random.randint(lower_bound/5, upper_bound/100))
                upper = IntElem(random.randint(lower.key + 1000,
                                               upper_bound/5))

                vo = SkipListVO.range_query(sl, lower, upper)

                try:
                    elems = vo.verify(lower, upper, sl.root.label)
                except VerificationObjectException as e:
                    self.assertTrue(False, 'Error: %s' %e.msg)

                expected = [e for e in sl.to_list_of_lists()[-1]
                              if lower <= e <= upper]
                if len(elems) != len(expected):
                    print 'num returned elems:', len(elems)
                    print 'num expected elems:', len(expected)

                    for x, y in zip(elems, expected):
                        print x,
                        print '---',
                        print y

                self.assertEqual(elems, expected)

    def test_empty_vo_fails(self):
        elems = self.elems
        sl = self.sl
        lower = self.lower
        upper = self.upper
        vo = self.vo

        # Make sure it won't verify an empty VO
        bad_vo = SkipListVO(IntElem(0),
                            IntElem(10),
                            VONode(None, sl.root.down.label, sl.root.right.label, -1),
                            None)
        passed = False
        
        try:
            bad_vo.verify(lower, upper, sl.root.label)
        except VerificationObjectException as e:
            passed = True

        self.assertTrue(passed, 'Should not verify an empty VO')

    def test_bogus_root_hash(self):
        elems = self.elems
        sl = self.sl
        lower = self.lower
        upper = self.upper
        vo = self.vo

        # Make sure it won't verify a bogus root hash
        bad_root_hval = sha256(b'foobar').digest()
        passed = False
        
        try:
            vo.verify(lower, upper, bad_root_hval)
        except VerificationObjectException as e:
            passed = True

        self.assertTrue(passed, 'Should not verify a bogus root hash')

    def test_too_long_range(self):
        elems = self.elems
        sl = self.sl
        lower = self.lower
        upper = self.upper
        vo = self.vo

        # Make sure it won't let us return too many elements
        passed = False

        try:
            vo.verify(IntElem(1), IntElem(5), sl.root.label)
        except VerificationObjectException as e:
            passed = True

        self.assertTrue(passed, 'Should not verify an overextended range')

    def test_stringify(self):
        for i in range(0, self.num_iters):
            elems = [IntElem(random.randint(0, 100000000))
                     for i in range(0, 1000)]
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(100000001))

            lower = random.choice(elems[1:200])
            upper = random.choice(elems[500:-1])

            vo = SkipListVO.range_query(sl, lower, upper)
            
            self.assertTrue(isinstance(vo, SkipListVO))

            serialized = vo.serialize()
            new_vo = SkipListVO.deserialize(serialized, IntElem)

            print 'vo:'
            for l in vo.to_list_of_lists():
                print l

            print
            print new_vo.root
            print 'new_vo:'
            for l in new_vo.to_list_of_lists():
                print l

            self.assertEqual(vo, new_vo)

    def test_vo_insert(self):
        seed = str(time.time())
        random.seed(seed)
        for i in range(0, self.num_iters):
            elems = [IntElem(random.randint(0, 100000000))
                     for i in range(0, self.size)]
            num_elems = self.size
            elems.sort()
            
            for i in range(len(elems)-1):
                if elems[i] == elems[i+1]:
                    elems[i+1] = elems[i+1] + 1

            orig_elems = elems

            min_elem = IntElem(-1)
            max_elem = IntElem(100000001)
            
            sl = AuthSkipList.new(elems, min_elem, max_elem, RecordedCoin())

            left = IntElem(random.randint(5, 6000))
            right = IntElem(random.randint(left.key+100, 9000))
            
            vo = SkipListVO.range_query(
                sl, left, right, PrefixCoin([]))

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(elems, [e for e in orig_elems if left<=e<=right])

            elem = IntElem(random.randint(left.key+1, right.key-1))

            while elem in orig_elems:
                elem = IntElem(random.randint(left.key+1, right.key-1))

            bisect.insort(orig_elems, elem)

            sl.coin.read()
            sl.insert(elem)

            vo.coin.extend(sl.coin.read())
            vo.insert(elem)

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(sl.root.label, vo.root.label)
            self.assertEqual(elems, [e for e in orig_elems if left<=e<=right])

    def test_vo_insert_many_seeded(self):
        seed = str(time.time())
        random.seed(seed)
        for i in range(0, self.num_iters):
            seed = random.randint(0, 1000000)

            elems = [IntElem(random.randint(0, 100000000))
                     for i in range(0, self.size)]
            num_elems = self.size
            elems.sort()
            
            for i in range(len(elems)-1):
                if elems[i] == elems[i+1]:
                    elems[i+1] = elems[i+1] + 1

            orig_elems = elems

            min_elem = IntElem(-1)
            max_elem = IntElem(100000001)
            
            sl = AuthSkipList.new(elems, min_elem, max_elem)

            left = IntElem(random.randint(5, 6000000))
            right = IntElem(random.randint(left.key+100, 9000000))
            
            vo = SkipListVO.range_query(sl, left, right)

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(elems, [e for e in orig_elems if left<=e<=right])

            new_elems = [IntElem(random.randint(left.key+1, right.key-1))
                         for i in range(20)]
            
            sl.coin = SeededCoin(seed)
            vo.coin = SeededCoin(seed)

            for elem in new_elems:
                sl.insert(elem)

            for elem in new_elems:
                vo.insert(elem)

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(sl.root.label, vo.root.label)

    def test_vo_insert_many(self):
        seed = str(time.time())
        random.seed(seed)
        for i in range(0, self.num_iters):
            elems = [IntElem(random.randint(0, 100000000))
                     for i in range(0, self.size)]
            num_elems = self.size
            elems.sort()
            
            for i in range(len(elems)-1):
                if elems[i] == elems[i+1]:
                    elems[i+1] = elems[i+1] + 1

            orig_elems = elems

            min_elem = IntElem(-1)
            max_elem = IntElem(100000001)
            
            sl = AuthSkipList.new(elems, min_elem, max_elem, RecordedCoin())

            left = IntElem(random.randint(5, 6000000))
            right = IntElem(random.randint(left.key+100, 9000000))
            
            vo = SkipListVO.range_query(
                sl, left, right, PrefixCoin([]))

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(elems, [e for e in orig_elems if left<=e<=right])

            new_elems = [IntElem(random.randint(left.key+1, right.key-1))
                         for i in range(20)]

            sl.coin.read()

            for elem in new_elems:
                sl.insert(elem)

            vo.coin.extend(sl.coin.read())

            for elem in new_elems:
                vo.insert(elem)

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(sl.root.label, vo.root.label)

    def test_vo_insert_commutes(self):
        seed = str(time.time())
        random.seed(seed)
        for i in range(0, self.num_iters):
            elems = [IntElem(random.randint(0, 100000000))
                     for i in range(0, self.size)]
            num_elems = self.size
            elems.sort()
            
            for i in range(len(elems)-1):
                if elems[i] == elems[i+1]:
                    elems[i+1] = elems[i+1] + 1

            orig_elems = elems

            min_elem = IntElem(-1)
            max_elem = IntElem(100000001)
            
            sl = AuthSkipList.new(elems, min_elem, max_elem, RecordedCoin())

            left = IntElem(random.randint(5, 6000))
            right = IntElem(random.randint(left.key+100, 9000))
            
            vo = SkipListVO.range_query(
                sl, left, right, PrefixCoin([]))

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            elem = IntElem(random.randint(left.key+1, right.key-1))

            while elem in orig_elems:
                elem = IntElem(random.randint(left.key+1, right.key-1))

            bisect.insort(orig_elems, elem)

            sl.coin.read()
            sl.insert(elem)

            new_vo = SkipListVO.range_query(sl, left, right, PrefixCoin([]))

            vo.coin.extend(sl.coin.read())
            vo.insert(elem)

            try:
                elems = vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(sl.root.label, vo.root.label)
            self.assertEqual(elems, [e for e in orig_elems if left<=e<=right])

            try:
                elems = new_vo.verify(left, right, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(sl.root.label, vo.root.label)
            self.assertEqual(elems, [e for e in orig_elems if left<=e<=right])

            self.assertEqual(vo, new_vo)

    def test_different_single_insert(self):
        for i in range(0, self.num_iters):
            print
            print i
            orig_seed = random.randint(0, 10000000)
            elems = [IntElem(random.randint(0, 100)) for i in range(0, 5)]
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(elems[0].key-1),
                                  IntElem(elems[-1].key+1),
                                  SeededCoin(orig_seed))

            new_elem = IntElem(random.randint(elems[1].key, elems[-2].key))
            min_ne = elems[1]
            max_ne = elems[-2]

            vo = SkipListVO.range_query(sl, min_ne, max_ne)

            try:
                ret_elems = vo.verify(min_ne, max_ne, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            seed = random.randint(0, 1000000)
            vo.coin = SeededCoin(seed)
            sl.coin = SeededCoin(seed)

            self.assertEqual(vo.root.label, sl.root.label)

            vo.insert(new_elem)
            sl.insert(new_elem)

            self.assertEqual(sl.root.label, vo.root.label)

    def test_multiple_inserts(self):
        for i in range(0, self.num_iters):
            orig_seed = random.randint(0, 10000000)
            elems = [IntElem(random.randint(0, 100000000))
                     for i in range(0, 100)]
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(elems[0].key-1),
                                  IntElem(elems[-1].key+1),
                                  SeededCoin(orig_seed))

            new_elems = [IntElem(random.randint(elems[1].key, elems[-2].key))
                         for i in range(0, 10)]
            min_ne = min(new_elems)
            max_ne = max(new_elems)

            vo = SkipListVO.range_query(sl, min_ne, max_ne)

            try:
                ret_elems = vo.verify(min_ne, max_ne, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            seed = random.randint(0, 1000000)
            vo.coin = SeededCoin(seed)
            sl.coin = SeededCoin(seed)

            self.assertEqual(vo.root.label, sl.root.label)

            for elem in new_elems:
                vo.insert(elem)
                sl.insert(elem)
                self.assertEqual(sl.root.label, vo.root.label, 'failed on index %d' %new_elems.index(elem))

            self.assertEqual(sl.root.label, vo.root.label)
