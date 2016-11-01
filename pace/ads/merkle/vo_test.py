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

from hashlib import sha256
from unittest import TestCase

import time
import random

from pace.ads.merkle.mht_utils import MHTUtils
from pace.ads.merkle.mht import MHT
from pace.ads.merkle.vo import VO, VerificationObjectException
from pace.ads.merkle.vo_node import VONode
from pace.ads.merkle.empty_node import EmptyNode
from pace.common.pacetest import PACETestCase

class VOTest(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

        # Setup for small, hand-made tests
        self.elems = [0, 5, 6, 10]
        self.mht = MHT.new(self.elems)

        self.lower = 1
        self.upper = 9

        self.vo = self.mht.range_query(self.lower, self.upper)

    def test_range(self):
        """ Ensure that range queries work correctly
        """
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 1000)]
            elems.sort()
            mht = MHT.new(elems)

            lower = random.choice(elems[1:200])
            upper = random.choice(elems[500:999])

            vo = mht.range_query(lower, upper)
            
            try:
                vo.verify(lower, upper, mht.root.hval)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)
        
    def test_empty_vo_fails(self):
        elems = self.elems
        mht = self.mht
        lower = self.lower
        upper = self.upper
        vo = self.vo

        # Make sure it won't verify an empty VO
        bad_vo = VO(0, 10, EmptyNode(), [])
        passed = False
        
        try:
            bad_vo.verify(lower, upper, mht.root.hval)
        except VerificationObjectException as e:
            passed = True

        self.assertTrue(passed, 'Should not verify an empty VO')

    def test_bogus_root_hash(self):
        elems = self.elems
        mht = self.mht
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

    def test_omitted_element(self):
        elems = self.elems
        mht = self.mht
        lower = self.lower
        upper = self.upper
        vo = self.vo

        # Make sure it won't let us omit an element
        leaf0 = VONode.leaf(0)
        leaf5 = VONode.leaf(5)
        leaf6 = VONode.leaf(6)
        bad_leaf6 = leaf6.hval
        leaf10 = VONode.leaf(10)

        node05 = VONode.node(MHTUtils.merge_hashes(leaf0.hval, leaf5.hval),
                              leaf0, leaf5)
        node610 = VONode.node(MHTUtils.merge_hashes(bad_leaf6, leaf10.hval),
                               bad_leaf6, leaf10)
        bad_node610 = VONode.node(
            MHTUtils.merge_hashes(bad_leaf6, leaf10.hval), bad_leaf6, leaf10)

        root = VONode.node(
            MHTUtils.merge_hashes(node05.hval, bad_node610.hval),
            node05,
            bad_node610)
        bad_vo = VO(0, 10, root, [leaf0, leaf5, leaf10])

        passed = False

        assert root.hval == mht.root.hval
        
        try:
            bad_vo.verify(lower, upper, mht.root.hval)
        except VerificationObjectException as e:
            passed = True

        self.assertTrue(passed, 'Should not verify an incomplete tree')

    def test_too_long_range(self):
        elems = self.elems
        mht = self.mht
        lower = self.lower
        upper = self.upper
        vo = self.vo

        # Make sure it won't let us return too many elements
        passed = False

        try:
            vo.verify(1, 5, mht.root.hval)
        except VerificationObjectException as e:
            passed = True

        self.assertTrue(passed, 'Should not verify an overextended range')

    def test_stringify_leaf(self):
        for i in range(0, self.num_iters):
            elem = random.randint(0, 1000)
            l = VONode.leaf(elem)
            s = l.serialize()
            new_l, leaves = VONode.deserialize(s)

            self.assertEqual(l, new_l,
                'Taking a leaf to string and back must return an equivalent \
                 object')

    def test_stringify_node(self):
        for i in range(0, self.num_iters):
            elem1 = random.randint(0, 1000)
            elem2 = random.randint(0, 1000)

            l1, l2 = VONode.leaf(elem1), VONode.leaf(elem2)

            n = VONode.node(MHTUtils.merge_hashes(l1.hval, l2.hval), l1, l2)
            s = n.serialize()
            new_n, leaves = VONode.deserialize(s)

            self.assertEqual(n, new_n,
                'Taking a node to string and back must return an equivalent \
                 object')

    def test_stringify(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 1000)]
            elems.sort()
            mht = MHT.new(elems)

            lower = random.choice(elems[1:200])
            upper = random.choice(elems[500:-1])

            vo = mht.range_query(lower, upper)
            
            assert isinstance(vo, VO)

            serialized = vo.serialize()
            new_vo = VO.deserialize(serialized)

            self.assertEqual(vo, new_vo,
                'Error: to_string & from_string should return an \
                 equivalent object')

    def test_vo_insert(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 100)]
            elems.sort()
            mht = MHT.new(elems)
            root = mht.root.hval

            index = random.choice(range(1, 99))
            left = elems[index-1]
            right = elems[index]

            elem = random.choice(range(left, right))
            vo = mht.insert(elem)

            mht.valid()
            vo.verify(left+1, right-1, root)

            x, new_root = vo.insert(elem)
            vo.verify(left+1, right-1, new_root)

            self.assertEqual(vo.root.hval, mht.root.hval)
