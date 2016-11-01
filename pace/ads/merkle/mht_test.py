## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for MHT library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  17 Jul 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random

from pace.ads.merkle.mht import MHT, MHTInsertionException
from pace.ads.merkle.mht_utils import MHTUtils
from pace.common.pacetest import PACETestCase


class MerkleTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

    def test_valid(self):
        """ Ensure that we only create valid hash trees.
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 1000000000)
                     for i in range(0, self.size/2)]
            elems.sort()
            mht = MHT.new(elems)
            
            try:
                mht.valid()
            except InvalidMerkleTree as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

    def test_membership(self):
        """ Ensure that every element of the hash tree is reflected as in it.
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 100)]
            elems.sort()
            mht = MHT.new(elems)

            for elem in elems:
                self.assertTrue(mht.contains(elem),
                                'MHT claims not to have element %d' %elem)

    def test_non_membership(self):
        """ Ensure that non-elements of the MHT are not in it
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 100)]
            elems.sort()
            mht = MHT.new(elems)

            self.assertEqual(mht.contains(-1), None,
                "MHT thinks it contains -1 (it doesn't)")
            self.assertEqual(mht.contains(100000001), None,
                "MHT thinks it contains 100000001 (it doesn't)")

    def test_proofs(self):
        """ Ensure that the returned membership proofs are valid.
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 100)]
            elems.sort()
            mht = MHT.new(elems)

            for elem in elems:
                proof = mht.contains(elem)
                self.assertTrue(MHTUtils.verify(mht.root.hval, elem, proof),
                                'Returned proof does not verify that %d is in \
                                 the tree' %elem)

    def test_partial_insert(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 100)]
            elems.sort()

            index = random.choice(range(1, 99))
            left = elems[index-1]
            right = elems[index]

            elem = random.choice(range(left, right))

            new_elems, i = MHT.partial_insert(elems, elem)

            self.assertEqual(index, i, 'Error: element inserted at wrong index')
            self.assertEqual(new_elems,
                             elems[:index] + [elem] + elems[index:],
                             'Error: failure to insert element into list')

    def test_left_insert_fails(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 100)]
            elems.sort()
            elems = elems[1:]

            index = random.choice(range(1, 99))
            left = elems[index-1]
            right = elems[index]

            mht = MHT.new(elems)
            elem = 0

            try:
                mht.insert(elem)
            except MHTInsertionException as e:
                return

            raise Error('Not supposed to succeed on an out-of-range insert.')
                
    def test_valid_insert(self):
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

    def test_insert_contains(self):
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

            proof = mht.contains(elem)

            self.assertTrue(MHTUtils.verify(mht.root.hval, elem, proof),
                            'Returned proof does not verify that inserted \
                             element is in the tree')

    def test_batch_insert(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 300)]
            elems.sort()
            mht = MHT.new(elems)
            root = mht.root.hval

            new_elems = [random.randint(elems[0], elems[-1])
                         for i in range(0, 50)]

            mht.batch_insert(new_elems)

            for elem in new_elems:
                proof = mht.contains(elem)

                self.assertTrue(MHTUtils.verify(mht.root.hval, elem, proof),
                                'Returned proof does not verify that inserted \
                                 element is in the tree')

    def test_gestalt_batch_insert(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 300)]
            elems.sort()
            mht = MHT.new(elems)
            control_mht = MHT.new(elems)
            root = mht.root.hval

            left = random.choice(elems[1:self.size/3])
            right = random.choice(elems[2*self.size/3:-1])

            new_elems = [random.randint(left, right)
                         for i in range(0, 50)]

            mht._gestalt_batch_insert(left, right, new_elems)
            mht.valid()     ## make sure it's valid
            control_mht.batch_insert(new_elems)

            self.assertEqual(mht.sorted_elems, control_mht.sorted_elems)

            for elem in new_elems:
                proof = mht.contains(elem)

                self.assertTrue(proof is not None,
                                'Added element not in tree')
                self.assertTrue(MHTUtils.verify(mht.root.hval, elem, proof))

    def test_gestalt_batch_insert_again(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(1, 99999999)
                     for i in range(0, 98)]
            elems.sort()
            elems = [0] + elems + [100000000]

            mht = MHT.new(elems)

            for i in range(1, 10):
                elems = [random.randint(1, 99999999)
                         for i in range(1, 100)]
                mht._gestalt_batch_insert(min(elems), max(elems), elems)
                mht.valid()
        

    def test_batch_insert_vo(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 300)]
            elems.sort()
            mht = MHT.new(elems)
            root = mht.root.hval

            new_elems = [random.randint(elems[0], elems[-1])
                         for i in range(0, 50)]

            vo = mht.range_query(min(new_elems), max(new_elems))

            mht.batch_insert(new_elems)

            for elem in new_elems:
                proof = mht.contains(elem)
                vo.insert(elem)

                self.assertTrue(MHTUtils.verify(mht.root.hval, elem, proof),
                                'Returned proof does not verify that inserted \
                                 element is in the tree')

            self.assertEqual(vo.root.hval, mht.root.hval)

    def test_both_inserts(self):
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, 300)]
            elems.sort()
            mht = MHT.new(elems)
            root = mht.root.hval

            new_elems = [random.randint(elems[0], elems[-1])
                         for i in range(0, 50)]

            vo = mht.range_query(min(new_elems), max(new_elems))

            mht.batch_insert(new_elems)

            for elem in new_elems:
                vo.insert(elem)

            self.assertEqual(vo.root.hval, mht.root.hval)
