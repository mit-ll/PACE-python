## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for authenticated skip lists
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  21 Aug 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random

from pace.ads.skiplist.skiplistnode import InvalidSkipListException
from pace.ads.skiplist.authnode import AuthNode
from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.elemclass import IntElem
from pace.common.pacetest import PACETestCase

def gen_elems(lower, upper, num):
    return [IntElem(random.randint(lower, upper)) for i in range(num)]

class AuthSkipListTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

    def test_valid(self):
        """ Ensure that we only create valid skip lists
        """

        for i in range(0, self.num_iters):
            elems = gen_elems(0, 1000000000, self.size)
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(1000000001))
            
            try:
                sl.valid()
            except InvalidSkipListException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

    def test_membership(self):
        """ Ensure that every element of the skip list is reflected as in it.
        """

        for i in range(0, self.num_iters):
            elems = gen_elems(0, 100000000, self.size)
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(1000000001))

            for elem in elems:
                found, proof = sl.contains(elem)
                self.assertTrue(found,
                                'skip list claims not to have element %d' %elem.key)

    def test_verify_in(self):
        """ Ensure that proofs of membership validate.
        """

        for i in range(0, self.num_iters):
            elems = gen_elems(-100, 100, 50)
            sl = AuthSkipList.new(elems, IntElem(-101), IntElem(101))

            for elem in elems:
                found, proof = sl.contains(elem)
                self.assertEqual(AuthSkipList.verify(proof), sl.root.label)

    def test_non_membership(self):
        """ Ensure that non-elements of the skip list are not in it
        """

        for i in range(0, 10 * self.num_iters):
            elems = gen_elems(0, 25, 5)
            sl = AuthSkipList.new(elems, IntElem(-201), IntElem(201))

            found, proof = sl.contains(IntElem(-150))
            verification = AuthSkipList.verify(proof)

            self.assertEqual(verification, sl.root.label)

            found, proof = sl.contains(IntElem(150))
            self.assertEqual(AuthSkipList.verify(proof), sl.root.label)

            bad_elem = IntElem(random.randint(-100, 100))
            while bad_elem in elems:
                bad_elem = IntElem(random.randint(-100, 100))

            found, proof = sl.contains(bad_elem)
            self.assertEqual(AuthSkipList.verify(proof), sl.root.label,
                'proof of absence of %d fails to verify' %bad_elem.key)

    def test_range_query(self):
        """ Check that range queries work
        """

        lower_bound = -100000
        upper_bound = 100000
        num_elems = 1000

        for i in range(0, self.num_iters):
            elems = gen_elems(lower_bound, upper_bound, num_elems)
            for x in elems:
                if elems.count(x) > 1:
                    elems.remove(x)
            sl = AuthSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1))
            
            for j in range(0, self.num_iters):
                lower = IntElem(random.randint(lower_bound/5, upper_bound/100))
                upper = IntElem(random.randint(lower.key+1000, upper_bound/5))

                proofs = sl._range_query(lower, upper)
                received = AuthSkipList._verify_range_query(
                    proofs, lower, upper, sl.root.label)

                bottom = sl.root
                while bottom.down:
                    bottom = bottom.down

                expected = []
                while bottom.right and bottom.elem <= upper:
                    if bottom.elem >= lower:
                        expected.append(bottom.elem)
                    bottom = bottom.right

                self.assertTrue(all([lower <= x <= upper for x in expected]))
                self.assertTrue(sorted(expected) == expected)

                print 'Range query from %d to %d' %(lower.key, upper.key)
                print "Expected length: %d" %len(expected)
                print "Received length: %d" %len(received)

                self.assertEqual(expected, received)

    def test_smaller_range_query(self):
        """ Check that range queries work
        """

        lower_bound = -100
        upper_bound = 100
        num_elems = 5

        for i in range(0, self.num_iters):
            elems = gen_elems(lower_bound, upper_bound, num_elems)
            for x in elems:
                if elems.count(x) > 1:
                    elems.remove(x)

            sl = AuthSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1))
            
            for j in range(0, self.num_iters):
                lower = IntElem(random.randint(lower_bound/5, upper_bound/100))
                upper = IntElem(random.randint(lower.key+10, upper_bound/2))

                proofs = sl._range_query(lower, upper)
                received = AuthSkipList._verify_range_query(
                    proofs, lower, upper, sl.root.label)

                bottom = sl.root
                while bottom.down:
                    bottom = bottom.down

                expected = []
                while bottom.right and bottom.elem <= upper:
                    assert bottom.elem != bottom.right.elem
                    if bottom.elem >= lower:
                        expected.append(bottom.elem)
                    bottom = bottom.right

                self.assertTrue(all([lower <= x <= upper for x in expected]))
                self.assertTrue(sorted(expected) == expected)

                self.assertEqual(expected, received)
    
    def test_verified_insert(self):
        """ Test that verified insert actually allows the client to compute
            the new root label.
        """
        lower_bound = -1000
        upper_bound = 1000
        num_elems = 10
        num_new_elems = 150

        for i in range(0, self.num_iters):
            elems = gen_elems(lower_bound, upper_bound, num_elems)
            elems = set(elems)
            sl = AuthSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1))

            old_label = sl.root.label

            new_elems = gen_elems(lower_bound, upper_bound, num_new_elems)
            new_elems = [elem for elem in new_elems if elem not in elems]

            for elem in new_elems:
                print 'inserting elem %d' %elem.key
                print 'into list %s' %str(sl.to_list_of_lists())
                ret_elems, proof, proof_diff = sl.insert_with_diff(elem)
                print 'result list: %s' %str(sl.to_list_of_lists())

                self.assertEqual(
                    AuthSkipList.verify(
                        [AuthNode._hash(e.serialize())
                         for e in reversed(ret_elems)] + proof),
                        old_label)

                new_proof = AuthSkipList.update_query(
                    ret_elems, proof, proof_diff, elem)

                x, qproof = sl.contains(elem)
                self.assertTrue(x,
                    'Claims just-inserted element is not in list')
                self.assertEqual(AuthSkipList.verify(qproof), sl.root.label)

                np = AuthSkipList.verify(new_proof)
                print 'Root label: %s' %str(sl.root.label)
                print 'Recv label: %s' %str(np)
                self.assertEqual(np, sl.root.label)

                old_label = sl.root.label
