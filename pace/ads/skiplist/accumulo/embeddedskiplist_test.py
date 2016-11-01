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
base_dir = os.path.join(this_dir, '../../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random

from pace.ads.skiplist.skiplistnode import InvalidSkipListException
from pace.ads.skiplist.accumulo.embeddednode import EmbeddedNode
from pace.ads.skiplist.accumulo.embeddedskiplist import EmbeddedSkipList
from pace.ads.skiplist.elemclass import IntElem
from pace.ads.skiplist.coin import HashCoin
from pace.ads.skiplist.authnode import AuthNode
from pace.ads.skiplist.authskiplist import AuthSkipList

from pace.common.pacetest import PACETestCase
from pace.common.fakeconn import FakeConnection

class EmbeddedSkipListTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))
        # NB: tests are already slow; chose a small
        #     number to make them feasible
        self.num_iters = 1

    def test_valid(self):
        """ Ensure that we only create valid skip lists
        """

        for i in xrange(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            sl = EmbeddedSkipList.new(
                    elems, IntElem(-1), IntElem(1000000001), conn_info=None)

            try:
                sl.valid()
            except InvalidSkipListException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

    def test_membership(self):
        """ Ensure that every element of the skip list is reflected as in it.
        """

        for i in xrange(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            sl = EmbeddedSkipList.new(elems, IntElem(-1), IntElem(1000000001), conn_info=None)

            for elem in elems:
                found, proof = sl.contains(elem)
                self.assertTrue(found,
                                'skip list claims not to have element %d' %elem.key)

    def test_verify_in(self):
        """ Ensure that proofs of membership validate.
        """

        for i in xrange(0, self.num_iters):
            elems = map(IntElem, self.generate_elems(-100, 100, 50))
            sl = EmbeddedSkipList.new(elems, IntElem(-101), IntElem(101), conn_info=None)

            for elem in elems:
                found, proof = sl.contains(elem)
                self.assertEqual(EmbeddedSkipList.verify(proof), sl.root.label)

    def test_verify_in_small(self):
        """ Ensure that proofs of membership validate (smaller test).
        """

        for i in xrange(0, self.num_iters):
            elems = map(IntElem, self.generate_elems(0, 50, 10))
            sl = EmbeddedSkipList.new(elems, IntElem(-1), IntElem(101), conn_info=None, coin=HashCoin())

            for elem in elems:
                found, proof = sl.contains(elem)
                self.assertEqual(EmbeddedSkipList.verify(proof), sl.root.label)

    def test_non_membership(self):
        """ Ensure that non-elements of the skip list are not in it
        """

        for i in xrange(0, 10 * self.num_iters):
            elems = map(IntElem, self.generate_elems(0, 25, 5))
            sl = EmbeddedSkipList.new(elems, IntElem(-201), IntElem(201), conn_info=None)

            found, proof = sl.contains(IntElem(-150))
            verification = EmbeddedSkipList.verify(proof)

            self.assertEqual(verification, sl.root.label)

            found, proof = sl.contains(IntElem(150))
            self.assertEqual(EmbeddedSkipList.verify(proof), sl.root.label)

            bad_elem = IntElem(random.randint(-100, 100))
            while bad_elem in elems:
                bad_elem = IntElem(random.randint(-100, 100))

            found, proof = sl.contains(bad_elem)
            self.assertEqual(EmbeddedSkipList.verify(proof), sl.root.label,
                'proof of absence of %d fails to verify' %bad_elem.key)

    def test_medium_range_query(self):
        """ Check that range queries work
        """

        lower_bound = -10000
        upper_bound = 10000
        num_elems = 100

        for i in xrange(0, self.num_iters):
            elems = map(IntElem,
                        self.generate_elems(
                            lower_bound, upper_bound, num_elems))
            for x in elems:
                if elems.count(x) > 1:
                    elems.remove(x)

            sl = EmbeddedSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1), conn_info=None)
            
            for j in xrange(0, self.num_iters):
                lower = IntElem(random.randint(lower_bound/5, upper_bound/100))
                upper = IntElem(random.randint(lower.key+10, upper_bound/2))

                proofs = sl._range_query(lower, upper)
                received = EmbeddedSkipList._verify_range_query(
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
    def test_smaller_range_query(self):
        """ Check that range queries work
        """

        lower_bound = -100
        upper_bound = 100
        num_elems = 5

        for i in xrange(0, self.num_iters):
            elems = map(IntElem,
                        self.generate_elems(
                            lower_bound, upper_bound, num_elems))
            for x in elems:
                if elems.count(x) > 1:
                    elems.remove(x)

            sl = EmbeddedSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1), conn_info=None)
            
            for j in xrange(0, self.num_iters):
                lower = IntElem(random.randint(lower_bound/5, upper_bound/100))
                upper = IntElem(random.randint(lower.key+10, upper_bound/2))

                proofs = sl._range_query(lower, upper)
                received = EmbeddedSkipList._verify_range_query(
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

        for i in xrange(0, self.num_iters):
            elems = map(IntElem,
                        self.generate_elems(
                            lower_bound, upper_bound, num_elems))
            sl = EmbeddedSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1), conn_info=None)

            old_label = sl.root.label

            new_elems = map(IntElem,
                        self.generate_elems(
                            lower_bound, upper_bound, num_new_elems))
            new_elems = [elem for elem in new_elems if elem not in elems]

            for elem in new_elems:
                ret_elems, proof, proof_diff = sl.insert_with_diff(elem)

                self.assertEqual(
                    EmbeddedSkipList.verify(
                        [EmbeddedNode._hash(e.serialize())
                         for e in reversed(ret_elems)] + proof),
                        old_label)

                new_proof = EmbeddedSkipList.update_query(
                    ret_elems, proof, proof_diff, elem)

                x, qproof = sl.contains(elem)
                self.assertTrue(x,
                    'Claims just-inserted element is not in list')
                self.assertEqual(EmbeddedSkipList.verify(qproof), sl.root.label)

                np = EmbeddedSkipList.verify(new_proof)
                self.assertEqual(np, sl.root.label)

                old_label = sl.root.label

    def test_small_verified_insert(self):
        """ Test that verified insert actually allows the client to compute
            the new root label.
        """
        lower_bound = -100
        upper_bound = 100
        num_elems = 5
        num_new_elems = 10

        for i in xrange(0, self.num_iters):
            elems = map(IntElem,
                        self.generate_elems(
                            lower_bound, upper_bound, num_elems))
            sl = EmbeddedSkipList.new(elems, IntElem(lower_bound-1),
                                  IntElem(upper_bound+1), conn_info=None,
                                  coin=HashCoin())

            old_label = sl.root.label

            new_elems = map(IntElem,
                        self.generate_elems(
                            lower_bound, upper_bound, num_new_elems))
            new_elems = [elem for elem in new_elems if elem not in elems]

            for elem in new_elems:
                ret_elems, proof, proof_diff = sl.insert_with_diff(elem)

                self.assertEqual(
                    EmbeddedSkipList.verify(
                        [EmbeddedNode._hash(e.serialize())
                         for e in reversed(ret_elems)] + proof),
                        old_label)

                new_proof = EmbeddedSkipList.update_query(
                    ret_elems, proof, proof_diff, elem)

                x, qproof = sl.contains(elem)
                self.assertTrue(x,
                    'Claims just-inserted element is not in list')
                self.assertEqual(EmbeddedSkipList.verify(qproof), sl.root.label)

                np = EmbeddedSkipList.verify(new_proof)
                self.assertEqual(np, sl.root.label)

                old_label = sl.root.label

    def test_comparison_to_auth(self):
        """ Test embedded list and authenticated list side-by-side to see where
            the former goes wrong. Mostly here for debugging.
        """

        for i in xrange(0, self.num_iters):
            elems = map(IntElem, self.generate_elems(0, 50, 10))
            esl = EmbeddedSkipList.new(elems, IntElem(-1), IntElem(101), coin=HashCoin(), conn_info=None)
            asl = AuthSkipList.new(elems, IntElem(-1), IntElem(101), coin=HashCoin())

            for elem in elems:
                evisited, eclosest = esl.root.search(elem)
                avisited, aclosest = asl.root.search(elem)

                new = []
                for n, f in evisited:
                    new.append((n, f))
                evisited = new

                eelems, eproof = esl.do_query(evisited, eclosest, elem)
                aelems, aproof = asl.do_query(avisited, aclosest, elem)

                efound = eelems[0] == elem
                afound = aelems[0] == elem
                
                eproof = [AuthNode._hash(x.serialize())
                          for x in reversed(eelems)] + eproof
                aproof = [AuthNode._hash(x.serialize())
                          for x in reversed(aelems)] + aproof
                
                # Make sure the embedded one isn't cheating somehow
                self.assertEqual(esl.root.label, asl.root.label)

                self.assertEqual(AuthSkipList.verify(aproof),
                                 asl.root.label)
                self.assertEqual(EmbeddedSkipList.verify(eproof),
                                 esl.root.label)

                # Make sure the embedded one isn't cheating somehow
                self.assertEqual(esl.root.label, asl.root.label)

    def test_non_membership_comp(self):
        """ Ensure that non-elements of the skip list are not in it,
            comparing the results to the authenticated skip list.
        """

        for i in xrange(0, 10 * self.num_iters):
            elems = map(IntElem, self.generate_elems(0, 25, 5))
            esl = EmbeddedSkipList.new(elems, IntElem(-201), IntElem(201), coin=HashCoin(), conn_info=None)
            asl = AuthSkipList.new(elems, IntElem(-201), IntElem(201), coin=HashCoin())

            bad_elem = IntElem(random.randint(-100, 100))
            while bad_elem in elems:
                bad_elem = IntElem(random.randint(-100, 100))

            bad_elems = [IntElem(-150), IntElem(150), bad_elem]

            for elem in bad_elems:

                evisited, eclosest = esl.root.search(elem)
                avisited, aclosest = asl.root.search(elem)

                new = []
                for n, f in evisited:
                    new.append((n, f))
                evisited = new

                eelems, eproof = esl.do_query(evisited, eclosest, elem)
                aelems, aproof = asl.do_query(avisited, aclosest, elem)

                efound = eelems[0] == elem
                afound = aelems[0] == elem

                eproof = [AuthNode._hash(x.serialize())
                          for x in reversed(eelems)] + eproof
                aproof = [AuthNode._hash(x.serialize())
                          for x in reversed(aelems)] + aproof
                
                self.assertEqual(efound, afound)
                self.assertTrue(not efound)
                
                self.assertEqual(AuthSkipList.verify(aproof),
                                 asl.root.label)
                self.assertEqual(EmbeddedSkipList.verify(eproof),
                                 esl.root.label)

                # Make sure the embedded one isn't cheating somehow
                self.assertEqual(esl.root.label, asl.root.label)

