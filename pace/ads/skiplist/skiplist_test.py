## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for skip list library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  19 Aug 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random

from pace.ads.skiplist.skiplist import SkipList
from pace.common.pacetest import PACETestCase

class SkipListTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

    def test_valid(self):
        """ Ensure that we only create valid skip lists
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 1000000000)
                     for i in range(0, self.size)]
            sl = SkipList.new(elems, -1, 1000000001)
            
            try:
                sl.valid()
            except InvalidSkipListException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

    def test_membership(self):
        """ Ensure that every element of the skip list is reflected as in it.
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, self.size)]
            sl = SkipList.new(elems, -1, 1000000001)

            for elem in elems:
                self.assertTrue(sl.contains(elem),
                                'skip list claims not to have element %d' %elem)

    def test_non_membership(self):
        """ Ensure that non-elements of the skip list are not in it
        """

        for i in range(0, self.num_iters):
            elems = [random.randint(0, 100000000) for i in range(0, self.size)]
            sl = SkipList.new(elems, -1, 1000000001)

            self.assertEqual(sl.contains(-2), False,
                "skip list thinks it contains -2 (it doesn't)")
            self.assertEqual(sl.contains(100000002), False,
                "skip list thinks it contains 100000002 (it doesn't)")

            bad_elem = random.randint(0, 100000000)
            while bad_elem in elems:
                bad_elem = random.randint(0, 100000000)

            self.assertEqual(sl.contains(bad_elem), False,
                "skip list thinks it contains %d (it doesn't)" %bad_elem)
