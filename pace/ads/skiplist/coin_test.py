## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Unit tests for coin library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  08 Aug 2014  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random

from pace.ads.skiplist.coin import BaseCoin, PrefixCoin, SeededCoin, RecordedPrefixCoin, RecordedCoin, HashCoin
from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.elemclass import IntElem
from pace.common.pacetest import PACETestCase

class SkipListTests(PACETestCase):

    def setUp(self):
        self.sizes = [10, 100, 1000, 10000]
        random.seed(time.time())
        
    def hash_coin_test(self):
        for n in self.sizes:
            for iters in range(self.num_iters):

                elems = [str(random.randint(-10000000, 10000000))
                         for i in range(1000)]

                hc = HashCoin()
                hash_elems1 = [hc.flip(e) for e in elems]
                hash_elems2 = [hc.flip(e) for e in elems]

                self.assertEqual(hash_elems1, hash_elems2)

    def prefix_coin_test(self):
        for n in self.sizes:
            for iters in range(self.num_iters):

                bc = BaseCoin()
                elems = [bc.flip() for i in range(n)]

                pc = PrefixCoin(elems)
                prefix_elems = [pc.flip() for i in range(n)]

                self.assertEqual(elems, prefix_elems)

    def seeded_coin_test(self):
        for n in self.sizes:
            for iters in range(self.num_iters):
                rand = random.randint(0,1000)
                random.seed(rand)

                bc = BaseCoin()
                elems = [bc.flip() for i in range(n)]

                sc = SeededCoin(rand)
                seeded_elems = [sc.flip() for i in range(n)]

                self.assertEqual(elems, seeded_elems)

    def record_coin_test(self):
        for n in self.sizes:
            for iters in range(self.num_iters):
                rand = random.randint(0,1000)
                random.seed(rand)

                bc = BaseCoin()
                elems = [bc.flip() for i in range(n)]

                random.seed(rand)
                rc = RecordedCoin()
                more_elems = [rc.flip() for i in range(n)]
                rec_elems = rc.record

                self.assertEqual(elems, rec_elems)
                self.assertEqual(elems, more_elems)
    
    def record_prefix_coin_test(self):
        for n in self.sizes:
            for iters in range(self.num_iters):
                rand = random.randint(0,1000)
                random.seed(rand)

                bc = BaseCoin()
                elems = [bc.flip() for i in range(n)]

                random.seed(rand)
                rpc = RecordedPrefixCoin(elems)
                more_elems = [rpc.flip() for i in range(n)]
                rec_elems = rpc.record

                self.assertEqual(elems, rec_elems)
                self.assertEqual(elems, more_elems)

    def base_coin_test(self):
        for n in self.sizes:
            for iters in range(self.num_iters):
                rand = random.randint(0,1000)
                random.seed(rand)

                elems = [random.randint(0,1) == 1 for i in range(n)]

                random.seed(rand)
                bc = BaseCoin()
                flipped_elems = [bc.flip() for i in range(n)]

                self.assertEqual(elems, flipped_elems)

    def skiplist_test(self):
        """ Make sure the different coins can be used to guarantee the same
            skiplist.
        """
        for n in self.sizes[:-1]:
            for iters in range(self.num_iters):
                max_elem = n * 100
                min_elem = -1 * max_elem

                lower = IntElem(min_elem-1)
                upper = IntElem(max_elem+1)
                
                elems = [IntElem(random.randint(min_elem, max_elem))
                         for i in range(n)]

                rand = random.randint(0,1000)
                random.seed(rand)

                prefix = [random.randint(0,1) == 1 for i in range(10 * n)]

                random.seed(rand)
                sl_base = AuthSkipList.new(
                    elems, lower, upper, BaseCoin())

                random.seed(rand)
                sl_recd = AuthSkipList.new(
                    elems, lower, upper, RecordedCoin())

                sl_pref = AuthSkipList.new(
                    elems, lower, upper, PrefixCoin(prefix))

                sl_rpre = AuthSkipList.new(
                    elems, lower, upper, RecordedPrefixCoin(prefix))

                sl_seed = AuthSkipList.new(
                    elems, lower, upper, SeededCoin(rand))

                self.assertEqual(sl_seed.to_list_of_lists(),
                                 sl_rpre.to_list_of_lists())
                self.assertEqual(sl_rpre.to_list_of_lists(),
                                 sl_pref.to_list_of_lists())
                self.assertEqual(sl_pref.to_list_of_lists(),
                                 sl_recd.to_list_of_lists())
                self.assertEqual(sl_recd.to_list_of_lists(),
                                 sl_base.to_list_of_lists())

                self.assertEqual(sl_seed.root.label,
                                 sl_rpre.root.label)
                self.assertEqual(sl_rpre.root.label,
                                 sl_pref.root.label)
                self.assertEqual(sl_pref.root.label,
                                 sl_recd.root.label)
                self.assertEqual(sl_recd.root.label,
                                 sl_base.root.label)




