## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Unit tests for SkipList servers
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  10 Oct 2014  CS    Original file (copied from ../merkle/mht_server_test.py
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import random
import socket
import time

from threading import Thread

from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.skiplist_server import SocketSLServer, SLHandler, SeededSocketSLClient, PrefixSocketSLClient, HashSocketSLClient
from pace.ads.skiplist.skiplistvo import SkipListVO, VerificationObjectException
from pace.ads.skiplist.coin import SeededCoin, RecordedCoin, HashCoin
from pace.ads.skiplist.elemclass import IntElem
from pace.common.pacetest import PACETestCase

class SLServerTest(PACETestCase):

    @staticmethod
    def run_server(server):
        server.serve_forever()

    def setUp(self):
        # Need the extra randomness to make sure it doesn't generate the
        # same seed on different tests.
        random.seed(int(time.time()) + random.randint(0, 1000))

        self.host = 'localhost'
        self.port = random.randint(9000, 9999)

        # Try 10 times to get a valid port; if not, will fail. If this
        # fails, check to make sure ports 9000-9999 are not in use.
        for _ in xrange(10):
            try:
                self.server = SocketSLServer(IntElem, (self.host, self.port),
                                             SLHandler)
                break
            except socket.error:
                self.port = random.randint(9000, 9999)
                
        self.thread = Thread(group=None, target=SLServerTest.run_server,
                             name=None, args=[self.server], kwargs={})
        self.thread.daemon = True
        self.thread.start()

        print 'Starting test',
        self.start_time = time.time()

    def tearDown(self):
        self.end_time = time.time()
        print 'Test finished. Time taken: %s' %str(self.end_time - self.start_time)
        self.server.shutdown()
        self.thread.join()

    def test_remote_prefix_query(self):
        for i in range(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            coin = RecordedCoin()
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(1000000001), coin)

            with PrefixSocketSLClient.new(
                    elems, IntElem(-1), IntElem(1000000001), coin.record,
                    IntElem, self.host, self.port) as client:
                for j in range(0, self.num_iters):
                    elem = random.choice(elems)
                    good_result = sl.contains(elem)
                    test_result = client.query(elem)
                    self.assertEqual(good_result, test_result)

    def test_remote_seed_query(self):
        for i in range(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            seed = random.randint(0, 100000)
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(1000000001), SeededCoin(seed))

            with SeededSocketSLClient.new(
                    elems, IntElem(-1), IntElem(1000000001), seed, IntElem, self.host, self.port) as client:
                for j in range(0, self.num_iters):
                    elem = random.choice(elems)
                    good_result = sl.contains(elem)
                    test_result = client.query(elem)
                    self.assertEqual(good_result, test_result)

    def test_remote_hash_query(self):
        for i in range(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(1000000001), HashCoin())

            with HashSocketSLClient.new(
                    elems, IntElem(-1), IntElem(1000000001), IntElem, self.host, self.port) as client:
                for j in range(0, self.num_iters):
                    elem = random.choice(elems)
                    good_result = sl.contains(elem)
                    test_result = client.query(elem)
                    self.assertEqual(good_result, test_result)

    def test_remote_range_query(self):
        total_time = 0
        for i in range(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            seed = random.randint(0, 100000)
            sl = AuthSkipList.new(elems, IntElem(-1), IntElem(1000000001), SeededCoin(seed))
            start = time.time()
            with SeededSocketSLClient.new(
                    elems, IntElem(-1), IntElem(1000000001), seed, IntElem, self.host, self.port) as client:
                ## Get valid lower & upper bounds with enough room between
                ## them (about a third of the list) for a substantial range
                ## query
                lower = random.choice(elems[1:self.size/3])
                upper = random.choice(elems[2*self.size/3:-1])

                self.assertEqual(SkipListVO.range_query(sl, lower, upper),
                                 client.range_query(lower, upper))
            end = time.time()
            total_time = total_time + (end - start)

        print 'Average time taken: %s' %str(total_time / self.num_iters)

    def test_remote_range_query_2(self):
        for i in range(0, self.num_iters):
            orig_seed = random.randint(0, 10000000)
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(elems[0].key-1),
                                  IntElem(elems[-1].key+1),
                                  SeededCoin(orig_seed))

            with SeededSocketSLClient.new(
                    elems, IntElem(elems[0].key-1), IntElem(elems[-1].key+1),
                    orig_seed, IntElem, self.host, self.port) as client:

                lower = random.choice(elems[1:self.size/3])
                upper = random.choice(elems[2*self.size/3:-1])

                localvo = SkipListVO.range_query(sl, lower, upper)
                othervo = client.range_query(lower, upper)

                try:
                    ret_elems = localvo.verify(lower, upper, sl.root.label)
                except VerificationObjectException as e:
                    self.assertTrue(False, 'Error: %s' %e.msg)

                self.assertEqual(ret_elems, [x for x in elems
                                             if lower <= x <= upper])

                try:
                    ret_elems = othervo.verify(lower, upper, sl.root.label)
                except VerificationObjectException as e:
                    self.assertTrue(False, 'Error: %s' %e.msg)

                self.assertEqual(ret_elems, [x for x in elems
                                             if lower <= x <= upper])

                self.assertEqual(localvo, othervo)

    def test_remote_batch_insert(self):
        for i in range(0, self.num_iters):
            orig_seed = random.randint(0, 10000000)
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(elems[0].key-1),
                                  IntElem(elems[-1].key+1),
                                  SeededCoin(orig_seed))
            old_root = sl.root.label

            self.assertEqual(len(sl.to_list_of_lists()[-1])-2, self.size)

            ## Generate a small number (in this case, n/10) of random elements
            ## between the minimum and maximum elements (not including the
            ## boundary elements) to insert.
            new_elems = map(IntElem,
                            self.generate_elems(
                                elems[1].key, elems[-2].key, self.size/10))
            min_ne = min(new_elems)
            max_ne = max(new_elems)

            vo = SkipListVO.range_query(sl, min_ne, max_ne)

            try:
                ret_elems = vo.verify(min_ne, max_ne, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(ret_elems, [x for x in elems
                                         if min_ne <= x <= max_ne])

            seed = random.randint(0, 1000000)
            vo.coin = SeededCoin(seed)
            sl.coin = SeededCoin(seed)

            self.assertEqual(vo.root.label, sl.root.label)

            with SeededSocketSLClient.new(
                    elems, IntElem(elems[0].key-1), IntElem(elems[-1].key+1),
                    orig_seed, IntElem, self.host, self.port) as client:
                lower = random.choice(elems[1:self.size/3])
                upper = random.choice(elems[2*self.size/3:-1])

                self.assertEqual(SkipListVO.range_query(sl, lower, upper),
                                 client.range_query(lower, upper))

                self.assertEqual(SkipListVO.range_query(sl, min_ne, max_ne),
                                 client.range_query(min_ne, max_ne))

                for elem in new_elems:
                    vo.insert(elem)
                for elem in new_elems:
                    sl.insert(elem)

                self.assertEqual(sl.root.label, vo.root.label)

                try:
                    new_root = client.batch_insert(old_root, new_elems,
                        min_ne, max_ne, seed)
                except VerificationObjectException as e:
                    self.assertTrue(False, 'Error: %s' %e.msg)

                self.assertEqual(new_root, vo.root.label)

                self.assertEqual(sl.root.label, new_root)
                self.assertEqual(len(sl.to_list_of_lists()[-1])-2,
                                 self.size + (self.size/10))

                for elem in new_elems:
                    proof = client.query(elem)
                    self.assertEqual(proof, sl.contains(elem))
                    self.assertEqual(AuthSkipList.verify(proof[1]), sl.root.label)

    def test_remote_batch_insert_helper(self):
        for i in range(0, self.num_iters):
            orig_seed = random.randint(0, 10000000)
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(elems[0].key-1),
                                  IntElem(elems[-1].key+1),
                                  SeededCoin(orig_seed))

            new_elems = [IntElem(random.randint(elems[1].key, elems[-2].key))
                         for i in range(0, 2)]
            min_ne = min(new_elems)
            max_ne = max(new_elems)

            while min_ne == max_ne:
                new_elems = [IntElem(random.randint(elems[1].key, elems[-2].key))
                             for i in range(0, 2)]
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

            orig_label = sl.root.label

            for elem in new_elems:
                vo.insert(elem)
                sl.insert(elem)
                self.assertEqual(sl.root.label, vo.root.label, 'failed on index %d' %new_elems.index(elem))

            self.assertEqual(sl.root.label, vo.root.label)

            with SeededSocketSLClient.new(
                    elems, IntElem(elems[0].key-1), IntElem(elems[-1].key+1),
                    orig_seed, IntElem, self.host, self.port) as client:

                try:
                    new_root = client.batch_insert(orig_label, new_elems,
                        min_ne, max_ne, seed)
                except VerificationObjectException as e:
                    self.assertTrue(False, 'Error: %s' %e.msg)

                self.assertEqual(new_root, vo.root.label)

                self.assertEqual(sl.root.label, new_root)
                self.assertEqual(len(sl.to_list_of_lists()[-1])-2,
                                 len(elems) + len(new_elems))

                for elem in new_elems:
                    proof = client.query(elem)
                    self.assertEqual(proof, sl.contains(elem))
                    self.assertEqual(AuthSkipList.verify(proof[1]), sl.root.label)

    def test_remote_batch_insert_hash_coin(self):
        for i in range(0, self.num_iters):
            elems = map(IntElem, self.generate_elems())
            elems.sort()
            sl = AuthSkipList.new(elems, IntElem(elems[0].key-1),
                                  IntElem(elems[-1].key+1), HashCoin())
            old_root = sl.root.label

            self.assertEqual(len(sl.to_list_of_lists()[-1])-2, self.size)

            ## Generate a small number (in this case, n/10) of random elements
            ## between the minimum and maximum elements (not including the
            ## boundary elements) to insert.
            new_elems = [IntElem(random.randint(elems[1].key, elems[-2].key))
                         for i in range(0, self.size/10)]
            new_elems = map(IntElem,
                            self.generate_elems(
                                elems[1].key, elems[-2].key, self.size/10))
            min_ne = min(new_elems)
            max_ne = max(new_elems)

            vo = SkipListVO.range_query(sl, min_ne, max_ne, HashCoin())

            try:
                ret_elems = vo.verify(min_ne, max_ne, sl.root.label)
            except VerificationObjectException as e:
                self.assertTrue(False, 'Error: %s' %e.msg)

            self.assertEqual(ret_elems, [x for x in elems
                                         if min_ne <= x <= max_ne])

            self.assertEqual(vo.root.label, sl.root.label)

            with HashSocketSLClient.new(
                    elems, IntElem(elems[0].key-1), IntElem(elems[-1].key+1),
                    IntElem, self.host, self.port) as client:
                lower = random.choice(elems[1:self.size/3])
                upper = random.choice(elems[2*self.size/3:-1])

                self.assertEqual(SkipListVO.range_query(sl, lower, upper),
                                 client.range_query(lower, upper))

                self.assertEqual(SkipListVO.range_query(sl, min_ne, max_ne),
                                 client.range_query(min_ne, max_ne))

                for elem in new_elems:
                    vo.insert(elem)
                for elem in new_elems:
                    sl.insert(elem)

                self.assertEqual(sl.root.label, vo.root.label)

                try:
                    new_root = client.batch_insert(old_root, new_elems,
                        min_ne, max_ne)
                except VerificationObjectException as e:
                    self.assertTrue(False, 'Error: %s' %e.msg)

                self.assertEqual(new_root, vo.root.label)

                self.assertEqual(sl.root.label, new_root)
                self.assertEqual(len(sl.to_list_of_lists()[-1])-2,
                                 self.size + (self.size/10))

                for elem in new_elems:
                    proof = client.query(elem)
                    self.assertEqual(proof, sl.contains(elem))
                    self.assertEqual(AuthSkipList.verify(proof[1]), sl.root.label)
