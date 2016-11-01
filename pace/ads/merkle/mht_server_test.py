## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for MHT servers
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Jul 2014  ZS    Original file
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

from pace.ads.merkle.mht import MHT
from pace.ads.merkle.mht_utils import MHTUtils
from pace.ads.merkle.mht_server import SocketMHTServer, MHTHandler, SocketMHTClient
from pace.common.pacetest import PACETestCase

class MHTServerTest(PACETestCase):

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
                self.server = SocketMHTServer((self.host, self.port),
                                              MHTHandler)
                break
            except socket.error:
                self.port = random.randint(9000, 9999)

        self.thread = Thread(group=None, target=MHTServerTest.run_server,
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

    def test_remote_query(self):
        print 'single element query'
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 1000000000)
                     for i in range(0, self.size)]
            elems.sort()
            mht = MHT.new(elems)

            with SocketMHTClient.new(elems, self.host, self.port) as client:
                for j in range(0, self.num_iters):
                    elem = random.choice(elems)
                    good_result = mht.contains(elem)
                    test_result = client.query(elem)
                    self.assertEqual(good_result, test_result,
                        'Unequal proofs returned')

    def test_remote_range_query(self):
        print 'range query'
        total_time = 0
        for i in range(0, self.num_iters):
            elems = [random.randint(0, 1000000000)
                     for i in range(0, self.size)]
            elems.sort()
            mht = MHT.new(elems)
            start = time.time()
            with SocketMHTClient.new(elems, self.host, self.port) as client:
                ## Get valid lower & upper bounds with enough room between
                ## them (about a third of the list) for a substantial range
                ## query
                lower = random.choice(elems[1:self.size/3])
                upper = random.choice(elems[2*self.size/3:-1])

                self.assertEqual(mht.range_query(lower, upper),
                                 client.range_query(lower, upper))
            end = time.time()
            total_time = total_time + (end - start)

        print 'Average time taken: %s' %str(total_time / self.num_iters)

    def test_remote_batch_insert(self):
        print 'batch insert'
        total_time = 0
        other_time = 0
        complete_time = 0
        loop_time = 0
        init_time = time.time()
        for i in range(0, self.num_iters):
            loop_start = time.time()
            start = time.time()
            elems = [random.randint(0, 100000000) for i in range(0, self.size)]
            elems.sort()
            mht = MHT.new(elems)
            old_root = mht.root.hval

            self.assertEqual(len(mht.sorted_elems), self.size)

            ## Generate a small number (in this case, n/10) of random elements
            ## between the minimum and maximum elements (not including the
            ## boundary elements) to insert.
            new_elems = [random.randint(elems[1], elems[-2])
                         for i in range(0, self.size/10)]
            min_ne = min(new_elems)
            max_ne = max(new_elems)

            vo = mht.range_query(min_ne, max_ne)

            for elem in new_elems:
                vo.insert(elem)

            mht.batch_insert(new_elems)
            end = time.time()

            start = time.time()
            with SocketMHTClient.new(elems, self.host, self.port) as client:
                end = time.time()
                start = time.time()
                new_root = client.batch_insert(old_root, new_elems,
                    min_ne, max_ne)
                client.ping()
                end = time.time()
                total_time = total_time + (end - start)

                start = time.time()
                self.assertEqual(new_root, vo.root.hval)

                self.assertEqual(mht.root.hval, new_root)
                self.assertEqual(len(mht.sorted_elems),
                                 self.size + (self.size/10))

                for elem in new_elems:
                    proof = client.query(elem)
                    self.assertEqual(proof, mht.contains(elem))
                    self.assertTrue(MHTUtils.verify(new_root, elem, proof),
                                    'Returned proof does not verify that \
                                     inserted element is in the tree')
            end = time.time()
            other_time = other_time + (end - start)
            loop_end = time.time()
            loop_time = loop_time + (loop_end - loop_start)
        end_time = time.time()

        print 'Total batch insert time: %s' %str(end_time - init_time)

        print 'Time for batch inserts: %s' %str(total_time)
        print 'And time to do test queries: %s' %str(other_time)
        print 'Time in loop: %s' %str(loop_time)
        print 'Time accounted for: %s' %str(total_time + other_time)
