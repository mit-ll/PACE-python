## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Tests for skiplist element classes
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  04 Oct 2014  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from unittest import TestCase

import time
import random

from pace.ads.skiplist.elemclass import IntElem, StrElem, AccumuloKey, AccumuloEntry
from pace.common.pacetest import PACETestCase

def _fix_tup_sign(tup):
    a, b, c, d, e = tup
    return (a, b, c, d, -e)

class ElemClassTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

    def test_ord(self):
        for i in range(self.num_iters):

            epairs = [(random.randint(-100000, 100000),
                      random.randint(-100000, 100000))
                      for _ in range(self.size)]
            epairs.append((0,0))
            epairs.append((10000,10000))
            epairs.append((-10000,-10000))

            for x, y in epairs:
                self.assertEqual(x < y, IntElem(x) < IntElem(y))
                self.assertEqual(str(x) < str(y),
                                 StrElem(str(x)) < StrElem(str(y)))

                self.assertEqual(x > y, IntElem(x) > IntElem(y))
                self.assertEqual(str(x) > str(y),
                                 StrElem(str(x)) > StrElem(str(y)))

                self.assertEqual(x >= y, IntElem(x) >= IntElem(y))
                self.assertEqual(str(x) >= str(y),
                                 StrElem(str(x)) >= StrElem(str(y)))

                self.assertEqual(x <= y, IntElem(x) <= IntElem(y))
                self.assertEqual(str(x) <= str(y),
                                 StrElem(str(x)) <= StrElem(str(y)))

                self.assertEqual(x == y, IntElem(x) == IntElem(y))
                self.assertEqual(str(x) == str(y),
                                 StrElem(str(x)) == StrElem(str(y)))

                self.assertEqual(x != y, IntElem(x) != IntElem(y))
                self.assertEqual(str(x) != str(y),
                                 StrElem(str(x)) != StrElem(str(y)))

    def test_serialize(self):
        for i in range(self.num_iters):

            elems = [random.randint(-100000, 100000)
                     for _ in range(self.size)]

            for elem in elems:
                ie = IntElem(elem)
                se = StrElem(str(elem))

                self.assertEqual(ie, IntElem.deserialize(ie.serialize()))
                self.assertEqual(se, StrElem.deserialize(se.serialize()))

                self.assertEqual(ie.serialize(),
                                 IntElem.deserialize(
                                    ie.serialize()).serialize())
                self.assertEqual(se.serialize(),
                    StrElem.deserialize(se.serialize()).serialize())

    def test_accumulo_serialize(self):
        for i in range(self.num_iters):
            for row, cf, cq, cv, ts, val in [[str(random.randint(-10000, 10000))
                                              for i in range(6)]
                                             for _ in range(self.size)]:
                key = AccumuloKey(row, cf, cq, cv, ts)
                entry = AccumuloEntry(key, val)

                self.assertEqual(entry, AccumuloEntry.deserialize(entry.serialize()))
                self.assertEqual(entry.val,
                                 AccumuloEntry.deserialize(
                                    entry.serialize()).val)

                self.assertEqual(entry.serialize(),
                                 AccumuloEntry.deserialize(
                                    entry.serialize()).serialize())

    def test_accumulo_ord(self):
        for i in range(self.num_iters):
            for tup1, tup2 in [([random.randint(-10000, 10000) * (-1 if i == 4 else 0)
                                 for i in range(5)],
                                [random.randint(-10000, 10000) * (-1 if i == 4 else 0)
                                 for i in range(5)])
                               for _ in range(self.size)]:

                tup1 = tuple(tup1)
                tup2 = tuple(tup2)
                tk1 = _fix_tup_sign(tup1)
                tk2 = _fix_tup_sign(tup2)
                print 'tup1:', tup1
                print 'tup2:', tup2
                self.assertEqual(tup1 < tup2,
                                 AccumuloKey(*tk1) < AccumuloKey(*tk2))
                self.assertEqual(tup1 <= tup2,
                                 AccumuloKey(*tk1) <= AccumuloKey(*tk2))
                self.assertEqual(tup1 >= tup2,
                                 AccumuloKey(*tk1) >= AccumuloKey(*tk2))
                self.assertEqual(tup1 > tup2,
                                 AccumuloKey(*tk1) > AccumuloKey(*tk2))
                self.assertEqual(tup1 == tup2,
                                 AccumuloKey(*tk1) == AccumuloKey(*tk2))
                self.assertEqual(tup1 != tup2,
                                 AccumuloKey(*tk1) != AccumuloKey(*tk2))

            for tup1, tup2 in [([random.randint(-10000, 10000) * (0 if i < 1 else 1)
                                 for i in range(5)],
                                [random.randint(-10000, 10000) * (0 if i < 1 else 1)
                                 for i in range(5)])
                               for _ in range(self.size)]:

                tup1 = tuple(tup1)
                tup2 = tuple(tup2)
                tk1 = _fix_tup_sign(tup1)
                tk2 = _fix_tup_sign(tup2)
                self.assertEqual(tup1 < tup2,
                                 AccumuloKey(*tk1) < AccumuloKey(*tk2))
                self.assertEqual(tup1 <= tup2,
                                 AccumuloKey(*tk1) <= AccumuloKey(*tk2))
                self.assertEqual(tup1 >= tup2,
                                 AccumuloKey(*tk1) >= AccumuloKey(*tk2))
                self.assertEqual(tup1 > tup2,
                                 AccumuloKey(*tk1) > AccumuloKey(*tk2))
                self.assertEqual(tup1 == tup2,
                                 AccumuloKey(*tk1) == AccumuloKey(*tk2))
                self.assertEqual(tup1 != tup2,
                                 AccumuloKey(*tk1) != AccumuloKey(*tk2))

            for tup1, tup2 in [([random.randint(-10000, 10000) * (0 if i < 2 else 1)
                                 for i in range(5)],
                                [random.randint(-10000, 10000) * (0 if i < 2 else 1)
                                 for i in range(5)])
                               for _ in range(self.size)]:

                tup1 = tuple(tup1)
                tup2 = tuple(tup2)
                tk1 = _fix_tup_sign(tup1)
                tk2 = _fix_tup_sign(tup2)
                self.assertEqual(tup1 < tup2,
                                 AccumuloKey(*tk1) < AccumuloKey(*tk2))
                self.assertEqual(tup1 <= tup2,
                                 AccumuloKey(*tk1) <= AccumuloKey(*tk2))
                self.assertEqual(tup1 >= tup2,
                                 AccumuloKey(*tk1) >= AccumuloKey(*tk2))
                self.assertEqual(tup1 > tup2,
                                 AccumuloKey(*tk1) > AccumuloKey(*tk2))
                self.assertEqual(tup1 == tup2,
                                 AccumuloKey(*tk1) == AccumuloKey(*tk2))
                self.assertEqual(tup1 != tup2,
                                 AccumuloKey(*tk1) != AccumuloKey(*tk2))

            for tup1, tup2 in [([random.randint(-10000, 10000) * (0 if i < 3 else 1)
                                 for i in range(5)],
                                [random.randint(-10000, 10000) * (0 if i < 3 else 1)
                                 for i in range(5)])
                               for _ in range(self.size)]:

                tup1 = tuple(tup1)
                tup2 = tuple(tup2)
                tk1 = _fix_tup_sign(tup1)
                tk2 = _fix_tup_sign(tup2)
                self.assertEqual(tup1 < tup2,
                                 AccumuloKey(*tk1) < AccumuloKey(*tk2))
                self.assertEqual(tup1 <= tup2,
                                 AccumuloKey(*tk1) <= AccumuloKey(*tk2))
                self.assertEqual(tup1 >= tup2,
                                 AccumuloKey(*tk1) >= AccumuloKey(*tk2))
                self.assertEqual(tup1 > tup2,
                                 AccumuloKey(*tk1) > AccumuloKey(*tk2))
                self.assertEqual(tup1 == tup2,
                                 AccumuloKey(*tk1) == AccumuloKey(*tk2))
                self.assertEqual(tup1 != tup2,
                                 AccumuloKey(*tk1) != AccumuloKey(*tk2))

            for tup1, tup2 in [([random.randint(-10000, 10000) * (0 if i < 4 else 1)
                                 for i in range(5)],
                                [random.randint(-10000, 10000) * (0 if i < 4 else 1)
                                 for i in range(5)])
                               for _ in range(self.size)]:

                tup1 = tuple(tup1)
                tup2 = tuple(tup2)
                tk1 = _fix_tup_sign(tup1)
                tk2 = _fix_tup_sign(tup2)
                print 'tup1:', tup1
                print 'tup2:', tup2
                self.assertEqual(tup1 < tup2,
                                 AccumuloKey(*tk1) < AccumuloKey(*tk2))
                self.assertEqual(tup1 <= tup2,
                                 AccumuloKey(*tk1) <= AccumuloKey(*tk2))
                self.assertEqual(tup1 >= tup2,
                                 AccumuloKey(*tk1) >= AccumuloKey(*tk2))
                self.assertEqual(tup1 > tup2,
                                 AccumuloKey(*tk1) > AccumuloKey(*tk2))
                self.assertEqual(tup1 == tup2,
                                 AccumuloKey(*tk1) == AccumuloKey(*tk2))
                self.assertEqual(tup1 != tup2,
                                 AccumuloKey(*tk1) != AccumuloKey(*tk2))
