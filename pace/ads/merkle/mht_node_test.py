## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Unit tests for MHT nodes
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

from pace.ads.merkle.mht_node import MHTNode
from pace.ads.merkle.mht import MHT
from pace.common.pacetest import PACETestCase


class MerkleTests(PACETestCase):

    def setUp(self):
        random.seed(int(time.time()))

    def test_leaf(self):
        for i in range(0, self.num_iters):
            elem = random.randint(0, 1000000)
            l = MHTNode.leaf(elem)

            self.assertEqual(l.elem, elem,
                'leaf element is not what was expected')
            self.assertEqual(l.parent, None, 'new nodes should have no parent')
            self.assertEqual(l.left, None, 'leaves have no left child')
            self.assertEqual(l.right, None, 'leaves have no right child')

            hval = sha256(bytes(elem)).digest()
            l2 = MHTNode.leaf(elem, hval=hval)

            self.assertEqual(l.hval, hval,
                'Wrong hval being written to leaf')
    
    def test_node(self):
        lchild = MHTNode.leaf(5)
        rchild = MHTNode.leaf(6)

        for i in range(0, self.num_iters):
            elem = random.randint(0, 1000000)
            hval = sha256(bytes(elem)).digest()

            n = MHTNode.node(hval, lchild, rchild)

            self.assertEqual(n.hval, hval,
                'Wrong hval written to node')
            self.assertEqual(n.left, lchild, 'Wrong left child in node')
            self.assertEqual(n.right, rchild, 'Wrong right child in node')
            self.assertEqual(n.elem, None, 'Nodes should contain no element')

    def test_find_boundary(self):
        elems = [0, 2, 4, 6, 8, 10, 12, 14, 16]

        lower, li, ri, upper = MHTNode.find_boundary(elems, 5, 11)

        self.assertEqual(lower, 4, 'Invalid lower boundary returned')
        self.assertEqual(elems[li], 6,
            'Invalid first element of range returned')
        self.assertEqual(upper, 12,
            'Invalid upper boundary returned: %d' %upper)
        self.assertEqual(elems[ri], 10,
            'Invalid first element of range returned')

        lower, li, ri, upper = MHTNode.find_boundary(elems, 6, 10)

        self.assertEqual(lower, 4, 'Invalid lower boundary returned')
        self.assertEqual(elems[li], 6,
            'Invalid first element of range returned')
        self.assertEqual(upper, 12, 'Invalid upper boundary returned')
        self.assertEqual(elems[ri], 10,
            'Invalid first element of range returned')

    def test_lca(self):
        elems = [random.randint(0, 100000000) for i in range(0, self.size)]
        elems.sort()
        mht = MHT.new(elems)

        for i in range(0, self.num_iters):
            leaf1 = mht.elems[random.choice(mht.sorted_elems)]
            leaf2 = mht.elems[random.choice(mht.sorted_elems)]

            while leaf2 is leaf1:
                leaf2 = mht.elems[random.choice(mht.sorted_elems)]

            lca = MHTNode.least_common_ancestor(leaf1, leaf2)

            current = leaf1
            parents1 = []

            while current is not lca:
                self.assertTrue(current)
                parents1.append(current)
                current = current.parent
            
            current = leaf2

            while current is not lca:
                self.assertTrue(current)
                self.assertTrue(current not in parents1)
                current = current.parent



