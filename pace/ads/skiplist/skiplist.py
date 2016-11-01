## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Skip list library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  19 Aug 2014  ZS    Original file
## **************

import random
from hashlib import sha256

from pace.ads.skiplist.skiplistnode import SkipListNode, InvalidSkipListException
from pace.ads.skiplist.coin import BaseCoin

class SkipList(object):

    # the class to be used for nodes
    nodeclass = SkipListNode

    def __init__(self, root, lbound, rbound, coin):
        self.root = root
        self.lbound = lbound
        self.rbound = rbound
        self.coin = coin

    @classmethod
    def new(cls, elems, lbound, rbound, coin=BaseCoin()):
        """ Build a new SkipList
            
            Arguments:
            elems - the list of elements to put into the SkipList
            lbound - the leftmost element in the SkipList (acts like -infty)
            rbound - the rightmost element in the Skiplist (acts like +infty)
        """

        sl = cls(None, lbound, rbound, coin)
        right = cls.nodeclass.newnode(sl, None, None, rbound, True)
        left = cls.nodeclass.newnode(sl, None, right, lbound, True)
        sl.root = left

        for elem in elems:
            sl.insert(elem)

        return sl

    def insert(self, elem):
        """ Insert elem into the base level of the current SkipList, then
            determine how many levels to elevate it by
        """
        new_node, left_neighbor, visited = self.root.insert(elem)

        current = new_node
        current_hash_value = sha256(str(elem)).digest()

        for v, flag in visited:
            if not flag:
                continue

            if self.stop(current_hash_value):
                return

            current_hash_value = sha256(current_hash_value).digest()
            
            next_level = self.nodeclass.newnode(self, current, v.right, elem)
            v.right = next_level
            current = next_level

        # If we got here, we need to add another level of just -infty, +infty

        new_rght = self.nodeclass.newnode(self, self.root.right.right, None, self.rbound)
        new_root = self.nodeclass.newnode(self, self.root, new_rght, self.lbound)
        self.root = new_root

        while not self.stop(current_hash_value):
            current_hash_value = sha256(current_hash_value).digest()

            # Add higher levels
            old_right = self.root.right
            old_left = self.root

            new_right = self.nodeclass.newnode(self, old_right, None, old_right.elem)
            new_left = self.nodeclass.newnode(self, old_left, new_right, old_left.elem)

            new_level = self.nodeclass.newnode(self, current, old_right, elem)
            old_left.right = new_level
            self.root = new_left

            current = new_level

    def contains(self, elem):
        """ Returns True if elem is in the skip list, and False otherwise
        """

        visited, last = self.root.search(elem)

        return last.elem == elem

    def stop(self, elem):
        """ The 'coin flip' for a randomized SkipList to determine how
            high to elevate each element once it's inserted
        """
        return self.coin.flip(elem)

    def to_list_of_lists(self):
        """ Returns the list containing each level in the skiplist, from top
            to bottom.

            The first element of the result will just contain the left and
            right bounds ("-infty" and "+infty"), and the last element will
            contain those bounds with every element of the list between them.
        """
        current = self.root
        lists = []

        while current:
            row = current
            rlist = []

            while row:
                rlist.append(row.elem)
                row = row.right

            lists.append(rlist)
            current = current.down

        return lists

    def valid(self):
        ## Guarantee that the top level has exactly two elements
        if self.root is None:
            raise InvalidSkipListException(
                'Top level must have exactly two elements (found: zero)')
        if self.root.right is None:
            raise InvalidSkipListException(
                'Top level must have exactly two elements (found: one)')
        if self.root.right.right is not None:
            raise InvalidSkipListException(
                'Top level must have exactly two elements (found: more than 2)')

        ## Guarantee each level has strictly fewer elements than the one after
        prev_elems = 2
        current_left = self.root.down

        while current_left:
            current = current_left
            current_elems = 0
            while current:
                current_elems = current_elems + 1
                current = current.right

            if not (current_elems >= prev_elems):
                raise InvalidSkipListException(
                    'Each level must have at least as many nodes as the previous level')

            prev_elems = current_elems
            current_left = current_left.down

        ## Guarantee various per-node correctness properties
        self.root.valid()
