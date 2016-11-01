## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Authenticated skip list nodes
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  21 Aug 2014  ZS    Original file
## **************

# This is the python library implementation of SHA256, which is faster than
# the PyCrypto version in PyCrypto.Hash.SHA256
from hashlib import sha256

from pace.ads.skiplist.skiplist import SkipList
from pace.ads.skiplist.skiplistnode import SkipListNode

class AuthNode(SkipListNode):

    @staticmethod
    def _hash(x):
        return sha256(x).digest()

    @staticmethod
    def chash(x, y):
        """ A commutative hash function, defined in terms of the local _hash
            function (in this case, sha256). Hashes the concatenation of the
            minimum of its two arguments with the maximum of its two arguments.
        """
        return sha256(min(x, y) + max(x, y)).digest()

    @classmethod
    def newnode(cls, sl, down, right, elem, assign_label=False, *args, **kwargs):
        """ Create a new node. Can be overridden by subclasses.

            Arguments:
            sl - the skiplist this node is a part of.
            down - the bottom neighbor of the new node
            right - the right neighbor of the new node
            elem - the element to be stored in the new node.
            assign_label - whether to assign a hash label to this node
                           upon creation (alternative is to defer it to
                           be called manually by whoever is using this
                           code). Default: False (do not assign a label
                           yet)
            *args, **kwargs - any more arguments that a subclass
                              might want to use

            Returns:
            A new SkipListNode with fields as given.
        """
        new_node = cls(sl, down, right, elem)
        new_node.tower = False

        if assign_label:
            new_node.assign_label()

        if down:
            down.tower = True

        return new_node

    def assign_label(self):
        node = self

        if node.right is None:
            node.label = str(0)
            return

        if node.down is None:
            if node.right.tower:
                node.label = AuthNode.chash(
                                AuthNode._hash(node.elem.serialize()),
                                AuthNode._hash(node.right.elem.serialize()))
            else:
                node.label = AuthNode.chash(
                                AuthNode._hash(node.elem.serialize()),
                                node.right.label)
        else:
            if node.right.tower:
                node.label = node.down.label
            else:
                node.label = AuthNode.chash(node.down.label, node.right.label)
