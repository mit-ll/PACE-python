## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Inner nodes in MHTs
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Jul 2014  ZS    Original file
## **************

import bisect

from pace.ads.merkle.mht_utils import MHTUtils
from pace.ads.merkle.eq import EqMixin

class MHTNode(object):
    """ Class for nodes in a (binary) Merkle hash tree.
        Instance variables:

        hval - the hash value at this node. always exists.
        left, right - the left and right children of this node.
                      If they are both None, this is a leaf.
                      They are always either both filled in or both None.
        elem - If this is a leaf (i.e. if left & right are None), this
               will point to the element the leaf corresponds to. Otherwise,
               this is None.
        parent - the parent of this node. if None, this is the root.
    """
    def __init__(self, hval, left=None, right=None, elem=None):
        self.hval = hval
        self.left = left
        self.right = right
        self.parent = None
        self.elem = elem

    def __eq__(self, n2):
        """ NB: Equality ignores hash functions and only makes sure they
                both either have parents or don't
        """
        
        if (self.hval == n2.hval
                and self.left == n2.left
                and self.right == n2.right
                and self.elem == n2.elem
                and ((self.parent and n2.parent) or
                    ((not self.parent) and (not n2.parent)))):
                return True
        else:
            return False

    @classmethod
    def leaf(cls, elem, hval=None):
        """ Helper function for creating a leaf MHTNode
            Arguments:
            elem - the element this leaf points to
            hval (optional) - the hash value of elem, if it's already been
                              computed.
        """
        if hval:
            h = hval
        else:
            h = MHTUtils.hash(elem)

        return cls(h, elem=elem)

    @classmethod
    def node(cls, hval, left, right):
        """ A helper function for defining non-leaf MHTNodes
            Arguments:
            hval - the hash value of this node
            left - the left subtree
            right - the right subtree
        """
        node = cls(hval, left, right)
        
        if isinstance(left, cls):
            left.parent = node
        if isinstance(right, cls):
            right.parent = node

        return node       

    @classmethod
    def insert(cls, new_leaf, sibling_leaf):
        old_parent = sibling_leaf.parent

        new_node = cls.node(
            MHTUtils.merge_hashes(sibling_leaf.hval, new_leaf.hval),
            sibling_leaf,
            new_leaf)
        new_node.parent = old_parent

        if new_node.parent is None:
            return False

        if new_node.parent.left is sibling_leaf:
            new_node.parent.left = new_node
        elif new_node.parent.right is sibling_leaf:
            new_node.parent.right = new_node

        
        MHTNode.update_parents(new_node.parent)
        return True

    @staticmethod
    def update_parents(node):
        current_node = node

        while current_node:
            current_node.hval = MHTUtils.merge_hashes(current_node.left.hval,
                                                      current_node.right.hval)
            current_node = current_node.parent


    @staticmethod
    def find_boundary(elems, left_bound, right_bound):
        """ Arguments:
            elems - list of elements to find the left boundary of
            left_bound - the least (according to <=) element that should
                         be included in the result set.
            right_bound - the greatest (according to <=) element that should
                          be included in the result set.

            Returns:
            left_boundary - the rightmost element in elems that is less than
                            left_bound
            left_index - the index of the least element in elems that
                         is >= left_bound
            right_index - the index of the greatest element in elems that
                          is >= left_bound
            right_boundary - the leftmost element in elems that is greater than
                             right_bound

        """

        left_i = bisect.bisect_left(elems, left_bound)
        right_i = bisect.bisect_right(elems, right_bound)
        return elems[left_i-1], left_i, right_i-1, elems[right_i]

    def valid(self):
        if self.left and self.right:
            if self.elem:
                raise InvalidMerkleTree('Only leaves may point to elements')

            if ((self.left.parent is not self) or
                (self.right.parent is not self)):
                raise InvalidMerkleTree(
                    'A node must be the parent of its children.')

            if not self.hval:
                raise InvalidMerkleTree(
                    'Each node must have a hash value')

            # Children must be valid
            self.left.valid()
            self.right.valid()

            # Your hash value must be the merge of your childrens' hash values
            if (self.hval !=
                    MHTUtils.merge_hashes(self.left.hval, self.right.hval)):
                raise InvalidMerkleTree(
                    "Each node's hash value must be the merge of its children's\
                    hash values.")
        elif self.left or self.right:
            # Children are all-or-nothing
            raise InvalidMerkleTree('Each node must have zero or two children')
        else:
            if self.elem is None:
                raise InvalidMerkleTree('Leaves must point to their elements.')

            if (MHTUtils.hash(self.elem) !=
                    self.hval):
                raise InvalidMerkleTree('Incorrect hash value stored at leaf')

            if self.parent:
                if not ((self.parent.left is self) or (self.parent.right is self)):
                    raise InvalidMerkleTree("You must be one of your parents' children")

    @staticmethod
    def least_common_ancestor(left, right):
        current, current_history = left.parent, [left]
        other, other_history = right, [right]

        while current.parent or other.parent:
            if current in other_history:
                return current

            current_history.append(current)

            if other.parent is None:
                current = current.parent
            else:
                tmp = current
                current = other.parent
                other = tmp

                tmp = other_history
                other_history = current_history
                current_history = tmp

        if current in other_history:
            return current

        return None

    def _root_of(self):
        """ Not particularly useful; just in place for debugging.
        """

        current = self
        while current.parent:
            current = current.parent
        return current

    def subtree_elems(self):
        """ Return all the elements in this subtree, in order.
        """

        if self.elem is not None:
            return [self.elem]
        else:
            return self.left.subtree_elems() + self.right.subtree_elems()
            

class InvalidMerkleTree(Exception):
    def __init__(self, msg):
        self.msg = msg
