## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Verification objects for MHTs
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Jul 2014  ZS    Original file
## **************

from base64 import b64encode, b64decode
import bisect

from pace.ads.merkle.eq import EqMixin
from pace.ads.merkle.vo_node import VONode
from pace.ads.merkle.hash_node import HashNode
from pace.ads.merkle.mht_utils import MHTUtils

class VO(EqMixin):
    """ Verification objects for MHTs. Structure is similar to a MHT,
        but may contain hashes to replace subtrees that are not necessary
        for the current verification.
    """

    def serialize(self):
        """ Create a string out of a VO
            
            NB: assumes the hash function used is standard to avoid
            having to serialize the hash class.
        """
        return '%s<=>%s<=>%s' %(str(self.left), str(self.right),
                                     self.root.serialize())

    @staticmethod
    def deserialize(s):
        sleft, sright, sroot = s.split('<=>')
        left, right = int(sleft), int(sright)

        root, leaves = VONode.deserialize(sroot)

        return VO(left, right, root, leaves)

    def __init__(self, left, right, root, leaves):
        """ Defines a verification object for a query on mht that
            returns elements elems, with left and right boundaries
            as given.
        """
        self.left = left
        self.right = right
        self.root = root
        self.leaves = leaves

    @staticmethod
    def new(left, elems, right, mht_root):
        """ Defines a verification object for a query on mht that
            returns elements elems, with left and right boundaries
            as given.
        """
        all_elems = [left] + elems + [right]
        root, leaves = VO.build_node(mht_root, all_elems)

        return VO(left, right, root, leaves)

    @staticmethod
    def build_node(mht_node, elems):
        if mht_node.left and mht_node.right:
            left, l_leaves = VO.build_node(mht_node.left, elems)
            right, r_leaves = VO.build_node(mht_node.right, elems)

            # Check if we can collapse this to just a hash value
            if not (isinstance(left, VONode) or isinstance(right, VONode)):
                return HashNode(mht_node.hval), []

            new_node = VONode.node(mht_node.hval, left, right)
            
            return new_node, l_leaves + r_leaves

        else:
            # It's a leaf, so see if it's in the set or not
            if mht_node.elem in elems:
                new_node = VONode.leaf(mht_node.elem, mht_node.hval)
                return new_node, [new_node]
            else:
                return HashNode(mht_node.hval), []
    
    def verify_insertion(self, old_root_hval, left, right, elem):
        """ Verify that 'self' is a proof that 'elem' was correctly inserted
            into an MHT between 'left' and 'right', whose old root value was
            old_root_hval.

            Arguments:
            old_root_hval - the root hash of the MHT before the insertion
            left, right - the elements on the left & right sides of the element
                          post-insertion
            elem - the element that was inserter

            Returns:
            root_hval - the new root hash value of the MHT after the insertion
        """

        # MHT.insert() needs to return a VO for the empty range between left &
        # right and the new root value; that way, we can check the VO to make
        # sure it's consistent with what we expect, then insert it into the VO
        # to make sure we get back the correct hash value.
        #
        # There might even be a way to do both of these at the same time? But
        # we should leave optimizations like that for later.
        self.verify(left, right, old_root_hval)

        return self.insert(elem)

    def insert(self, elem):
        """ Insert an element into a VO, returning the new root hash value.
        """

        if elem <= self.left or elem >= self.right:
            raise VerificationObjectException(
                "Element given for insertion is not within the given range.")

        just_elems = [leaf.elem for leaf in self.leaves]

        i = bisect.bisect_left(just_elems, elem)

        new_leaf = VONode.leaf(elem)
        sibling_leaf = self.leaves[i-1]

        x = VONode.insert(new_leaf, sibling_leaf)

        self.leaves = self.leaves[:i] + [new_leaf] + self.leaves[i:]

        return (x, self.root.hval)


    def verify(self, left, right, root_hval):
        """ Verify that 'self' (the verification object) does in fact
            verify the range given. It's sent by the (untrusted) server,
            so we must verify everything.
        """
        leaves = self.leaves

        if len(leaves) < 2:
            raise VerificationObjectException(
                'Leaves length must be at least 2 (actual: %d)' %len(leaves))

        left_leaf = leaves[0]
        right_leaf = leaves[-1]
        leaves = leaves[1:-1]

        ## Check boundary conditions---minimum possible check on
        ## whether the results are valid
        if left_leaf.elem >= left or right_leaf.elem <= right:
            raise VerificationObjectException(
                'Left and right boundary objects must be outside of range:\n\
                Range: %s to %s\n\
                Left object: %s, Right object: %s' %(str(left),
                                                     str(right),
                                                     str(left_leaf.elem),
                                                     str(right_leaf.elem)))
        if not all(left <= leaf.elem <= right for leaf in leaves):
            raise VerificationObjectException(
                'All leaves must be within the left & right bounds')
        if not all(leaves[i].elem <= leaves[i+1].elem
                   for i in range(0, len(leaves)-1)):
            raise VerificationObjectException(
                'Leaves must be sorted')

        ## Make sure everything hashes together correctly

        if self.root.hval != root_hval:
            raise VerificationObjectException(
                'Root hash value does not match published value')

        VO.verify_node(self.root, self.leaves, len(self.leaves))

    @staticmethod
    def verify_node(node, leaves, num_leaves):
        if not isinstance(node, VONode):
            # If leaves is neither empty nor full, there's a gap in the
            # result set that means the server attempted to omit an element
            if leaves and num_leaves != len(leaves):
                raise VerificationObjectException(
                    'Incomplete VO detected---elements omitted in result set.')

            return leaves

        # need the extra check for non-none False objects
        if node.elem is not None:
            ## It's a leaf
            if node.hval != MHTUtils.hash(node.elem):
                raise VerificationObjectException(
                    'Node hval must match element hval')
            
            if node.elem != leaves[0].elem:
                raise VerificationObjectException(
                    'Node element must be the first of the remaining leaves')

            return leaves[1:]
                
        elif not (VO.child_node_class(node.left) and
                  VO.child_node_class(node.right)):
            raise VerificationObjectException(
                'Nodes must have exactly zero or one children.')
        else:
            ## It's an internal node
            left_hval = node.left.hval
            right_hval = node.right.hval

            if not (MHTUtils.merge_hashes(left_hval, right_hval) ==
                    node.hval):
                raise VerificationObjectException(
                    "Node hash value does not match its childrens' hvals")
            
            remaining_leaves = VO.verify_node(node.left, leaves, num_leaves)
            return VO.verify_node(node.right, remaining_leaves, num_leaves)

    @staticmethod
    def child_node_class(maybenode):
        return isinstance(maybenode, VONode) or isinstance(maybenode, HashNode)

class VerificationObjectException(Exception):
    def __init__(self, msg):
        self.msg = msg
