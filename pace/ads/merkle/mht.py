## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Merkle hash tree library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  17 Jul 2014  ZS    Original file
## **************

import bisect

from pace.ads.merkle.mht_utils import MHTUtils
from pace.ads.merkle.mht_node import MHTNode
from pace.ads.merkle.vo import VO

class MHTInsertionException(Exception):
    def __init__(self, msg):
        self.msg = msg

class MHT(object):
    """ Binary Merkle hash tree class. Provides a verified data structure
        that can prove that an element is (or isn't) contained within it.

        Instance variables:
        elems - a dict of elements mapped to their corresponding leaf node
                in the hash tree
        sorted_elems - the original (sorted) list of elements
        root - the top level node of the hash tree, whoseh hash value depends
               on all of the elements.
    """
    
    def __init__(self, elems, sorted_elems, root):
        self.elems = elems
        self.sorted_elems = sorted_elems
        self.root = root

    @staticmethod
    def new(elems):
        """ Assumes elems is sorted, nonempty, and contains no
            repeated elements.
        """
        sorted_elems = elems

        work = [MHTNode.leaf(elem) for elem in elems]
        elem_dict = dict(zip(elems, work))

        next_level = []

        # I am going out of my way not to implement this recursively,
        # because python
        while work:
            for i in range(0, len(work), 2):

                if i+1 >= len(work):
                    next_level.append(work[i])
                else:
                    left = work[i]
                    right = work[i+1]

                    new_hash = MHTUtils.merge_hashes(left.hval, right.hval)
                    new_node = MHTNode.node(new_hash, left, right)

                    left.parent = new_node
                    right.parent = new_node

                    next_level.append(new_node)

            if len(next_level) == 1:
                return MHT(elems=elem_dict, sorted_elems=elems,
                           root=next_level[0])

            work = next_level
            next_level = []

    @staticmethod
    def partial_insert(sorted_elems, elem):
        """ Insert an element into a list of leaves. Helper function for
            both insert() and batch_insert()
            Arguments:
            sorted_elems - a sorted list of elements in the MHT
            elem - the element to insert into leaves

            Returns:
            new_leaves - a list of leaves in an MHT that contains elem
                         inserted into the correct location
            i - the index into which elem was inserted.
        """
        i = bisect.bisect_left(sorted_elems, elem)
        return (sorted_elems[:i] + [elem] + sorted_elems[i:], i)

    def insert(self, elem):
        """ Insertion of a single element into a Merkle hash tree.
            NB: this function does *not* guarantee anything about the
            balancedness of the resulting tree.

            Arguments:
            self - the MHT to be modified
            elem - the element to be inserted

            Returns:
            vo - a verification object that proves that the range into which
                 elem was inserted was in fact empty before insertion

            Assumes:
            - There are at least two 'boundary' elements in the MHT
            - One boundary element is less than everything else that will
              be inserted (including elem), and the other is greater than
              everything else (including elem).
        """

        ## Insertion algorithm:
        ## 1) Find where the element belongs in the leaf list.
        ## 2) Choose a neighbor to pair it with, and make a new node
        ##    that is the parent of those two leaves.
        ## 3) Replace that leaf's spot in the old tree with that node.
        ## 4) Move up the tree and recompute the hash values at each
        ##    node, constructing a VO on the way up.

        new_elems, i = MHT.partial_insert(self.sorted_elems, elem)

        vo = VO.new(self.sorted_elems[i-1], [], self.sorted_elems[i], self.root)

        self._batch_single_insert(elem, i, new_elems)

        return vo

    def _batch_single_insert(self, elem, i, new_elems):
        """ Insertion of a single element into a Merkle hash tree without
            a corresponding VO, as part of a batch insert.
            NB: this function does *not* guarantee anything about the
            balancedness of the resulting tree.

            Arguments:
            self - the MHT to be modified
            elem - the element to be inserted
            i - the index at which to insert elem
            new_elems - the new list of elements

            Returns:
            i - the index at which elem was inserted into the list

            Assumes:
            - There are at least two 'boundary' elements in the MHT
            - One boundary element is less than everything else that will
              be inserted (including elem), and the other is greater than
              everything else (including elem).

            Optimization Opportunities:
            - We might be able to get away with waiting to update the tree
              until the end of the batch insert, then doing it all at once;
              it seems like there's a lot of unnecessary work being done here.
        """

        if i-1 < 0 or i+1 > len(self.sorted_elems):
            raise MHTInsertionException(
                'Element to be inserted %d does not occur within range of MHT (from %d to %d)\nGiven index %d in a %d-element list' %(elem, self.sorted_elems[0], self.sorted_elems[-1], i, len(self.sorted_elems)))

        new_leaf = MHTNode.leaf(elem)

        self.sorted_elems = new_elems
        self.elems[elem] = new_leaf

        # Sibling choice needs to be deterministic, so we choose the
        # left sibling
        sibling_leaf = self.elems[self.sorted_elems[i-1]]

        MHTNode.insert(new_leaf, sibling_leaf)

    def batch_insert(self, elems):
        """ Insert a series of elements into a tree all at once.
            
            Arguments:
            elems - an iterable sequence of elements to insert

            Optimization opportunities:
            - Requiring that the input list be sorted might provide some
              interesting ways to optimize insertion? Not sure how realistic
              it is in practice, though.
        """
        for elem in elems:
            new_elems, i = MHT.partial_insert(self.sorted_elems, elem)
            self._batch_single_insert(elem, i, new_elems)

    @staticmethod
    def batch_list_insert(elem, sorted_elems):
        """ Step 1/3 of batch insertion.

            The first precomputing phase of a batch insert. Determines the list
            of elements to ultimately insert into the MHT.

            Arguments:
            elem - the next element to insert in this phase
            sorted_elems - the elements in the range to be inserted into
                           so far
        """
        
        bisect.insort_left(sorted_elems, elem)

    @staticmethod
    def batch_node_insert(sorted_elems):
        """ Step 2/3 of batch insertion.
        
            Makes the entire new subtree for an insert out of the sorted list
            of elements to exist within that range. Currently guaranteed to be
            as balanced as possible, since it just makes a new MHT.

            Arguments:
            sorted_elems - the list of elements within the insertion range,
                           in sorted order.

            Returns:
            mht - the entire new subtree to be added to the main MHT
        """

        return MHT.new(sorted_elems)

    def batch_update(self, subtree, lca):
        """ Step 3/3 of batch insertion.

            Modifies the MHT to reflect the changes made during the previous
            two steps.

            Arguments:
            subtree - the MHT representing the tree to be placed at the least
                      common ancestor of the insertion range.
            lca - the root of the subtree of the original MHT being modified
        """

        if lca.parent:
            # LCA isn't the root, so make sure the new subtree has the
            # right parent
            subtree.root.parent = lca.parent

            # Set the LCA's parent child to the new subtree instead of
            # the LCA
            if lca.parent.left is lca:
                lca.parent.left = subtree.root
            elif lca.parent.right is lca:
                lca.parent.right = subtree.root
        else:
            # if the lca has no parent, it was the root of the tree
            self.root = subtree.root

        MHTNode.update_parents(subtree.root.parent)

        self.elems = dict(self.elems.items() + subtree.elems.items())
        self.sorted_elems = self.root.subtree_elems()

    def _gestalt_batch_insert(self, left, right, new_elems):
        """ Run all three phases of batch update in a row. Note that this is
            mostly for testing/comparison purposes: the three phases are
            separated for a reason! In particular, this function
            is NOT safe for concurrent access.

            Arguments:
            left, right - the left and right bounds of the range to be inserted
                          into
            new_elems - the list of new elements to be inserted
        """

        lefti = bisect.bisect_left(self.sorted_elems, left)
        righti = bisect.bisect_right(self.sorted_elems, right)

        ## can't currently handle the case where there are no elements in the
        ## given range
        assert lefti < righti

        lca = MHTNode.least_common_ancestor(
            self.elems[self.sorted_elems[lefti]],
            self.elems[self.sorted_elems[righti-1]])

        range_elems = lca.subtree_elems()
        
        for elem in new_elems:
            MHT.batch_list_insert(elem, range_elems)

        subtree = MHT.batch_node_insert(range_elems)

        self.batch_update(subtree, lca)

    def contains(self, elem):
        """ Arguments:
            self - the MHT to be queried
            elem - the elem whose membership in the MHT is to be determined

            Returns:
            If elem is not in the MHT, returns false.
            If elem is in the MHT, returns a list of hashes that can be combined
            with elem's hash to compute the root hash of the tree for the
            client to verify that the item actually is present.

            NB: if self is a singleton MHT, this will return the empty list.
            Therefore, `if mht.contains(x)` is an inadequate test, since it
            will evaluate to false if None is returned or if x is the singleton
            value within mht.
        """

        if elem not in self.elems:
            return None

        node = self.elems[elem]
        proof = []
        parent = node.parent

        while parent:
            if node is parent.left:
                proof.append((True, parent.right.hval))
            elif node is parent.right:
                proof.append((False, parent.left.hval))

            node = parent
            parent = node.parent

        return proof

    def range_query(self, lower, upper):
        """ Return a verification object for all elements between lower
            and upper (inclusive) in the tree.

            Arguments:
            lower - lower bound for the range query
            upper - upper bound for the range query

            Returns:
            Verification object for the range (never None)

            Assume the MHT contains at least two elements and that the
            least & greatest elements stored are known to the client.
        """

        lbound, li, ri, rbound = MHTNode.find_boundary(self.sorted_elems,
                                                       lower,
                                                       upper)
        
        vo_elems = self.sorted_elems[li:ri+1]

        return VO.new(lbound, vo_elems, rbound, self.root)

    def valid(self):
        """ Verifies that self is a valid Merkle hash tree
        """

        for elem, leaf in self.elems.items():
            if (leaf.hval != MHTUtils.hash(elem)):
                raise InvalidMerkleTree(
                    "Each leaf's hash value must be its element's hash.")

            if leaf.left or leaf.right:
                raise InvalidMerkleTree(
                    'Each leaf must have no children')

            if leaf.elem is None:
                raise InvalidMerkleTree(
                    'Each leaf must have an element')
            elif leaf is not self.elems[leaf.elem]:
                raise InvalidMerkleTree(
                    'Each leaf element must point to itself')

            if leaf._root_of() is not self.root:
                raise InvalidMerkleTree(
                    'The root of each leaf must be the main root.')

        if self.root.parent:
            raise InvalidMerkleTree(
                'The root must have no parent')

        ## Make sure the nodes are well-formed
        self.root.valid()
