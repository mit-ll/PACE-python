## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Authenticated skip list library
##               (as in Goodrich & Tamassia 2001)
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  20 Aug 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../..')
sys.path.append(base_dir)

from hashlib import sha256

from pace.ads.skiplist.skiplist import SkipList
from pace.ads.skiplist.authnode import AuthNode


class AuthSkipList(SkipList):

    nodeclass = AuthNode

    def insert(self, elem):
        """ Insert elem into the base level of the current SkipList, then
            determine how many levels to elevate it by, returning the new hash
            value of the tree. Note that this assumes some other information in
            order to prove that the insert was done correctly (such as having
            done a range query on the proper range); without this information,
            one should use insert_with_diff,  instead.

            Returns:
            ret_elems - the elements in the query set
            label - the updated root label

            Override: also needs to update metadata of each node
        """
        visited, left_neighbor = self.root.search(elem)

        # Have to do this query now before the skiplist gets updated
        # TODO: can maybe do the query inline instead of duplicating effort
        ret_elems, proof = self.do_query(visited, left_neighbor, elem)

        ## First, insert the element into the list---note that this does NOT
        ## label the node; that must be done later
        new_node = self.nodeclass.newnode(self, None, left_neighbor.right, elem, left=left_neighbor)
        left_neighbor.right = new_node

        current = new_node
        stopped = False
        lefts = 0
        current_hash_value = sha256(elem.serialize()).digest()

        new_elems = []

        ## Determine how many levels of the skiplist to insert the new
        ## element on. Each time we visited a node in the traversal, if we
        ## dropped down (instead of going right), that node is a potential
        ## new neighbor for a new node. We look at these bottom-up, and keep
        ## inserting nodes until the element is gone.
        for v, flag in visited:
            if not flag:
                # We just went right at this step, so don't do anything
                continue

            # Otherwise, we dropped down, so we need to see if we insert a new
            # level of the inserted element
            if self.stop(current_hash_value):
                stopped = True
                break

            current_hash_value = sha256(current_hash_value).digest()

            ## Defer labeling until later, in case we're inserting it at the
            ## current top level.
            next_level = self.nodeclass.newnode(self, current, v.right, elem, left=v)
            new_elems.append(next_level)

            v.right = next_level
            current = next_level

        new_roots = []

        if not stopped:
            # If we got here we need to add another level of just -infty, +infty
            old_rght = self.root.right.right

            new_rght = self.nodeclass.newnode(
                self, self.root.right.right, None, self.rbound, True)
            new_root = self.nodeclass.newnode(
                self, self.root, new_rght, self.lbound)

            self.root = new_root
            new_roots.append(new_root)

            # At this point, we can safely assign labels to all the new nodes
            # created up until now.
            new_node.assign_label()
            for n in new_elems:
                n.assign_label()

            while not self.stop(current_hash_value):
                current_hash_value = sha256(current_hash_value).digest()

                # Add higher levels
                old_right = self.root.right
                old_left = self.root

                new_right = self.nodeclass.newnode(
                    self, old_right, None, old_right.elem, True)
                new_left = self.nodeclass.newnode(
                    self, old_left, new_right, old_left.elem)
                new_roots.append(new_left)
                

                # It's safe to label this one because the new level has
                # already been inserted
                new_level = self.nodeclass.newnode(
                    self, current, old_right, elem, True, left=old_left)
                old_left.right = new_level
                self.root = new_left

                current = new_level

        else:
            # Need to update the nodes visited up until now
            new_node.assign_label()
            for n in new_elems:
                n.assign_label()

        # Now we have to update all the visited nodes' labels
        left_neighbor.assign_label()
        modified = [v for v, _ in visited] + new_roots

        for v in modified:
            v.assign_label()

        return ret_elems, self.root.label

    def insert_with_diff(self, elem):
        """ Insert elem into the base level of the current SkipList, then
            determine how many levels to elevate it by, returning a proof
            that the spot used to be empty and a proof that the element was
            actually inserted so the client can update its root label.

            Returns three values:
                - ret_elems: The elements returned by a query for `elem`
                             in the old skip list.
                - proof: A proof that `elem` was not in the old skip list
                - proof_diff: A diff that the client can use to insert
                              `elem` into `proof` and receive a new root
                              hash value.
        """
        visited, left_neighbor = self.root.search(elem)

        # Have to do this query now before the skiplist gets updated
        # TODO: can maybe do the query inline instead of duplicating effort
        ret_elems, proof = self.do_query(visited, left_neighbor, elem)

        ## First, insert the element into the list---note that this does NOT
        ## label the node; that must be done later
        new_node = self.nodeclass.newnode(self, None, left_neighbor.right, elem, left=left_neighbor)
        left_neighbor.right = new_node

        current = new_node
        stopped = False
        lefts = 0
        current_hash_value = sha256(elem.serialize()).digest()

        new_elems = []
        proof_diff = []
        pre_proof_diff = []

        ## Determine how many levels of the skiplist to insert the new
        ## element on. Each time we visited a node in the traversal, if we
        ## dropped down (instead of going right), that node is a potential
        ## new neighbor for a new node. We look at these bottom-up, and keep
        ## inserting nodes until the element is gone.
        for v, flag in visited:
            if not flag:
                # We just went right at this step, so don't do anything, but
                # remember that we have to accumulate one more level if we
                # end up going up again
                lefts = lefts + 1
                # If we're still on the base level, need to signal that this
                # element was added from the base level, for bookkeeping
                # purposes.
                if not v.down:
                    pre_proof_diff.append('MEET')
                continue

            # Otherwise, we dropped down, so we need to see if we insert a new
            # level of the inserted element
            if self.stop(current_hash_value):
                stopped = True
                break

            current_hash_value = sha256(current_hash_value).digest()

            if not proof_diff:
                proof_diff = pre_proof_diff
                proof_diff.append('UP')
                lefts = 0     # UP subsumes PASS
            
            ## Defer labeling until later, in case we're inserting it at the
            ## current top level.
            next_level = self.nodeclass.newnode(self, current, v.right, elem, left=v)
            new_elems.append(next_level)

            ## If this level was "interesting", we need to add to the returned
            ## value that tells the client how to modify the query to get the
            ## new root value.
            ##
            ## An "interesting" level is defined as the following:
            ##
            ## - The first new level (after the base level) is always
            ##   interesting.
            ## - Any level that has just gone up after going left some nonzero
            ##   number of times is interesting.
            ## - Any level with a plateau node on the right (other than +infty)
            ##   is interesting.

            if lefts:
                # The tower of new elements just passed a plateau node on the
                # left, so we need to accumulate all the labels from that chain
                # of plateau nodes
                proof_diff.append(str(lefts))
                lefts = 0

            vright = v.right

            if (not vright.tower) and vright.right:
                # The tower of new elements just met a plateau node on the right
                proof_diff.append('MEET')

            v.right = next_level
            current = next_level

        new_roots = []

        if not stopped:
            # If we got here we need to add another level of just -infty, +infty
            old_rght = self.root.right.right

            new_rght = self.nodeclass.newnode(
                self, old_rght, None, self.rbound, True)
            new_root = self.nodeclass.newnode(
                self, self.root, new_rght, self.lbound)

            self.root = new_root
            new_roots.append(new_root)

            # At this point, we can safely assign labels to all the new nodes
            # created up until now.
            new_node.assign_label()
            for n in new_elems:
                n.assign_label()

            while not self.stop(current_hash_value):
                current_hash_value = sha256(current_hash_value).digest()

                # Add higher levels
                old_right = self.root.right
                old_left = self.root

                #TODO: can cache min/max elems for fewer lookups
                new_right = self.nodeclass.newnode(
                    self, old_right, None, old_right.elem, True)
                new_left = self.nodeclass.newnode(
                    self, old_left, new_right, old_left.elem)
                new_roots.append(new_left)
                

                # It's safe to label this one because the new level has
                # already been inserted
                new_level = self.nodeclass.newnode(
                    self, current, old_right, elem, True, left=old_left)
                old_left.right = new_level
                self.root = new_left

                current = new_level

        else:
            # Need to update the nodes visited up until now
            new_node.assign_label()
            for n in new_elems:
                n.assign_label()

        # Now we have to update all the visited nodes' labels

        left_neighbor.assign_label()
        modified = [v for v, _ in visited] + new_roots

        for v in modified:
            v.assign_label()

        return ret_elems, proof, proof_diff

    @staticmethod
    def update_query(base_elems, old_proof, proof_diff, elem):
        """ Updates a query of an element from an old skiplist without
            that element in it to a query of that element in the skiplist
            resulting from inserting it into the old one. Used to update
            the root label after an insert.
        """

        # No matter what, we're going to insert elem into the proof, so do it
        # first
        elem_loc = 1        # will always be immediately after the left neighbor
        base_elems.insert(elem_loc, elem)

        i = 0
        current = None

        # Recall that a proof is just a path from a base level node to the root
        # of the skip list. This partitions the path into three parts:
        #
        # - Everything from the base of the new path to the top of the new tower
        #   created by adding elem
        # - The label of the node below the node to the left of the new plateau
        #   node, if such a node exists (i.e. if at least one new non-base node
        #   was added). This is calculated from elements in the old proof.
        # - Everything further up in the proof than the new tower reached, whose
        #   order is unchanged.
        #
        # The element i keeps track of the difference between these locations:
        # everything to the left of i (not including i) is in the first group,
        # everything to the right of i (including i) is in the third group, and
        # the variable 'current' is the second group.

        for action in proof_diff:
            if action == 'MEET':
                # If we meet a plateau node on the right, we need to make sure
                # it occurs in the proof before the values we're accumulating
                # (since they need to get hashed into the overall value only
                # after the new tower stops & starts going left)
                i = i + 1
            elif action == 'UP':
                # This action should only occur once per insert, if the inserted
                # element's tower ends up going above the base list.

                # First, we accumulate all the elements in the base list to
                # the left of the new element (and including the new element
                # itself) that occur in the proof.
                current = AuthNode.chash(AuthNode._hash(base_elems[0].serialize()),
                                         AuthNode._hash(elem.serialize()))
                current = reduce(AuthNode.chash, old_proof[:i], current)

                # Next, we update the proof we're modifying. The first element
                # in it now needs to be the label of the bottom node in the
                # new tower.
                old_proof = old_proof[i:]
                i = 1

                # To compute this label, hash the elements from the inserted
                # element to the next base-level tower node, then accumulate
                # them together in order with the commutative hash.
                proof_order_hashes = [AuthNode._hash(e.serialize())
                                      for e in reversed(base_elems[elem_loc:])]
                new_elem_node_label = reduce(AuthNode.chash, proof_order_hashes)
                old_proof = [new_elem_node_label] + old_proof

                # base_elems has been folded into old_proof, so we can set it
                # to the empty list.
                base_elems = []
            else: # passed a plateau node
                # Accumulate the next 'acc_levels' elements of the old proof
                # into the current value.
                acc_levels = int(action)
                for z in range(acc_levels):
                    passed = old_proof.pop(i)
                    current = AuthNode.chash(passed, current)

        if current is not None:
            old_proof.insert(i, current)

        # Return the single list to feed in to verify()
        return ([AuthNode._hash(e.serialize()) for e in reversed(base_elems)] +
                old_proof)
        
    
    def contains(self, elem):
        """ Override of super method. Now returns a proof that elem either is
            or is not in the skip list.

            NB: I have no idea what this algorithm is trying to do, why
                it's right, or how to verify it, I'm just transcribing it
                from the paper's pseudocode into Python.
        """
        visited, closest = self.root.search(elem)
        elems, proof = self.do_query(visited, closest, elem)

        return elems[0] == elem, [AuthNode._hash(x.serialize())
                                  for x in reversed(elems)] + proof

    def do_query(self, visited, closest, elem):
        """ Given the input to a search for an element and that element, return
            a proof that either that element is in the skiplist or that it is
            not (so a proof that the elements on either side of it are adjacent
            in the skiplist.

            Arguments:
            visited - the nodes visited in the skiplist stored in reverse order,
                      paired with a flag indicating whether the next step was
                      to go right or down.
            closest - the node of the base list containing either the element
                      being queried or the greatest element in the skiplist
                      less than the element being queried.
            elem - the element being queried
            
            Returns:
            ret_elems - The elements in the base list starting from 'closest'
                        and going to (and including) the next tower node in the
                        base list.
            proof - A list of hash values that, when combined with ret_elems,
                    proves whether or not elem is in the skiplist.
        """
        proof = []

        last = closest
        found = (last.elem == elem)

        ret_elems = []

        ## First, return the elements of each node to the right of the node
        ## where the search ended until a tower node is reached. This provides
        ## enough information to verify a query in either the positive or
        ## negative direction, as well as enough information for a range
        ## query to be able to search for the next tower node in the base
        ## list.
        nxt = last
        ret_elems.append(nxt.elem)
        while (not nxt.right.tower) and nxt.right.right:
            ret_elems.append(nxt.right.elem)
            nxt = nxt.right
        ret_elems.append(nxt.right.elem)

        for v, flag in visited:
            if not v.right.tower:
                # its right neighbor is a plateau node, so add things
                if v.right is not last:
                    proof.append(v.right.label)
                elif v.down is None:
                    proof.append(AuthNode._hash(v.elem.serialize()))
                else:
                    proof.append(v.down.label)

            last = v
        
        # Return the elements from the end node in the base list to the next
        # tower node; this provides enough information for proof of membership
        # and proof of lack of membership, plus some extra information for
        # other functions that use do_query()
        return ret_elems, proof

    def _range_query(self, lower, upper):
        """ Perform a range query on the skip list, returning all elements
            between lower and upper (inclusive).

            Deprecated code, useful mostly for benchmarking/regression tests
        """

        ## General algorithm overview:
        ## - First, search for 'lower' in the list. This will return either the
        ##   "leaf" node that contains 'lower' (if it is in the list) or the
        ##   first node with an element less than 'lower' (if it is not). Either
        ##   way, this will provide the evidence that the first element of the
        ##   result is in fact the first element in the list that is in the
        ##   range.
        ##
        ## - Keeping track of the current element, move right along the list
        ##   until finding an element greater than or equal to 'upper'. Each
        ##   time a node is reached where the last node searched for does not
        ##   depend on its element's value, perform a new search for that
        ##   element. That will guarantee that the client can verify that the
        ##   returned range is both sound and complete.
        ##
        ## - Return to the client the sequence of verification sequences
        ##   generated by this process.
        ##
        ## TODO: We can almost certainly optimize this process, perhaps by
        ## only returning the paths to a least common ancestor (like in MHTs),
        ## or even more cleverly, tracing the previous visited sequence up until
        ## we find the place where the next search would branch off from it,
        ## then return a sequence (with possible subsequences) based on these
        ## traversals.

        visited, left_bound = self.root.search(lower)
        elems, proof = self.do_query(visited, left_bound, lower)

        proofs = [(elems, proof)]

        elem = elems[-1]
        while elem < upper:
            visited, left_bound = self.root.search(elem)
            elems, proof = self.do_query(visited, left_bound, elem)
            proofs.append((elems, proof))
            elem = elems[-1]

        return proofs

    @staticmethod
    def verify(proof):
        # TODO: does this actually verify anything?
        return reduce(AuthNode.chash, proof)

    @staticmethod
    def _verify_range_query(proofs, lower, upper, root_label):
        """ Verifies a range query done with (the deprecated function)
            _range_query(). Also deprecated.
        """
        labels = [AuthSkipList.verify([AuthNode._hash(x.serialize())
                                       for x in reversed(elems)] + proof)
                  for elems, proof in proofs]

        if not labels:
            raise InvalidVerificationObjectException(
                'Empty list of proofs returned')
            
        all_elems = proofs[0][0]

        for elems, proof in proofs[1:]:
            all_elems.extend(elems[1:])

        ## Check to make sure the original list of elements is sorted
        if not (sorted(all_elems) == all_elems):
            raise InvalidVerificationObjectException(
                'Returned list of elements not sorted')

        ## There might be more than one upper boundary that got included, so
        ## make sure to get rid of all of them from the returned list
        while all_elems[-1] > upper:
            all_elems.pop()

        ## The lower boundary may or may not have been needed, so make sure to
        ## include it just in case
        if all_elems[0] < lower:
            all_elems = all_elems[1:]

        if not all([label == root_label for label in labels]):
            raise InvalidVerificationObjectException(
                'Invalid path exists in VO')
        
        if not all([lower <= elem <= upper for elem in all_elems]):
            raise InvalidVerificationObjectException(
                'Elements returned not in requested range')

        return all_elems

class InvalidVerificationObjectException(Exception):
    def __init__(self, msg):
        self.msg = msg
