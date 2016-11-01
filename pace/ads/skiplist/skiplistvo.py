## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Verification objects for skiplists
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   4 Sep 2014  ZS    Copied from python/merkle/ to use with skiplists
##  18 Jul 2014  ZS    Original file (python/merkle/vo.py)
## **************

from hashlib import sha256
from base64 import b64encode, b64decode
import bisect

from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.vonode import VONode, VerificationObjectException
from pace.ads.skiplist.coin import BaseCoin

class SkipListVO(AuthSkipList):
    """ Verification objects for skiplists.

        Note that while this is built on skiplists as a base class, a
        skip list VO is _not_ necessarily a valid skip list. There are
        two major distinctions for the current, unoptimized case:

        1) The VO has a tree-like structure. In particular, if the right
           neighbor of a node in a skiplist is irrelevant to the root
           label contribution of the current path, its corresponding node
           in the VO will have an empty entry for its right neighbor.

        2) If a branch has no elements in the query's range on it, it will
           get collapsed to its label value, which will be inserted at the
           appropriate point in the VO in lieu of the branch itself.
    """

    nodeclass = VONode

    def __eq__(self, other):
        if self.lbound != other.lbound:
            return False
        
        if self.rbound != other.rbound:
            return False

        if not (self.root == other.root):
            return False

        return True

    def __neq__(self, other):
        return not self.__eq__(other)


    @classmethod
    def new(cls, auth_skiplist, lbound, rbound, coin=BaseCoin()):
        """ Create a new VO from an AuthSkipList for a given range.
            
            The new VO has a tree-like structure. Notably, it does NOT have
            the usual grid-like structure of a skiplist; that is, there is
            not a horizontal connection between each element of each row.
        """

        vo = cls(None, lbound, rbound, coin)
        vo_root = vo.build_node(auth_skiplist.root)
        vo.root = vo_root
        return vo

    @classmethod
    def range_query(cls, auth_skiplist, lbound, rbound, coin=BaseCoin()):
        """ Do a range query on a skiplist with a given range. Same as new()
        """

        return cls.new(auth_skiplist, lbound, rbound, coin)

    def serialize(self):
        return ';'.join(
            [self.lbound.serialize(), self.rbound.serialize(),
             self.root.serialize()])

    @staticmethod
    def deserialize(node, elemClass):
        lbound, rbound, tree = node.split(';')

        vo = SkipListVO(None, 
                        elemClass.deserialize(lbound),
                        elemClass.deserialize(rbound),
                        None)

        vo.root = VONode.deserialize(vo, tree, elemClass)
        return vo

    def insert(self, elem):
        """ Insert the element 'elem' into 'self'. The result of this should
            be the result of inserting 'elem' into the skiplist that generated
            the VO, then performing the same range query on it (assuming both
            coins produce the same flips). 'elem' must be within the VO's
            range.
        """

        visited, left_neighbor, index = self.root.search(elem)

        ## First, insert the element into the list---note that this does NOT
        ## label the node; that must be done later

        ## NB: if the node doesn't move up, 'elem' just gets inserted into the
        ##     list of elements in left_neighbor. if it does go up, it gets
        ##     the elements after a certain point in its own leaf list, and
        ##     left_neighbor replaces those elements with 'elem'
        elem_leaf = None

        current = elem_leaf
        stopped = False
        current_hash_value = sha256(elem.serialize()).digest()

        new_elems = []

        ## Determine how many levels of the skiplist to insert the new
        ## element on. Each time we visited a node in the traversal, if we
        ## dropped down (instead of going right), that node is a potential
        ## new neighbor for a new node. We look at these bottom-up, and keep
        ## inserting nodes until the element is gone.
        for v, flag in visited:
            if not flag:
                # We just went right at this step, so don't do anything.
                continue

            # Otherwise, we dropped down, so we need to see if we insert a new
            # level of the inserted element
            if self.stop(current_hash_value):
                stopped = True
                break

            current_hash_value = sha256(current_hash_value).digest()

            if current is None:
                elem_leaf = self.nodeclass.newnode(self, None, None,
                    [elem] + left_neighbor.elem[index:])

                assert all([y >= elem for y in elem_leaf.elem])

                del(left_neighbor.elem[index:])
                left_neighbor.elem.append(elem)

                left_neighbor.assign_label()

                next_level = self.nodeclass.newnode(self, elem_leaf, v.right, elem)
                new_elems.append(next_level)
                current = next_level

                left_neighbor.right = None
                v.right = next_level
                left_neighbor = v

            else:
                ## Defer labeling until later, in case we're inserting it at the
                ## current top level.
                next_level = self.nodeclass.newnode(self, current, v.right, elem)
                new_elems.append(next_level)

                left_neighbor.right = None
                left_neighbor = v
                v.right = next_level
                current = next_level

        new_roots = []

        if not stopped:
            # If we got here we need to add another level of just -infty, +infty
            self.root.right.right = None
            left_neighbor = self.root

            new_rght = '0'
            new_root = self.nodeclass.newnode(
                self, self.root, new_rght, self.root.elem)

            self.root = new_root
            new_roots.append(new_root)

            # At this point, we can safely assign labels to all the new nodes
            # created up until now.
            elem_leaf.assign_label()
            for n in new_elems:
                n.assign_label()

            while not self.stop(current_hash_value):
                current_hash_value = sha256(current_hash_value).digest()

                # Add higher levels
                old_right = self.root.right
                old_left = self.root

                if isinstance(old_right, VONode):
                    new_right = self.nodeclass.newnode(
                        self, None, None, old_right.elem, True)
                else:
                    new_right = old_right
                    old_right = None

                new_left = self.nodeclass.newnode(
                    self, old_left, new_right, old_left.elem)
                new_roots.append(new_left)
                
                # It's safe to label this one because the new level has
                # already been inserted
                new_level = self.nodeclass.newnode(self, current, None, elem, True)
                old_left.right = new_level
                self.root = new_left

                left_neighbor.right = None
                left_neighbor = old_left

                current = new_level

        else:
            if current is None:
                assert not new_elems
                left_neighbor.elem.insert(index, elem)
                left_neighbor.assign_label()
            else:
                # Need to update the nodes visited up until now
                elem_leaf.assign_label()
                for n in new_elems:
                    n.assign_label()

        # Now we have to update all the visited nodes' labels
        modified = [v for v, _ in visited] + new_roots

        for v, f in visited:
            v.assign_label()

        for v in new_roots:
            v.assign_label()

        return

    def build_node(self, skiplist_node):
        """ Builds a VO node for a skip list within a range.

            Returns:
            One value, depending on what it found:

            If the node is on a path from something needed in the range query
            to the root, return the VONode of that node.

            If not, return the hash value of that node.
        """
        # two cases: base level & not-base level
        #
        # base level: if nothing between here & the next tower node (not
        #             including the next tower node) is in range, return
        #             nothing; otherwise return those elements
        #
        # not-base level: two more cases
        #   right-hand neighbor is a tower node: just make a new node & figure
        #       out what to put under it
        #   right-hand neighbor is a plateau node: two *more* cases
        #       if it's not in range: put its label there
        #       if it is in range: recur!
        #
        # TODO: how do we list the elements returned, exactly? was thinking a
        #       list of lists, but actually that might not be necessary if we
        #       just always check for being out-of-range and keep track of the
        #       last element we saw in the last 'branch' of the VO during
        #       verification
        #  Potential answer: don't list them at all!
        # TODO: can probably "unroll" at least some of this recursion into loops
        lower = self.lbound
        upper = self.rbound

        if skiplist_node.down is None:
            # we're in the base level
            # need to find out if we're including this branch by going to the
            # rightmost non-tower element & seeing if it's >= the
            # lower bound of the range.
            # If it is, we include each element of the base level here.
            #
            # For now, we achieve this inclusion by returning a list of all
            # the base elements in this branch, up to and including the next
            # tower node.

            current = skiplist_node
            elems = [current.elem]

            # current.right should exist---if it fails because
            # of that, it's a bug & should be investigated!
            assert current.right

            while not current.right.tower:
                current = current.right
                elems.append(current.elem)

            if current.right.elem >= lower:
                elems.append(current.right.elem)
                leaf = VONode.newnode(self, None, None, elems)
                return leaf
            else:
                return skiplist_node.label

        else:
            # We're not in the base level. Need to check if the element to
            # the right is a plateau node. If it's not, we just make a node here
            # and continue.

            if skiplist_node.right.tower:
                # TODO: this is the recursion we can probably eliminate
                lower_node = self.build_node(skiplist_node.down)

                if isinstance(lower_node, VONode):
                    current_node = VONode.newnode(self, lower_node, None,
                                                  skiplist_node.elem)
                    return current_node
                else:
                    return lower_node
            else:
                # Othwerwise, the thing on the right is a plateau node, so we
                # need to take it into account when constructing this branch
                # of the path.

                lower_node = self.build_node(skiplist_node.down)

                if skiplist_node.right.elem <= upper:
                    right_node = self.build_node(skiplist_node.right)
                else:
                    right_node = skiplist_node.right.label

                if not (isinstance(lower_node, VONode) or
                        isinstance(right_node, VONode)):
                    return VONode.chash(lower_node, right_node)
                else:
                    current_node = VONode.newnode(self, lower_node,
                                                  right_node,
                                                  skiplist_node.elem)
                    return current_node

    def verify(self, lbound, rbound, root_label):
        """ Verifies that the range query is in fact a valid range query over
            the expected bounds and on a skiplist with the given root label.
        """
        if lbound != self.lbound or rbound != self.rbound:
            raise VerificationObjectException(
                'Malformed VO: unexpected bound(s)')

        elems = self.root.verify(self.lbound, self.rbound)
            

        if self.root.label != root_label:
            raise VerificationObjectException(
                'Malformed VO: root hash does not match expected root hash\nreceived: %s\nexpected: %s' %(self.root.label, root_label))

            
        # If the root labels matched, then the elements in the list must all
        # be the right elements in the hash tree, in order, so make sure they
        # include the necessary boundaries. Note that this cannot possibly
        # succeed if there are fewer than 2 elements returned.

        leftmost = bisect.bisect_left(elems, lbound)

        if not (leftmost > 0):
            raise VerificationObjectException(
                'Malformed VO: left boundary for range query not included in VO')

        rightmost = bisect.bisect_right(elems, rbound)

        if not (rightmost < len(elems)):
            raise VerificationObjectException(
                'Malformed VO: right boundary for range query not included in VO')

        for i in range(len(elems)-1):
            if elems[i] <= self.lbound and elems[i+1] > self.lbound:
                if elems[i] == self.lbound:
                    leftmost = i
                else:
                    leftmost = i + 1

                for j in range(i+1, len(elems)):
                    if elems[j-1] < self.rbound:
                        if elems[j] == self.rbound:
                            # If it gets here, it found both a left and a right
                            # bound
                            return elems[leftmost:j+1]
                        elif elems[j] > self.rbound:
                            return elems[leftmost:j]
                            
        # ...and if it gets here, it didn't
        raise VerificationObjectException(
            'Malformed VO: boundaries for range query not included in VO')

    def to_list_of_lists(self):
        """ Attempts to turn the current object into a list of lists, similar
            to SkipList.to_list_of_lists(). Due to the structure of skiplist
            VOs, this is mostly only useful for rudimentary debugging.
        """
        current = self.root
        rows = []

        while isinstance(current, VONode):
            row = []
            crow = current

            while isinstance(crow, VONode):
                row.append(crow.elem)
                crow = crow.right

            if crow:
                row.append(crow)

            rows.append(row)
            current = current.down

        if current:
            rows.append(current)

        return rows
