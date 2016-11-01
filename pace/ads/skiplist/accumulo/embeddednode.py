## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Skiplist nodes embedded into Accumulo
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  11 Feb 2015  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../../..')
sys.path.append(base_dir)

# This is the python library implementation of SHA256, which is faster than
# the PyCrypto version in PyCrypto.Hash.SHA256
from hashlib import sha256
from pyaccumulo import Range, Mutation
from collections import deque

import string

from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.authnode import AuthNode
from pace.ads.skiplist.elemclass import AccumuloEntry
from pace.common.common_utils import get_single_entry

class EmbeddedNode(AuthNode):
    """ An embedding of authenticated skiplist nodes into Accumulo,
        attempting to duplicate as little of the complicated code
        as possible.

        Assumptions:
        This class assumes that the user never wants to delete any of
        the metadata about a node, just write or overwrite it. In particular,
        this means writes of right, down, and parent nodes will always take
        a node, not None.
    """

    def __init__(self, sl, name):
        """ Each node must refer to its parent skiplist, which contains
            information about the server and table the embedding resides
            in, and the name of the node, which is a unique ID used to
            look it up in the relevant table in Accumulo.
            
            Arguments:

            sl - the overall embedded skiplist object
            name - the unique identifier of this node
        """
        self.name = name
        self.sl = sl

    @staticmethod
    def _make_name(down, right, elem):
        """ Generate a name for a node with the given children & element.
        """

        if down:
            # Node is an internal node; make sure its name is (probably) unique
            dname = down.name
            rname = right.name if right else ''
            name = sha256(','.join([dname, rname, elem.serialize()])).digest()
        else:
            # Node is a leaf; make the hash depend only on the element.
            name = sha256(elem.serialize()).digest()

        return name
            
    @classmethod
    def newnode(cls, sl, down, right, elem, assign_label=False, left=None):
        """ Create a new node.

            Arguments:
            sl - the skiplist this node is a part of.
            down - the bottom neighbor of the new node (if any)
            right - the right neighbor of the new node (if any)
            elem - the element to be stored in the new node.
            assign_label - whether to assign a hash label to this node
                           upon creation (alternative is to defer it to
                           be called manually by whoever is using this
                           code). Default: False (do not assign a label
                           yet)
            left - the node to the left of this node, if any. Default: None

            Returns:
            A new SkipListNode with fields as given.
        """
        name = cls._make_name(down, right, elem)
        new_node = cls(sl, name)
        new_node.elem = elem

        if left is not None:
            new_node.parent = left, False

        if down is not None:
            down.parent = (new_node, True)
            new_node.down = down

        if right is not None:
            new_node.right = right

            par = right.parent

            if par is not None:
                parent, from_up = par
                if not from_up:
                    right.parent = (new_node, False)
            else:
                right.parent = (new_node, False)

        if assign_label:
            new_node.assign_label()
        
        return new_node

    def search(self, elem):
        """ Search the SkipList for node containing an element that is
            either equal to elem (if elem is in the list) or the closest
            element in the list that is less than elem (if elem is not in the
            list)

            Since this is embedded in an Accumulo table, we can look up the
            node in the table first by its hash value. If it is not present,
            we then fail back to the older, slower method in the superclass.

            Argument:
            elem - the element (from elemclass.py) to be searched for

            Returns:
            visited - a collection of nodes visited, stored in reverse order
            current - the closest node in the base list that is less than or
                      equal to elem
        """
        # Look for the element; if it's found, return it; if not, search.
        node = self.sl.from_elem(elem)

        if node is not None:
            # It was found! Return the iterable object for its 'visited'
            # path and the node itself.
            return node.path(), node

        # It wasn't found! Time to search for it. This may arise when the
        # actual element being searched for is not stored in Accumulo, in
        # which case we need to find the greatest element less than the one
        # being searched for.

        current = self
        right = current.right
        visited = deque([])

        while (isinstance(right, type(self)) and
               right.elem <= elem):
            visited.appendleft((current, False))
            current = right
            right = current.right

        down = current.down

        while down is not None:
            visited.appendleft((current, True))
            current = down
            right = current.right
            while (isinstance(right, type(self)) and 
                   right.elem <= elem):
                visited.appendleft((current, False))
                current = right
                right = current.right

            down = current.down

        return visited, current

    def path(self):
        """ Return a generator for all the nodes between this node
            and the root.
        """
        node = self
        parent = node.parent

        while parent is not None:
            node, flag = parent
            yield node, flag
            parent = node.parent

    @property
    def tower(self):
        _, from_above = self.parent

        return not from_above

    @tower.setter
    def tower(self, value):
        raise Exception('Cannot set embedded tower values.')

    @property
    def down(self):
        entry = get_single_entry(self.sl.conn, self.sl.table, row=self.name,
                                 cf='child', cq='down')
        if entry is not None:
            return EmbeddedNode(self.sl, entry.val)
        else:
            return None

    @down.setter
    def down(self, value):
        """ Set the value of the node underneath this one.
            Argument must be another node.
            
            Arguments:
            value - the EmbeddedNode object to the right of `self`
        """
        assert isinstance(value, EmbeddedNode)

        m = Mutation(self.name)
        m.put(cf='child', cq='down', val=value.name)
        self.sl.conn.write(self.sl.table, m)

    @property
    def right(self):
        entry = get_single_entry(self.sl.conn, self.sl.table, row=self.name,
                                 cf='child', cq='right')
        if entry:
            return EmbeddedNode(self.sl, entry.val)
        else:
            return None

    @right.setter
    def right(self, value):
        """ Set the value of the node to the right of this one.
            Argument must be another node.
            
            Arguments:
            value - the EmbeddedNode object to the right of `self`
        """
        assert isinstance(value, EmbeddedNode)

        m = Mutation(self.name)
        m.put(cf='child', cq='right', val=value.name)
        self.sl.conn.write(self.sl.table, m)

    @property
    def raw_elem(self):
        """ Return just the serialization of the element.
        """
        entry = get_single_entry(self.sl.conn, self.sl.table, row=self.name,
                                 cf='other', cq='elem')
        assert entry is not None
        return entry.val

    @raw_elem.setter
    def raw_elem(self, value):
        m = Mutation(self.name)
        m.put(cf='other', cq='elem', val=value)
        self.sl.conn.write(self.sl.table, m)

    @property
    def elem(self):
        return self.sl.elemclass.deserialize(self.raw_elem)

    @elem.setter
    def elem(self, value):
        self.raw_elem = value.serialize()

    @property
    def label(self):
        entry = get_single_entry(self.sl.conn, self.sl.table, row=self.name,
                                 cf='other', cq='label')
        return entry.val

    @label.setter
    def label(self, value):
        # labels are represented as unstructured strings, so we can
        # just write them directly to the value field
        m = Mutation(self.name)
        m.put(cf='other', cq='label', val=value)
        self.sl.conn.write(self.sl.table, m)

    @property
    def parent(self):
        """ Return the parent node and a flag denoting whether it is the
            node above this one ('True') or to the left ('False').
        """

        parent = get_single_entry(self.sl.conn, self.sl.table, row=self.name,
                                  cf='parent')

        if parent is None:
            return None

        path, name = string.split(parent.val, ',', 1)
        parent_node = EmbeddedNode(self.sl, name)

        if path == 'from_left':
            return parent_node, False
        elif path == 'from_up':
            return parent_node, True
        else:
            raise Exception('Invalid parent column qualifier: %s' %parent.cq)

    @parent.setter
    def parent(self, value):
        """ Set the value of this node's parent node. Argument must be a
            tuple of an EmbeddedNode and a boolean denoting whether the
            parent is an upper (as opposed to left) neighbor.
            
            NB: `parent` is only set in `newnode()`
        """
        parnode, from_up = value

        assert isinstance(parnode, EmbeddedNode)
        
        if from_up:
            strval = ','.join(['from_up', parnode.name])
        else:
            strval = ','.join(['from_left', parnode.name])

        m = Mutation(self.name)
        m.put(cf='parent', cq='', val=strval)
        self.sl.conn.write(self.sl.table, m)

    @property
    def tower(self):
        """ Return whether this node is a tower node. If the parent node in the
            path is above this one, then it is a tower node; otherwise it is
            a plateau node.
        """
        parent = self.parent

        if parent:
            return self.parent[1]
        else:
            # Must be the root
            return False

    @tower.setter
    def tower(self, value):
        # tower is a derived property now---no need to store it explicitly
        pass

    def assign_label(self):
        """ One possible source of optimization for this function would
            be to figure out how to streamline/cache the lookups it
            performs.
        """
        node = self
        right = node.right

        if right is None:
            node.label = str(0)
            return

        if node.down is None:
            if right.tower:
                node.label = AuthNode.chash(
                                AuthNode._hash(node.raw_elem),
                                AuthNode._hash(right.raw_elem))
            else:
                node.label = AuthNode.chash(
                                AuthNode._hash(node.raw_elem),
                                right.label)
        else:
            if right.tower:
                node.label = node.down.label
            else:
                node.label = AuthNode.chash(node.down.label, right.label)
