## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Authenticated skiplists embedded in Accumulo
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  10 Feb 2015  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.join(this_dir, '../../../..')
sys.path.append(base_dir)

from hashlib import sha256
from pyaccumulo import Accumulo, Range
from collections import namedtuple

from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.coin import BaseCoin
from pace.ads.skiplist.elemclass import IntElem
from pace.ads.skiplist.accumulo.embeddednode import EmbeddedNode
from pace.common.fakeconn import FakeConnection

ConnInfo = namedtuple('ConnInfo', ['hostname', 'port', 'username', 'password'])

class EmbeddedSkipList(AuthSkipList):
    """ A class for an authenticated skip list embedded in an Accumulo
        instance. Most of the work on the actual embedding is in the 
        node class, found in embeddednode.py
    """

    nodeclass = EmbeddedNode

    def from_elem(self, elem):
        """ Check if an element is in the database. If so, return an
            embedded node pointing to that element's leaf node in the
            skiplist. If not, return None.
        """

        key = sha256(elem.serialize()).digest()

        candidates = self.conn.scan(self.table, Range(srow=key, erow=key))

        try:
            first = next(candidates)
        except StopIteration:
            # It's not there, so return None
            return None

        # Otherwise, this row is there, so return the node with the right name
        return EmbeddedNode(self, key)

    @classmethod
    def new(cls, elems, lbound, rbound, coin=BaseCoin(),
            conn_info=ConnInfo('localhost', 42424, 'root', 'secret'),
            table='__ADS_metadata___',
            elemclass=IntElem):
        """ Create a new skiplist that stores all of its data inside an
            Accumulo instance.

            Arguments:

            cls - the class implementing this class method
            elems - the elements to create the skiplist over
            lbound, rbound - the left and right boundary elements of the list
            coin - the source of randomness to use
                   (see pace.ads.skiplist.coin)
            conn_info - how to connect to the Accumulo instance being used
            table - the name of the table to store the ADS in
            elemclass - the class to use to store the elements in the skiplist
        """

        sl = cls(None, lbound, rbound, coin)

        if conn_info is not None:
            # For connecting to a live Accumulo instance
            host, port, user, password = conn_info
            conn = Accumulo(host=conn_info.host,
                            port=conn_info.port,
                            user=conn_info.user,
                            password=conn_info.password)
        else:
            # For testing/debug
            conn = FakeConnection()

        sl.conn = conn
        sl.table = table
        sl.elemclass = elemclass

        if not conn.table_exists(table):
            conn.create_table(table)

        right = cls.nodeclass.newnode(sl, None, None, rbound, True)
        left = cls.nodeclass.newnode(sl, None, right, lbound, True)

        sl.root = left

        for elem in elems:
            sl.insert(elem)

        return sl

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
            elem - the element (from elemclass.py) being queried
            
            Returns:
            ret_elems - The elements in the base list starting from 'closest'
                        and going to (and including) the next tower node in the
                        base list.
            proof - A list of hash values that, when combined with ret_elems,
                    proves whether or not elem is in the skiplist.
        """
        # NB: this (and several other functions in this class) has only been
        #     been changed to reduce the number of redundant accesses to
        #     node.right, node.down, etc.
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
        right = nxt.right
        right2 = right.right
        ## Continue until we encounter a tower node or exhaust the base list
        while (not right.tower) and right2:
            ret_elems.append(right.elem)
            nxt = right
            right = right2
            right2 = right.right
        ret_elems.append(right.elem)

        for v, flag in visited:
            right = v.right
            if not right.tower:
                # its right neighbor is a plateau node, so add things
                if right.name != last.name: # edited to use names, since they
                                            # might not be pointer-eq
                    proof.append(right.label)
                else:
                    down = v.down
                    if down is None:
                        proof.append(EmbeddedNode._hash(v.elem.serialize()))
                    else:
                        proof.append(down.label)
            last = v
        
        # Return the elements from the end node in the base list to the next
        # tower node; this provides enough information for proof of membership
        # and proof of lack of membership, plus some extra information for
        # other functions that use do_query()
        return ret_elems, proof
