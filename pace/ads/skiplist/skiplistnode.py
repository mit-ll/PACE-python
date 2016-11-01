## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Skip list node library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  19 Aug 2014  ZS    Original file
## **************

from collections import deque

class SkipListNode(object):

    def __init__(self, sl, down, right, elem):
        self.sl = sl
        self.down = down
        self.right = right
        self.elem = elem

    @staticmethod
    def newnode(sl, down, right, elem, *args, **kwargs):
        """ Create a new node. Can be overridden by subclasses.

            Arguments:
            sl - the skiplist this node is a part of.
            down - the bottom neighbor of the new node
            right - the right neighbor of the new node
            elem - the element to be stored in the new node.
            *args, **kwargs - any more arguments that a subclass
                              might want to use

            Returns:
            A new SkipListNode with fields as given.
        """
        new_node = SkipListNode(sl, down, right, elem)
        return new_node

    def search(self, elem):
        """ Search the SkipList for node containing an element that is
            either equal to elem (if elem is in the list) or the closest
            element in the list that is less than elem (if elem is not in the
            list)

            Argument:
            elem - the element to be searched for

            Returns:
            visited - a collection of nodes visited, stored in reverse order
            current - the closest node in the base list that is less than or
                      equal to elem
        """

        current = self
        visited = deque([])

        while (isinstance(current.right, type(self)) and
               current.right.elem <= elem):
            visited.appendleft((current, False))
            current = current.right

        while current.down:
            visited.appendleft((current, True))
            current = current.down
            while (isinstance(current.right, type(self)) and 
                   current.right.elem <= elem):
                visited.appendleft((current, False))
                current = current.right

        return visited, current

    def insert(self, elem):
        """ Insert an element into the base list.
            NB: this does NOT perform the 'coin flips' to determine which
                other lists the element being inserted will go in; it only
                adds it to the base lists. Elevation is the job of
                SkipList.insert.
        """
        visited, left_neighbor = self.search(elem)

        new_node = self.newnode(self.sl, None, left_neighbor.right, elem)
        left_neighbor.right = new_node

        return new_node, left_neighbor, visited

    def valid(self, recur=True):
        current = self

        while current:
            crow = current
            
            while crow:
                # Nodes must appear in sorted order
                if crow.right:
                    if not (crow.elem <= crow.right.elem):
                        raise InvalidSkipListException(
                            'Nodes must appear in sorted order')

                # The node beneath a node must have the same element
                if crow.down:
                    if not (crow.elem == crow.down.elem):
                        raise InvalidSkipListException(
                            'The node beneath a node must have the same element')
                crow = crow.right

            current = current.down

class InvalidSkipListException(Exception):
    def __init__(self, msg):
        self.msg = msg
