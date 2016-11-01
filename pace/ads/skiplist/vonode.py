## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Node class for VOs
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  28 Jul 2014  ZS    Original file
## **************

from base64 import b64encode, b64decode
from collections import deque
import bisect

from pace.ads.skiplist.authnode import AuthNode

class VONode(AuthNode):

    def __eq__(self, other):

        if not isinstance(other, VONode):
            return False

        if self.right != other.right:
            return False 

        if self.down != other.down:
            return False

        if self.elem != other.elem:
            return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

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

        return visited, current, bisect.bisect(current.elem, elem)

    def serialize(self):
        """ Return the current VO node as a string that can be sent over the
            network and reconstructed on the other side.

            Should obey the property that VONode.deserialize(n.serialize) == n
            and (VONode.deserialize(s)).serialize == s (for all n and s)
        """

        if self.down is None:
            s_down = '{}'
        elif not isinstance(self.down, VONode):
            s_down = b64encode(self.down)
        else:
            s_down = self.down.serialize()

        if self.right is None:
            s_right = '{}'
        elif not isinstance(self.right, VONode):
            s_right = b64encode(self.right)
        else:
            s_right = self.right.serialize()

        if isinstance(self.elem, list):
            ser_elem = '[%s]' %('~'.join([elem.serialize() for elem in self.elem]))
        else:
            ser_elem = self.elem.serialize()

        serialization = '(%s)' %(','.join([str(self.tower),
                                                 s_down,
                                                 s_right,
                                                 ser_elem]))
        return serialization

    @staticmethod
    def deserialize(vo, node, elemClass):
        """ Return the current VO node as a string that can be sent over the
            network and reconstructed on the other side.

            Should obey the property that
                VONode.deserialize(n.sl, n.serialize) == n
            and
                (VONode.deserialize(sl, s)).serialize == s (for all n and s)
        """
        here, _ = VONode.deserialize_helper(vo, node, 0, elemClass)
        return here

    @staticmethod
    def deserialize_helper(vo, node, k, elemClass):
        # TODO: remove the recursion (probably by making dummy nodes &
        #       backpatching them in with a loop?)

        if node[k:k+2] == '{}':
            return None, k+2

        elif node[k] != '(':
            # Must be a base64 encoding, so look for the ',' that delimits it
            i = node.find(',', k)
            return b64decode(node[k:i]), i
        
        # Otherwise, it's a full node
        i = k+1

        if node[i:i+4] == 'True':
            tower = True
            i = i + 4
        elif node[i:i+5] == 'False':
            tower = False
            i = i + 5
        else:
            raise VerificationObjectException(
                'first element of serialized node must be True or False')

        if node[i] != ',':
            raise VerificationObjectException(
                'commas must separate serialized node elements (1 & 2)')

        i = i + 1

        down, i = VONode.deserialize_helper(vo, node, i, elemClass)

        if node[i] != ',':
            raise VerificationObjectException(
                'commas must separate serialized node elements (2 & 3)\nfound "%s" instead' %node[i])

        i = i + 1

        right, i = VONode.deserialize_helper(vo, node, i, elemClass)

        if node[i] != ',':
            raise VerificationObjectException(
                'commas must separate serialized node elements (3 & 4)\nfound "%s" instead' %node[i])

        i = i + 1

        if node[i] == '[':
            # it's a leaf list
            i = i + 1
            j = node.find('])', i)
            elem = [elemClass.deserialize(x) for x in node[i:j].split('~')]
            i = j+2

        else:
            j = node.find(')', i)
            elem = elemClass.deserialize(node[i:j])
            i = j+1

        here = VONode(vo, down, right, elem)
        here.tower = tower

        return here, i

    @staticmethod
    def newnode(vo, down, right, elem, assign_label=False):
        if isinstance(down, str) and isinstance(right, str):
            return AuthNode.chash(down, right)
        elif isinstance(down, str) and right is None:
            return down
        elif isinstance(right, str) and down is None:
            return right
        elif down is None and right is None:
            return super(VONode, VONode).newnode(
                vo, None, None, elem, assign_label)

        if not isinstance(down, VONode):
            node = super(VONode, VONode).newnode(
                vo, None, right, elem, assign_label)
            node.down = down
        else:
            node = super(VONode, VONode).newnode(
                vo, down, right, elem, assign_label)
            down.tower = True
            
        return node

    def verify(self, lower, upper):
        """ Verify that a node (including its subtree) is correct, recursively
            assigning labels along the way
        """
        # TODO: recursion won't work for nontrivial cases in python;
        #       rewrite iteratively at some point
        node = self

        if node.down is None:
            if node.right is not None:
                raise VerificationObjectException(
                    'Malformed VO: base VO nodes have no children')
            if len(node.elem) < 2:
                raise VerificationObjectException(
                    'Malformed VO: base element list must have at least 2 elements')

            for i in range(len(node.elem)-1):
                if node.elem[i] > node.elem[i+1]:
                    raise VerificationObjectException(
                        'Malformed VO: elements in base must be in order')

            if node.elem[-1] < lower:
                raise VerificationObjectException(
                    'Malformed VO: element out of range (less than minimum)')

            # Don't want to check if right end is greater than maximum---might
            # have returned a base list whose first element is in the range,
            # but whose next element is the right boundary element
            if node.elem[0] > upper:
                raise VerificationObjectException(
                    'Malformed VO: element out of range (greater than maximum)')

            node.label = reduce(AuthNode.chash,
                                [AuthNode._hash(x.serialize())
                                 for x in reversed(node.elem)])

            return node.elem

        # If it's not a base element (and therefore has a lower neighbor)
        else:
            if node.right is None:

                if isinstance(node.down, VONode):
                    if node.down.down and node.elem != node.down.elem:
                        raise VerificationObjectException(
                            'Malformed VO: element of lower node must be same as parent')
                    elif (node.down.down is None and
                          node.elem != node.down.elem[0]):
                        raise VerificationObjectException(
                            'Malformed VO: first element of leaf list must be same as parent')
                    down_elems = node.down.verify(lower, upper)
                    node.label = node.down.label

                    return down_elems
                else:
                    raise VerificationObjectException(
                        'Malformed VO: Branch not collapsed when it should have been (right neighbor None)')

            else:
                if not (isinstance(node.down, VONode) or
                        isinstance(node.right, VONode)):
                    raise VerificationObjectException(
                        'Malformed VO: Branch not collapsed when it should have been (neither neighbor VOnode)')

                down_elems = []
                right_elems = []

                down_label = node.down
                right_label = node.right

                if isinstance(node.down, VONode):
                    if node.down.down and node.elem != node.down.elem:
                        raise VerificationObjectException(
                            'Malformed VO: element of lower node must be same as parent')
                    elif (node.down.down is None and
                          node.elem != node.down.elem[0]):
                        raise VerificationObjectException(
                            'Malformed VO: element of lower node must be same as parent')

                    down_elems = node.down.verify(lower, upper)
                    down_label = node.down.label
                elif lower <= node.elem <= upper:
                    # This branch definitely should have been returned!
                    # This check keeps a malicious server from omitting
                    # branches in the middle of a range.
                    raise VerificationObjectException(
                        'Malformed VO: branch omitted that should not have been')


                if isinstance(node.right, VONode):
                    if node.right.elem < node.elem:
                        raise VerificationObjectException(
                            'Malformed VO: elements on right must be >= elements on left')

                    right_elems = node.right.verify(lower, upper)
                    right_label = node.right.label

                    # Cut off the overlap, if it exists
                    if down_elems:
                        down_elems = down_elems[:-1]

                node.label = AuthNode.chash(down_label, right_label)

                return down_elems + right_elems

    def assign_label(self):
        """ VOs have a different structure than skiplists, so their label
            assignment algorithm is completely different. If a node has a
            right neighbor, then that node must have been a plateau node; if
            not, then its right neighbor must have been a tower node.
        """

        if self.down is None:
            self.label = reduce(AuthNode.chash,
                                [AuthNode._hash(x.serialize())
                                 for x in reversed(self.elem)])
            return

        if isinstance(self.down, VONode):
            down_hash = self.down.label
        else:
            down_hash = self.down

        if self.right is None:
            # Just assign the bottom hash, since the right neighbor was a
            # tower node
            self.label = down_hash
            return

        if isinstance(self.right, VONode):
            right_hash = self.right.label
        else:
            right_hash = self.right

        self.label = AuthNode.chash(down_hash, right_hash)
        return

class VerificationObjectException(Exception):
    def __init__(self, msg):
        self.msg = msg
