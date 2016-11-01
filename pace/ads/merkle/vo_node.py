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

from pace.ads.merkle.mht_node import MHTNode
from pace.ads.merkle.empty_node import EmptyNode
from pace.ads.merkle.hash_node import HashNode


class VONode(MHTNode):

    def __init__(self, hval, left=None, right=None, elem=None):
        if left is None:
            left = EmptyNode()
        if right is None:
            right = EmptyNode()

        super(VONode, self).__init__(hval, left, right, elem)

    def set_parent(self, parent):
        self.parent = parent

    def serialize(node, depth=0):
        """ Create a (reversible) string out of a node
            
            NB: assumes the hash function used is standard to avoid
            having to serialize the hash class.
        """
        if not isinstance(node, MHTNode):
            if node:
                return b64encode(node)
            else:
                return str(node)

        separator = ',' + str(depth) + ','

        return '(%s)' %(separator.join([b64encode(node.hval),
                                       node.left.serialize(depth+1),
                                       node.right.serialize(depth+1),
                                       str(node.elem)]))

    @staticmethod
    def deserialize(s, depth=0):
        if s == 'None':
            return (EmptyNode(), [])
        elif s[0] != '(':
            # It's a hash value
            return (HashNode(b64decode(s)), [])

        separator = ',' + str(depth) + ','

        shval, sleft, sright, selem = s[1:-1].split(separator)

        if shval == 'None':
            hval = None
        else:
            hval = b64decode(shval)

        if sleft == 'None':
            left = EmptyNode()
        else:
            (left, left_leaves) = VONode.deserialize(sleft, depth + 1)

        if sright == 'None':
            right = EmptyNode()
        else:
            (right, right_leaves) = VONode.deserialize(sright, depth + 1)

        if selem == 'None':
            elem = None
        else:
            elem = int(selem)

        node = VONode(hval, left, right, elem)

        left.set_parent(node)
        right.set_parent(node)

        if elem is not None:
            leaves = [node]
        else:
            leaves = left_leaves + right_leaves

        return node, leaves
