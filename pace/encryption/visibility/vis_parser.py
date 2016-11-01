## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Visiblity nodes 
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   17 Feb 2015  ATLH    Original file - based on
##                        ColumnVisibility.java in Accumulo 
##                        code base
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)
 
from enum import IntEnum
import StringIO

class VisibilityFormatException(Exception):
    """ Exception raised when unable to process a vis label
        
        Attributes:
            msg - error message for situation
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class NodeType(IntEnum):
    """
    Represents the four types of nodes. 
    
       EMPTY: exactly what it says on the tin, an empty node
       
       TERM: This is a visibility label term, found at the leaves
         of the tree. For example in 'alice&bob', both 'alice' and
         'bob' would be the terms.
         
       OR: Node for an or clause, children are either other OR/AND
         nodes or terminal TERM nodes. 
         
       AND: Node for an and clause, children are either other OR/AND
         nodes or terminal TERM nodes.
    """
    EMPTY = 0
    TERM = 1
    OR = 2
    AND = 3

VALID_CHAR = ['_','-',':','.','/']

class VisNode(object):
    """
    Basic building block to form visibility trees. Stores the 
    type of the node and the start and the end locations of
    the term in the expression, does not actually store the 
    term itself. Can have multiple children if OR/AND node:
    for example a&b&c would have three children. 
    """
    def __init__(self, start, end=None, type=NodeType.TERM):
        '''
        Arguments:
          start: integer representing the start of the term,
                 in the case of OR/AND nodes, this is just the 
                 location of the '&'/'|'
          end:   integer representing the end of the term,
                 in the case of OR/AND nodes, this is just the
                 location of the '&'/|'. If not specified, is assumed
                 to be one more than the start.
          type:  The type of the node as specified in NodeType. 
                 Defaults to TERM.
        '''
        self.type = type 
        self.start = start
        self.children = []
        if end: 
            self.end = end
        else: 
            self.end = start + 1 
    
    def copy_node(self, node):
        '''
        Returns a copy of the node of the same type with
        the exception of its children. 
        '''
        
        return VisNode(start=node.start, 
                       end=node.end,
                       type=node.type)
        
    def add(self, child):
        """
        Adds the child to the end of list of children
        """
        self.children.append(child)
    
    def getTerm(self, expression):
        '''
        When passed the original expression for the node
        returns the associated term (without quotes if they exist).
        Throws an assertion if the node is not a term node. 
        '''
        assert self.type == NodeType.TERM
        
        if expression[self.start] == '"':
            return expression[(self.start+1):(self.end-1)]
        else:
            return expression[self.start:self.end]
        
class VisTree(object):
    """
    Represents a container for a root VisNode and the 
    corresponding expression
    """
    def __init__(self, root, expression):
        self.root = root
        self.expression = expression
                      
    def __str__(self):
        """
        Overloading str function, does not simply
        return self.expression because it is used
        primarily for testing, and it is useful to 
        see the structure of the tree. 
        """
        s = StringIO.StringIO()
        self._stringify(self.root,self.expression, s)
        s_string = s.getvalue()
        s.close()
        return s_string
        
    def _stringify(self, root, expression, out_put):
        """
        Arguments:
         root: VisNode to turn into a string representation
         exression: the corresponding expression for the 
                    root node passed in
         out_put: StringIO object in which the string 
                  description is placed. 
                  
        Side Effects: Returns nothing, but string representation
          is placed in the out_put object.    
        """
        #case of empty root
        if root is None:
           out_put.write('')
           return 
       
        if root.type == NodeType.TERM:
            out_put.write(expression[root.start:root.end])
        else:
            sep = ''
            for c in root.children:
                out_put.write(sep)
                parens = (c.type != NodeType.TERM) and (root.type != c.type)   
                if parens:
                    out_put.write("(")
                self._stringify(c, expression, out_put)
                if parens:
                    out_put.write(")")
                if root.type == NodeType.AND:
                    sep = '&'
                else: 
                    sep = "|"
                    
        
                
class VisParser(object):
    """
    Contains the logic for parsing visibility labels and turning into
    VisTree
    """
    
    def _getTreeType(self, node, expression):
        return VisTree(node, expression)
    
    def parse(self, expression):
        """
        Arguments:
            expression - the expression to parse
            
        Returns: VisTree containing the root node of 
          the parsed Visibility Tree and the original expression.
          Raises VisibilityFormatException if the visibility 
          is ill-formed. 
        """
        self._index = 0  #current parse location
        self._parens = 0 #number of parenthesis encountered
        
        if len(expression) == 0:
            return None
        
        node = self._parse(expression)
        
        if node is None:
          raise VisibilityFormatException("operator or missing parens: %s" % (expression))
        
        if self._parens != 0: 
          raise VisibilityFormatException("parenthesis mis-match: %s" % (expression))
        
        return self._getTreeType(node, expression)
    
    def _isValidAuthChar(self, c):
        """
        Determines if the character c is an authorized character for the 
        visibility field
        """
        return any([c >= 'a', c <= 'z',
                    c >= 'A', c <= 'Z',
                    c >= '0', c <= '9',
                    c in VALID_CHAR])

    def _processTerm(self, start, end, node_expr, expression):
        """
        Arguments:
            start - start of the term
            end - end of the term
            node_expr - Existing term node or None
            expression - the overall expression 
            
        Returns: Processed term node; if expr existed, it returns 
          the existing node, otherwise creates a new VisNode for
          the term
        """
        if start != end:
            if node_expr is not None:
                raise VisibilityFormatException("expression %s needs to be | or &" % (expression))
            return VisNode(start = start, end = end)
        
        if node_expr is None:
            raise VisibilityFormatException("empty term %s" % (expression))
        return node_expr
    
    def _create_node(self, start, type):
        return VisNode(start = start, type = type)
    
    def _parse(self, expression):
        """
        Arguments:
            expression - the expression to parse
            
        Returns: Root node to the newly parsed visibility tree
        """
        result = None                 #current top-level node
        expr = None                   #child node being parsed
        wholeTermStart = self._index  #start of the top-level term 
        subtermStart = self._index    #start of sub-level term
        subtermComplete = False       #has the subterm been completed
        
        #loop through all characters and parse them individually
        while self._index < len(expression):
            e = expression[self._index]
            self._index += 1
            if e == '&': #case of whole term being being AND
                expr = self._processTerm(subtermStart, self._index - 1, expr, expression)
                if result != None:
                    if result.type != NodeType.AND: 
                        raise VisibilityFormatException("cannot mix & and |")
                else:
                    result = self._create_node(wholeTermStart, NodeType.AND )
                result.add(expr)
                expr = None
                subtermStart = self._index
                subtermComplete = False 
                continue
            
            elif e == '|': #case of whole term being OR
                expr = self._processTerm(subtermStart, self._index - 1, expr, expression)
                if result != None:
                    if result.type != NodeType.OR:
                        raise VisibilityFormatException("cannot mix & and |")
                else:
                    result = self._create_node(wholeTermStart, NodeType.OR )
                result.add(expr)
                expr = None
                subtermStart = self._index
                subtermComplete = False 
                continue
        
            elif e == '(': #case of start of a parenthetical term 
                self._parens += 1
                if (subtermStart != self._index - 1) or (expr is not None):
                    raise VisibilityFormatException("expression needs & or |") 
                #parse the subterm expression 
                expr = self._parse(expression) 
                subtermStart = self._index
                subtermComplete = False
                continue
            
            elif e == ')': #case of end of a parenthetical term 
                self._parens -= 1
                #process the subterm and make sure it is wellformed 
                child = self._processTerm(subtermStart, self._index - 1, expr, expression)
                if child is None and result is None:
                    raise VisibilityFormatException("empty expression not allowed")
                if result is None:
                    return child
                #if the child is the same type as parent (result), promote the child's children 
                if result.type == child.type:
                    for c in child.children:
                        result.add(c)
                else:   
                    result.add(child)
                result.end = self._index - 1 
                return result
            
            elif e == '"': #case of a quoted expression 
                if subtermStart != (self._index - 1):
                    raise VisibilityFormatException("expression needs & or |")
                
                #check to make nothing is invalid escaped in the quotes 
                while (self._index < len(expression) and \
                       expression[self._index] != '"'):
                    if expression[self._index] == '\\':
                          self._index += 1
                          if (expression[self._index] != '\\' and \
                              expression[self._index] != '"'):
                              raise VisibilityFormatException('invalid escaping within quotes')
                    self._index += 1
                    
                #case without a closing quote
                if self._index == len(expression):
                    raise VisibilityFormatException("unclosed quote")
                
                if subtermStart + 1 == self._index:
                    raise VisibilityFormatException("empty term")
                
                self._index += 1
                subtermComplete = True
                continue
            
            else: #all other cases, should be valid characters part of a term 
                if subtermComplete:
                    raise VisibilityFormatException("expression needs & or |")
                
                #check to see the character is valid
                c = expression[self._index - 1]
                if not self._isValidAuthChar(c):
                    raise VisibilityFormatException('bad character (%c)' % (c))
                
                continue
            
        child = self._processTerm(subtermStart, self._index, expr, expression)
        if result is not None:
            result.add(child)
            result.end = self._index
        else:
            result = child
      
        if result.type != NodeType.TERM:
            if len(result.children) < 2:
                raise VisibilityFormatException("missing term")
      
        return result
    

    

        
            
    
    

    