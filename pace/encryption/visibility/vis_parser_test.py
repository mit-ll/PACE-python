## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Unit tests for vis_parser.py
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Feb 2015  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import unittest
from pace.encryption.visibility.vis_parser import NodeType, VisNode, VisTree, VisParser,\
                                            VisibilityFormatException

class VisNodeTest(unittest.TestCase):

    def test_get_term(self):
        """
        Tests get_term
        """
        node = VisNode(2, end = 5, type = NodeType.TERM)
        self.assertEqual(node.getTerm("abcdef"),"cde", "Get term does not correctly parse term.")
        self.assertEqual(node.getTerm('ab"d"f'),"d", "Get term does not correctly handle quotes.")
        
class VisParserTest(unittest.TestCase):
    
    
    def test_correct_expressions(self):
        '''
        Tests the parser on correct expressions
        '''
        expressions = ['a&b',
                       'a&b&c',
                       'a|b',
                       'a|b|c',
                       '(a&b)|c',
                       '(a|b)&c',
                       'a|(b&c)',
                       'a&(b|c)',
                       '(a&b)|(b&c)',
                       '(a|b)&(c|d)',
                       '"test&|"&b',
                       '((a&b)|c)&(d|e)']
        parser = VisParser()
        for e in expressions:
            tree = parser.parse(e)
            parsed_expr = tree.__str__()
            self.assertEqual(parsed_expr, e,
                             "Parser did not correctly parse %s: %s" % (e,parsed_expr))
            
            
    def test_incorrect_expressions(self):
        '''
        Test the parser on incorrect expressions 
        '''
        expressions = ['a&b|c',
                       'a&|b',
                       'a|b&c',
                       '()&b',
                       '""&b',
                       '"a&b&c',
                       'a(&b&c',
                       '<&*|}']
        
        parser = VisParser()
        for e in expressions:
            self.assertRaises(VisibilityFormatException,parser.parse, e)

        