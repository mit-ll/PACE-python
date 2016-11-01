## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: test case class for PACE project tests
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  13 Jan 2015  CS    Original file
## **************

import random
from unittest import TestCase

DEFAULT_NUM_ITERS = 5
DEFAULT_SIZE = 100

class PACETestCase(TestCase):
    """ Subclass of TestCase with some convenient constants built-in.
    """
    
    def __init__(self, *args):
        super(PACETestCase, self).__init__(*args)
        
        self.num_iters = DEFAULT_NUM_ITERS
        self.size = DEFAULT_SIZE

    def generate_elems(self, min_elem=0, max_elem=1000000000, size=None):
        """ Generate up to size unique integers between
            min_elem and max_elem.
        """
        if size is None:
            size = self.size
        ints = (random.randint(min_elem, max_elem)
                for _ in range(size))
        return set(ints)
