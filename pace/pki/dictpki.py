## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Abstract class for key management interface
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   19 Dec 2014  CS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from pace.pki.abstractpki import AbstractPKI

class DictPKI(AbstractPKI):
    def __init__(self, dictionary, tuple_class):
        self.dictionary = dictionary
        self.tuple_class = tuple_class

    def get_profile(self, identifier):
        return self.tuple_class(*self.dictionary[identifier])
