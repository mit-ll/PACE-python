## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Hash node class for VOs
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  28 Jul 2014  ZS    Original file
## **************

from base64 import b64encode, b64decode

from pace.ads.merkle.eq import EqMixin

class HashNode(EqMixin):
    def __init__(self, hval):
        self.hval = hval
    
    def set_parent(self, parent):
        pass

    def serialize(self, depth=0):
        return b64encode(self.hval)

    @staticmethod
    def deserialize(s):
        return b64decode(s)
