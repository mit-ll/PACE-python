## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Empty node class for VOs
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  28 Jul 2014  ZS    Original file
## **************

from pace.ads.merkle.eq import EqMixin

class EmptyNode(EqMixin):
    def __init__(self):
        pass

    def set_parent(self, parent):
        pass
    
    def serialize(self, depth=0):
        return 'None'

    @staticmethod
    def deserialize(s):
        if s == 'None':
            return EmptyNode()
        else:
            raise Error('Error in deserialization:\nExpected "None", got %s' %s)
