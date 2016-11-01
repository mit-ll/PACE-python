## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Interface for skiplist elements & some specific implemetations
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  03 Oct 2014  CS    Original file
## **************


from abc import ABCMeta, abstractmethod


class BaseElem(object):
    """ Abstract superclass for wrapping base Python types into elements
        suitable for insertion into SkipLists. Must be abstract since it
        can't generically define the deserialize method.
    """

    __metaclass__ = ABCMeta

    def __init__(self, key):
        """ This class is a wrapper around the type of keys being stored.
        """
        self.key = key

    def __str__(self):
        return str(self.key)

    def __cmp__(self, other):
        """ Default method for comparing two objects. Assumes
            the key's __cmp__ method is the desired method for
            ordering.
        """
        if self.key < other.key:
            return -1
        elif self.key == other.key:
            return 0
        else:
            assert self.key > other.key
            return 1

    @abstractmethod
    def serialize(self):
        """ Turn the element into a string to transportation over
            a network. Needs to be convertable back into an equivalent
            object with deserialize()
        """

    @abstractmethod
    def deserialize(s):
        """ Turn a string into an element of the implementation class.
            Resulting element needs to serialize to the same original
            string.
        """
        pass

class IntElem(BaseElem):
    def serialize(self):
        return str(self.key)

    @staticmethod
    def deserialize(s):
        return IntElem(int(s))

class StrElem(BaseElem):
    # Elements are strings, so serialize and deserialize operations are
    # the identity.
    def serialize(self):
        return self.key

    @staticmethod
    def deserialize(s):
        return StrElem(s)

class AccumuloKey(object):
    """ Class to use for Accumulo keys to fit Accumulo entries
        into a subclass of BaseElem.
    """
    def __init__(self, row, cf, cq, cv, ts):
        self.row = row
        self.cf = cf
        self.cq = cq
        self.cv = cv
        self.ts = ts

    def __cmp__(self, other):
        if self.row == other.row:
            if self.cf == other.cf:
                if self.cq == other.cq:
                    if self.cv == other.cv:
                        if self.ts == other.ts:
                            return 0
                        else:
                            # timestamps are ordered in the other direction
                            return -1 if self.ts > other.ts else 1
                    else:
                        return -1 if self.cv < other.cv else 1
                else:
                    return -1 if self.cq < other.cq else 1
            else:
                return -1 if self.cf < other.cf else 1
        else:
            return -1 if self.row < other.row else 1

    def serialize(self):
        return ','.join([self.row, self.cf, self.cq, self.cv, self.ts])

class AccumuloEntry(BaseElem):
    
    keyclass = AccumuloKey
    
    def __init__(self, key, val):
        self.key = key
        self.val = val

    def serialize(self):
        return ','.join([self.key.serialize(), self.val])

    @classmethod
    def deserialize(cls, s):
        i = 0
        j = s.find(',', i)
        row = s[i:j]

        i = j+1
        j = s.find(',', i)
        cf = s[i:j]
            
        i = j+1
        j = s.find(',', i)
        cq = s[i:j]
            
        i = j+1
        j = s.find(',', i)
        cv = s[i:j]
            
        i = j+1
        j = s.find(',', i)
        ts = s[i:j]
            
        val = s[j+1:]
            
        return AccumuloEntry(cls.keyclass(row, cf, cq, cv, ts), val)
