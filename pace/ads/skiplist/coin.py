## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Coin toss classes with various extra functionalities
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  19 Aug 2014  CS    Original file
## **************

import random
from collections import deque

class BaseCoin(object):
    """ Provides basic coin-toss functionality: uses the random module to
        'flip' a 'coin', returning either True or False with equal probability.

        NB: I believe the entropy used by the random module is low-quality, so
        this should only be used for non-security-required operations, such
        as determining the structure of a random skip list.
    """
    def flip(self, *args):
        return random.randint(0,1) == 1

class RecordedPrefixCoin(BaseCoin):
    def __init__(self, prefix):
        self.record = []
        self.prefix = deque(prefix)

    def flip(self, *args):
        if self.prefix:
            bit = self.prefix.popleft()
            self.record.append(bit)
            return bit
        else:
            bit = super(RecordedPrefixCoin, self).flip()
            self.record.append(toss)
            return bit

# Actually, we just need the client to record, and the server to be able to
# access a prefix, so we can split up these functionalities

class RecordedCoin(BaseCoin):
    """ Acts like a BaseCoin, but also records the outputs it produced, to be
        used later if needed.
    """
    def __init__(self):
        self.record = []

    def flip(self, *args):
        bit = super(RecordedCoin, self).flip()
        self.record.append(bit)
        return bit

    def read(self):
        """ Read the record of the flips so far, then reset it to be empty.
        """
        tmp = self.record
        self.record = []
        return tmp

class PrefixCoin(BaseCoin):
    """ Acts like a base coin, but first uses the provided list of boolean
        values, switching to the random module once it runs out of values from
        the list to use.
    """
    def __init__(self, prefix):
        self.prefix = deque(prefix)

    def flip(self, *args):
        if self.prefix:
            bit = self.prefix.popleft()
            return bit
        else:
            bit = super(PrefixCoin, self).flip()
            return bit

    def extend(self, suffix):
        """ Extend 'self' with the elements in 'suffix', to be used after
            the ones already contained in the prefix.
        """
        self.prefix.extend(suffix)

# Also useful for benchmarking---coins that start from a specific seed

class SeededCoin(BaseCoin):
    """ Acts like a base coin, but first seeds the random module with a given
        seed. Each call to flip() then restores the previous random state,
        computes the next bit, and stores the resulting state.
    """
    def __init__(self, seed):
        random.seed(seed)
        self.state = random.getstate()

    def flip(self, *args):
        random.setstate(self.state)
        bit = super(SeededCoin, self).flip()
        self.state = random.getstate()
        return bit

    def reseed(self, seed):
        random.seed(seed)
        self.state = random.getstate()

class HashCoin(BaseCoin):
    """ Iteratively computes the hash of each base element to compute the coin
        flip of each node. Inherently stateful & dependent on how skiplists
        are structured.

        The value returned is False if the least-significant bit of the hash
        value is 0, and True if the least-significant bit is 1.
    """

    def flip(self, elem_hash, *args):
        return (ord(elem_hash[-1]) % 2) == 1
