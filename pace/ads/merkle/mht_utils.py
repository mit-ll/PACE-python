## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Merkle hash tree utility functions
##               (that server & client can run)
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Jul 2014  ZS    Original file
## **************

from hashlib import sha256

class MHTUtils(object):
    @staticmethod
    def hash(elem):
        return sha256(bytes(elem)).digest()

    @staticmethod
    def merge_hashes(h1, h2):
        return sha256(h1 + h2).digest()

    @staticmethod
    def verify(root_hval, elem, proof):
        """ Arguments:
            root_hval - the hash value stored at the root of the MHT
            elem - the elem that is (allegedly) in the MHT
            proof - the alleged proof that elem is in the MHT

            Returns:
            True if proof is a proof that elem is in the MHT with root_hval
            False otherwise
        """
        hval = MHTUtils.hash(elem)

        for is_left, other_side in proof:
            if is_left:
                hval = MHTUtils.merge_hashes(hval, other_side)
            else:
                hval = MHTUtils.merge_hashes(other_side, hval)

        return hval == root_hval

