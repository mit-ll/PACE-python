## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Contains exceptions for encryption code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   10 Aug 2015  ATLH    Original file 
## **************

class EncryptionException(Exception):
    """ Exception raised when unable to encrypt.
        
        Attributes:
            msg - error message for situation
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg
    
class DecryptionException(Exception):
    """ Exception raised when unable to decrypt.
        
        Attributes:
            msg - error message for situation
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg