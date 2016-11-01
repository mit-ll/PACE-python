## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Abstract class for key management interface
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   18 Dec 2014  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from abc import ABCMeta, abstractmethod

class AbstractPKI(object):
    """Abstract interface that all key management objects
    must match. Should support matching between an identifier
    and keys. 
    """
    __metaclass__= ABCMeta
    
    @abstractmethod
    def __init__(self, *args):
        """
        Arguments:
        *args - user specified arguments necessary for key 
        management. May be information about an LDAP server,
        or some other external key management service.
        """
        pass
    
    @abstractmethod
    def get_profile(self, identifier):
        """
        Arguments:
        identifier - unique to a single user that is used 
        to map between a user and their security profile, which 
        may take the form of an X509 certificate or something
        similar
 
        Returns: profile of user in the form a named tuple,
        specified by particular use case. May contain signing
        or encryption keys, as well as scheme preference.

        Raises PKILookupError if `identifier` is not found
        """
        pass 

class PKILookupError(Exception):
    """ Error to be raised when an identifier is not found in get_profile
    """
    def __init__(self, msg):
        self.msg = msg

class PKIStorageError(Exception):
    """ Error to be raised when an entry to be stored in the PKI is invalid
    """
    def __init__(self, msg):
        self.msg = msg
