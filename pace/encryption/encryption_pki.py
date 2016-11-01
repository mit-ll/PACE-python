## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Class for encryption key management
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   10 Dec 2014  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from Crypto.PublicKey import RSA
from base64 import b64encode
from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options

from pace.pki.keystore import KeyInfo
from pace.pki.abstractpki import PKILookupError
from pace.pki.accumulo_keystore import AccumuloKeyStore
from pace.common.fakeconn import FakeConnection 

import pace.pki.key_wrap_utils as key_utils
from pace.encryption.enc_classes import AES_ALGORITHMS, VIS_ALGORITHMS

#creating cache where all the contents are stored within local memory 
cache_opts = {
     'cache.type': 'memory',
    }
cache = CacheManager(**parse_cache_config_options(cache_opts))

### NB: For functions decorated with:  
###
###    @cache.cache('key',expire=3600)   
###
### 
### Objects are cached for a paritcular set of arguments 
### when a function call is made - in this particular example
### it will be for an hour. Thus when a call is made again, 
### with the same set of arguments, the cached value is 
### returned in lieu of another execution of the method.
###
### NB: There exists one copy of the cache for each class. This means
### that two instances of the cache, that may have different
### instance variables, will use the same copy of the cache. In 
### this particular case, two copies of the PKI object that refer
### to different users on the same system or users who have more
### than one key store to connect to cannot be supported without
### further modification. For flexibility, we include both a plain key
### store and a cached subclass of it.

class EncryptionPKIBase(object):

    def __init__(self, *args):
        pass
    
    def get_key(self, algorithm):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the current key, triggers
                    PKILookupError if the algorithm is not part
                    of AES_ALGORITHMS
        
        Returns:
            Current key for (userid, algorithm) tuple
        
        Raises:
            PKILookupError if the key cannot be found for the
            (userid, algorithm) pairing. 
        """
        pass
    
    def get_current_key(self, algorithm):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the key, triggers
                    PKILookupError if the algorithm is not part
                    of AES_ALGORITHMS
        
        Returns:
            (Most current key for (userid, algorithm) tuple, version)
        
        Raises:
            PKILookupError if the key cannot be found for the
            (userid, algorithm) tuple. 
            
        """
        pass
    
    
    def get_attribute_key(self, algorithm, attribute):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the current key, triggers
                    PKILookupError if the algorithm is, not part
                    of VIS_ALGORITHMS 
        attribute - Attribute for which to rereive the current key for,
                    currently does not support looking for versions. 
        
        Returns:
            Current key for (userid, algorithm, attribute) triple 
            
        Raises:
            PKILookupError if the key cannot be found for the 
            (userid, algorithm, attribute) tuple.
        """
        pass
    
    def get_current_attribute_key(self, algorithm, attribute):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the key, triggers
                    PKILookupError if the algorithm is not part
                    of AES_ALGORITHMS 
        attribute - Attribute for which to retrieve the key for
        
        Returns:
        
            (Most current key for (userid, algorithm, attribute) tuple, version)
        
        Raises:
            PKILookupError if the key cannot be found for the
            (userid, algorithm, attribute) tuple. 
            
        """
        pass
    
    
class EncryptionPKIAccumulo(EncryptionPKIBase):
    
    """
    PKI object for encryption that uses an AccumuloKeyStore as a 
    backend. Matches the EncryptionPKIBase interface. 
    
    Instance variables:
    _acc_keystore - a handle on an instance of an Accumulo Keystore to 
            retrieve keys from
    _user_id - the string representing the user's identity
    _rsa_key - RSA key object produced by RSA.generate(). 
    
    """
    
    def __init__(self, conn, user_id, rsa_key):
        """
        Arguments:
        conn - (Accumulo connection) Connection to the Accumulo
                instance that is being used as the Keystore.
                NB: This represents the authentication for the user
                to be accessing the keystore - including what
                keys they should be able to access based on visability
                labels.
        user_id - (string) String that is used in the Keystore to
                identify the particular user
        rsa_key - (Crypto.PublicKey.RSA) Key object to wrap/unwrap keys
                with. TODO: create a loader from a file for RSA keys
                
        """
        self._acc_keystore = AccumuloKeyStore(conn)
        self._user_id = user_id
        self._rsa_key = rsa_key
    
    def get_current_key(self, algorithm):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the key for, triggers
                    PKILookupError if the algorithm is not part
                    of AES_ALGORITHMS
        
        Returns:
            (Most current key for (userid, algorithm) tuple, version)
        
        Raises:
            PKILookupError if the key cannot be found for the
            (userid, algorithm) tuple. 
            
        """      
        #get the keys
        try:
            key_wrap = self._acc_keystore.retrieve_latest_version(self._user_id, 
                                                          algorithm,
                                                          '')
        except PKILookupError:
            raise PKILookupError("User " + self._user_id + " with algorithm " +\
                                  algorithm + " is not present in keystore.")
        
        #unwrap the key
        return (key_utils.unwrap_key(key_wrap.keywrap, self._rsa_key), key_wrap.vers)
     
    def get_current_attribute_key(self, algorithm, attribute):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the key for, triggers
                    PKILookupError if the algorithm is not part
                    of AES_ALGORITHMS 
        attribute - (string) Attribute for which to retrieve the key for
        
        Returns:
            (Most current key for (userid, algorithm, attribute) tuple, version)
        
        Raises:
            PKILookupError if the key cannot be found for the
            (userid, algorithm, attribute) tuple. 
            
        """     
        #get the keys
        try:
            key_wrap = self._acc_keystore.retrieve_latest_version(self._user_id, 
                                                          algorithm,
                                                          attribute)
        except PKILookupError as ple:
            raise PKILookupError(
                "User %s with algorithm %s and attribute %s is not present in keystore."
                %(self._user_id, algorithm, attribute))
        
        #unwrap the key
        return (key_utils.unwrap_key(key_wrap.keywrap, self._rsa_key), key_wrap.vers)
    
    
    def get_key(self, algorithm, version=1):
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the key for, triggers
                    PKILookupError if the algorithm is not part
                    of AES_ALGORITHMS
        version - (int) version of key to grab, defaults to 1
        
        Returns:
            Key for (userid, algorithm, version) tuple
        
        Raises:
            PKILookupError if the key cannot be found for the
            (userid, algorithm, version) tuple. 
            
        """ 
        #get the keys
        try:
            key_wrap = self._acc_keystore.retrieve(self._user_id, 
                                               '',
                                               version,
                                               algorithm)
        except PKILookupError:
            raise PKILookupError("User " + self._user_id + " with algorithm " +\
                                  algorithm + " is not present in keystore.")
        #unwrap the key
        return key_utils.unwrap_key(key_wrap, self._rsa_key)

    def get_attribute_key(self, algorithm, attribute, version=1): 
        """
        Arguments:
        algorithm - (string) Name of algorithm for which the user
                    wishes to retrieve the current key for, triggers
                    PKILookupError if the algorithm is not part
                    of VIS_ALGORITHMS 
        attribute - (string) Attribute for which to retrieve the key for
        version - (int)version of key to grab, defaults to 1
        
        Returns:
            Key for (userid, algorithm, attribute, version) tuple
            
        Raises:
            PKILookupError if the key cannot be found for the 
            (userid, algorithm, attribute, version) tuple.
            
        """ 
        #get the keys
        try:
            key_wrap = self._acc_keystore.retrieve(self._user_id, 
                                               attribute,
                                               version,
                                               algorithm)
        except PKILookupError as ple:
            raise PKILookupError(
                "User %s with algorithm %s and attribute %s is not present in keystore."
                %(self._user_id, algorithm, attribute))
        #unwrap the key
        return key_utils.unwrap_key(key_wrap, self._rsa_key)


class CachingEncryptionPKIMixin(object):
    """
    Mixin class that implements caching the results for an hour 
    """

    @cache.cache('key',expire=3600)  
    def get_current_key(self, algorithm):
        return super(CachingEncryptionPKIMixin, self).get_current_key(algorithm)
     
    @cache.cache('key',expire=3600)  
    def get_current_attribute_key(self, algorithm, attribute):
        return super(CachingEncryptionPKIMixin, self).get_current_attribute_key(algorithm, attribute)

    @cache.cache('key',expire=3600)  
    def get_key(self, algorithm, version=1):
        return super(CachingEncryptionPKIMixin, self).get_key(algorithm, version)

    @cache.cache('key',expire=3600)  
    def get_attribute_key(self, algorithm, attribute, version=1): 
        return super(CachingEncryptionPKIMixin, self).get_attribute_key(algorithm, attribute, version)
    
class CachingEncryptionPKIAccumulo(CachingEncryptionPKIMixin, EncryptionPKIAccumulo):
    """
    Same as EncryptionPKIAccumulo, but caches results for an hour
    """
    pass

class DummyEncryptionPKI(EncryptionPKIAccumulo):
 
    """
    Sample PKI object for encryption that uses an AccumuloKeyStore as a 
    backend. Contains hard-code key values. 
    
    Used primarily for testing. Matches the EncryptionPKIAcummulo interface. 
    """

    
    def __init__(self, conn=None, terms=None):   
        """
        Arguments:
        
        conn - connection to AccumuloKeyStore. Can be connection to 
               a live Accumulo instance. Defaults to a FakeConnection()
        terms - (list) attributes to insert keys for - can be 'a'-'e'.
                Allows for the creation of a 'limited' PKI for
                demos and testing. Defaults to ['a','b',c','d','e']
                
        Note: For key names we recommend to use a combination of 
        the algorithm being used and the specific table name, 
        along the lines of AES_CBC__table__, not the names
        listed below.
               
        """
        # Initialize the new FakeConnection here so Python doesn't
        # create a new hidden global variable for the default argument
        if conn is None:
            conn = FakeConnection()

        if terms is None:
            terms = ['a','b','c','d','e']

        
        SYM_KEYS_TO_INSERT = {"table1": [(1,b'Sixteen by1e key')],
                              "Pycrypto_AES_CFB": [(1,b'Sixteen by1e key'),
                                                   (2,b'Sixteen by2e key'),
                                                   (3,b'Sixteen by3e key')],
                              "Pycrypto_AES_CBC": [(1,b'Sixteen bb1e key')],
                              "Pycrypto_AES_OFB": [(1,b'Sixteen bc1e key'),
                                                   (2,b'Sixteen bc2e key'),
                                                   (3,b'Sixteen bc3e key')],
                              "Pycrypto_AES_CTR": [(1,b'Sixteen bd1e key')],
                              "Pycrypto_AES_GCM": [(1,b'Sixteen be1e key'),
                                                   (2,b'Sixteen be2e key')],
                              "Pycrypto_AES_SIV": [(1, b'Sixteen byte keySixteen byte key')]}

        ATTR_KEYS_TO_INSERT={
                  "VIS_Identity" : [('a', 1, b'Sixteen bate k1y'),
                                    ('a', 2, b'Sixteen bate k2y'),
                                    ('a', 3, b'Sixteen bate k3y'),
                                    ('b', 1, b'Sixteen bbte k1y'),
                                   ('b', 2, b'Sixteen bbte k2y'),
                                   ('c', 1, b'Sixteen bcte key'), 
                                   ('d', 1, b'Sixteen bdte k1y'),
                                   ('d', 2, b'Sixteen bdte k2y'),
                                   ('d', 3, b'Sixteen bdte k3y'),
                                   ('d', 4, b'Sixteen bdte k4y'),
                                   ('e', 1, b'Sixteen bete key')],
                  "VIS_AES_CFB" : [('a', 1, b'Sixteen bate key'),
                                   ('b', 2, b'Sixteen bbte k2y'),
                                   ('b', 3, b'Sixteen bbte k3y'),
                                   ('c', 1, b'Sixteen bcte key'),
                                   ('d', 2, b'Sixteen bdte key'),
                                   ('d', 3, b'Sixteen bdte key'),
                                   ('d', 4, b'Sixteen bdte key'),
                                   ('d', 5, b'Sixteen bdte key'),
                                   ('e', 1, b'Sixteen bete key')],
                  "VIS_AES_CBC" : [('a', 1, b'Sixteen bate k1y'),
                                   ('a', 2, b'Sixteen bate k2y'),
                                   ('a', 3, b'Sixteen bate k3y'),
                                   ('a', 5, b'Sixteen bate k5y'),
                                   ('b', 1, b'Sixteen bbte k1y'),
                                   ('b', 2, b'Sixteen bbte k2y'),
                                   ('b', 3, b'Sixteen bbte k3y'),
                                   ('c', 3, b'Sixteen bcte k3y'),
                                   ('c', 4, b'Sixteen bcte k4y'),
                                   ('c', 5, b'Sixteen bcte k5y'),
                                   ('d', 1, b'Sixteen bdte k1y'),
                                   ('d', 2, b'Sixteen bdte k2y'),
                                   ('e', 1, b'Sixteen bete key')],
                  "VIS_AES_OFB" : [('a', 2, b'Sixteen bate k2y'),
                                   ('a', 3, b'Sixteen bate k3y'),
                                   ('a', 4, b'Sixteen bate k4y'),
                                   ('a', 5, b'Sixteen bate k5y'),
                                   ('b', 1, b'Sixteen bbte k1y'),
                                   ('b', 2, b'Sixteen bbte k2y'),
                                   ('b', 3, b'Sixteen bbte k3y'),
                                   ('b', 4, b'Sixteen bbte k4y'),
                                   ('c', 2, b'Sixteen bcte k2y'),
                                   ('c', 3, b'Sixteen bcte k3y'),
                                   ('d', 2, b'Sixteen bdte key'),
                                   ('e', 1, b'Sixteen bete key')],
                  "VIS_AES_CTR" : [('a', 1, b'Sixteen bate k1y'),
                                   ('a', 3, b'Sixteen bate k3y'),
                                   ('a', 4, b'Sixteen bate k4y'),
                                   ('b', 1, b'Sixteen bbte k1y'),
                                   ('b', 2, b'Sixteen bbte k3y'),
                                   ('b', 3, b'Sixteen bbte k3y'),
                                   ('c', 2, b'Sixteen bcte key'),
                                   ('d', 1, b'Sixteen bdte key'),
                                   ('e', 3, b'Sixteen bete k3y'),
                                   ('e', 5, b'Sixteen bete k5y')],
                  "VIS_AES_GCM" : [('a', 1, b'Sixteen bate key'),
                                   ('b', 2, b'Sixteen bbte key'),
                                   ('c', 1, b'Sixteen bcte k1y'),
                                   ('c', 2, b'Sixteen bcte k2y'),
                                   ('c', 3, b'Sixteen bcte k3y'),
                                   ('d', 1, b'Sixteen bdte k1y'),
                                   ('d', 2, b'Sixteen bdte k2y'),
                                   ('d', 4, b'Sixteen bdte k4y'),
                                   ('e', 5, b'Sixteen bete key')]}

        #remove existing symmetric key tables
        for metadata in SYM_KEYS_TO_INSERT.keys():
            if conn.table_exists(metadata):
                conn.delete_table(metadata)

        #remove existing attribute key tables
        for metadata in ATTR_KEYS_TO_INSERT.keys():
            if conn.table_exists(metadata):
                conn.delete_table(metadata)
        
        #generate RSA key    
        RSA_key = RSA.generate(3072)
        super(DummyEncryptionPKI,self).__init__(conn, 'one', RSA_key)
        
        #add symmetric keys
        for (algorithm, keys) in SYM_KEYS_TO_INSERT.iteritems():
            for ver, key in keys:
                self._acc_keystore.insert(str(self._user_id),
                                      KeyInfo(attr='',
                                              vers=ver,
                                              metadata=algorithm,
                                              keywrap=key_utils.wrap_key(key, self._rsa_key),
                                              keylen=len(key)))
                       
        #add attribute keys
        keys_to_insert = []
        for (algorithm, keys) in ATTR_KEYS_TO_INSERT.iteritems():
            for attr, vers, key in keys:
                if attr in terms:
                    keys_to_insert.append(
                        KeyInfo(attr=attr,
                            vers=vers,
                            metadata=algorithm,
                            keywrap=key_utils.wrap_key(key, self._rsa_key),
                            keylen=len(key)))
        
        self._acc_keystore.batch_insert(str(self._user_id), keys_to_insert)
        
class DummyCachingEncryptionPKI(CachingEncryptionPKIMixin, DummyEncryptionPKI):
    """
    Same as DummyEncryptionPKI, but caches results for an hour
    """
    pass
