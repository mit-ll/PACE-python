## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CAS
##  Description: Key storage interface & basic implementations
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  18 Jun 2015  CAS   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from abc import ABCMeta, abstractmethod
from collections import namedtuple, defaultdict
from types import IntType

from pace.pki.abstractpki import PKILookupError, PKIStorageError

# Object to store all associated information for keys.
# Used in AbstractKeyStore.batch_insert()
KeyInfo = namedtuple('KeyInfo', 'attr, vers, metadata, keywrap, keylen')
""" attr : string - the attribute for the key being inserted, if any.
           If this field is the empty string '', it denotes that this
           is not an attribute key.
    vers : int - the version number for the key
    metadata : string - metadata about the key (e.g. the mode of
               operation with which it is intended to be used)
    keywrap : string - the wrapped key to insert into the key store
    keylen : int - the length of the key wrapped in keywrap in bytes (NOT bits)
"""

class AbstractKeyStore(object):
    """ Abstract interface for key stores to implement.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def insert(self, userid, keyinfo):
        """ Insert a wrapped key into the key store.

            Arguments:
            
            self - the KeyStore object being written to
            userid : string - the ID of the user for whom the key is wrapped
            keyinfo : a KeyInfo tuple
        """
        pass

    def retrieve(self, userid, attr, vers, metadata):
        """ Attempt to retrieve a wrapped key from the key store. Similar to
            retrieve_info(), but returns only the keywrap.

            Arguments:
            
            self - the KeyStore object being retrieved from
            userid : string - the ID of the user for whom the key is wrapped
            attr : string - the attribute for the key being inserted, if any.
                   If this field is the empty string '', it denotes that this
                   is not an attribute key.
            vers : string - the version identifier for the key
            metadata : string - metadata about the key (e.g. the mode of
                       operation with which it is intended to be used)

            Returns:

            keywrap - the wrapped key corresponding to the provided info.

            Raises:

            PKILookupError - when no key is found
        """
        # simple default implementation
        return self.retrieve_info(userid, attr, vers, metadata).keywrap

    @abstractmethod
    def retrieve_info(self, userid, attr, vers, metadata):
        """ Attempt to retrieve a wrapped key from the key store.

            Arguments:
            
            self - the KeyStore object being retrieved from
            userid : string - the ID of the user for whom the key is wrapped
            attr : string - the attribute for the key being inserted, if any.
                   If this field is the empty string '', it denotes that this
                   is not an attribute key.
            vers : string - the version identifier for the key
            metadata : string - metadata about the key (e.g. the mode of
                       operation with which it is intended to be used)

            Returns:

            keyinfo - the KeyInfo object corresponding to the provided
                      values

            Raises:

            PKILookupError - when no key is found
        """
        pass

    @abstractmethod
    def batch_insert(self, userid, infos):
        """ Add all of a user's attribute keys into the key store at once,
            to avoid the overhead of repeated individual insertions.

            Arguments:

            self - the KeyStore object being written to
            userid : string - the ID of the user whose keys these are
            infos : [KeyInfo] - a list of KeyInfo objects (that is,
                    (attr, vers, metadata, keywrap, keylen) tuples) to be
                    inserted into the key store in batches. The batching
                    method is left up to the specific implementation, and
                    ideally would be faster than inserting each tuple
                    individually.
        """
        pass

    @abstractmethod
    def batch_retrieve(self, userid, metadata, attr=None):
        """ Fetch all of a user's keys at once. Optionally, fetch only their
            keys either for a specified attribute or with no attribute at all.
            
            Arguments:

            self - the KeyStore object being read from
            userid : string - the ID of the user whose keys to fetch
            metadata : string - the metadata of the keys to search for
            attr : optional string - the attribute to search for. Default
                   value: None. If this argument is None, this method should
                   return all of the given user's keys. If this argument is
                   the empty string, it should return that user's non-attribute
                   keys. If this argument is a non-empty string, it should
                   return all of that user's keys for that attribute, including
                   all versions and metadata options.

            Returns:

            [KeyInfo] - a non-empty list of KeyInfo objects (that is, 
            (attr, vers, metadata, keywrap, keylen) tuples). If the attr
            argument was None, the attr field of each tuple will be the
            attribute corresponding to the returned version, metadata, and
            keywrap; otherwise, the attr field of each tuple will be equal to
            the attr argument.

            Raises:

            PKILookupError - if there is no information to be returned
        """
        pass

    @abstractmethod
    def remove_revoked_keys(self, userid, metadata, attr):
        """ Delete all stored key versions corresponding to the given
            revoked userid, metadata, and attribute.

            Arguments:

            self - the KeyStore object to delete elements from
            userid : string - the ID of the user whose keys are being deleted
            metadata : string - the metadata of the keys to delete
            attr : string - the attribute of the keys to delete
        """
        pass

    @abstractmethod
    def get_metadatas(self, user, attr):
        """ Get all metadatas that a given user has for a given attribute.

            Arguments:

            self - the KeyStore object to delete elements from
            userid : string - the ID of the user whose metadata is
                     being fetched
            attr : string - the attribute whose metadata is being fetched

            Returns:

            metadatas : string set - a set of metadata strings
        """
        pass

    def retrieve_latest_version(self, userid, metadata, attr):
        """ Fetch the latest key for the given user, attribute,
            and metadata. "Latest" here means that the integer that the
            version contains has the greatest magnitude (e.g. '10' is
            more recent than '2' because 10 > 2 even though '2' > '10').
            
            self - the KeyStore object being read from
            userid : string - the ID of the user whose keys to fetch
            metadata : string - the metadata of the keys to search for
            attr : string - the attribute to search for.

            Returns:

            KeyInfo - the KeyInfo object for the appropriate key.

            Raises:

            PKILookupError - if no such key is found.
        """
        vers = self.retrieve_latest_version_number(metadata, attr)
        return self.retrieve_info(userid, attr, vers, metadata)

    @abstractmethod
    def retrieve_latest_version_number(self, metadata, attr):
        """ Return the most recent version number for the given attribute
            and metadata. 
            
            self - the KeyStore object being read from
            metadata : string - the metadata of the key version to search for
            attr : string - the attribute to search for

            Returns:

            v_num : int - the version number for the appropriate key

            Raises:

            PKILookupError - if no such key is found
        """
        pass


class DummyKeyStore(AbstractKeyStore):
    
    def __init__(self):
        self.store = {}
        # Use a default dict for vnums so all versions start at 0; this
        # assumes all real versions are positive
        self.vnums = defaultdict(int)
        self.metas = {}

    def insert(self, userid, keyinfo):
        """ Insert a wrapped key into the key store.

            Arguments:
            
            self - the KeyStore object being written to
            userid : string - the ID of the user for whom the key is wrapped
            keyinfo : a KeyInfo tuple
        """

        if type(keyinfo.vers) is not IntType:
            raise PKIStorageError('version must be an integer')

        metadata = keyinfo.metadata

        # Store things by self.store[metadata][userid][attr][vers] => keywrap
        # Need to initialize stores first in case they are empty
        if metadata not in self.store:
            self.store[metadata] = {}

        metamap = self.store[metadata]

        if userid not in metamap:
            metamap[userid] = {}

        usermap = metamap[userid]

        if keyinfo.attr not in usermap:
            usermap[keyinfo.attr] = {}

        attrmap = usermap[keyinfo.attr]
        attrmap[keyinfo.vers] = keyinfo.keywrap, keyinfo.keylen

        if (userid, keyinfo.attr) not in self.metas:
            self.metas[(userid, keyinfo.attr)] = set([])

        self.metas[(userid, keyinfo.attr)].add(keyinfo.metadata)
        self.vnums[(keyinfo.attr, metadata)] = max(
            self.vnums[(keyinfo.attr, metadata)], keyinfo.vers)

    def retrieve_info(self, userid, attr, vers, metadata):
        """ Attempt to retrieve a wrapped key from the key store.

            Arguments:
            
            self - the KeyStore object being retrieved from
            userid : string - the ID of the user for whom the key is wrapped
            attr : string - the attribute for the key being retrieved, if any.
                   If this field is the empty string '', it denotes that this
                   is not an attribute key.
            vers : string - the version identifier for the key
            metadata : string - metadata about the key (e.g. the mode of
                       operation with which it is intended to be used)

            Returns:

            keyinfo - the KeyInfo object corresponding to the provided
                      values

            Raises:

            PKILookupError - when no key is found
        """

        try:
            keywrap, keylen = self.store[metadata][userid][attr][vers]
            return KeyInfo(attr, vers, metadata, keywrap, keylen)
        except KeyError:
            raise PKILookupError('No key found in lookup')

    def batch_insert(self, userid, infos):
        """ Add all of a user's attribute keys into the key store at once,
            to avoid the overhead of repeated individual insertions.

            Arguments:

            self - the KeyStore object being written to
            userid : string - the ID of the user whose keys these are
            keywraps : [(string, string, string, string)] - a list of
                   (attr, vers, metadata, keywrap, keylen) KeyInfos to be
                   inserted into the key store in batches. The batching method 
                   is left up to the specific implementation, and ideally would
                   be faster than inserting each tuple individually.

            Raises:

            PKIStorageError - if the key info is not properly constructed
        """

        # This is a dummy key store, so just insert them all separately
        for keyinfo in infos:
            self.insert(userid, keyinfo)

    def batch_retrieve(self, userid, metadata, attr=None):
        """ Fetch all of a user's keys at once. Optionally, fetch only their
            keys either for a specified attribute or with no attribute at all.
            
            Arguments:

            self - the KeyStore object being read from
            userid : string - the ID of the user whose keys to fetch
            metadata : string - the metadata of the keys to search for
            attr : optional string - the attribute to search for. Default
                   value: None. If this argument is None, this method should
                   return all of the given user's keys. If this argument is
                   the empty string, it should return that user's non-attribute
                   keys. If this argument is a non-empty string, it should
                   return all of that user's keys for that attribute, including
                   all versions and metadata options.

            Returns:

            [KeyInfo] - a non-empty list of KeyInfo objects (that is, 
            (attr, vers, metadata, keywrap, keylen) tuples). If the attr
            argument was None, the attr field of each tuple will be the
            attribute corresponding to the returned version, metadata, and
            keywrap; otherwise, the attr field of each tuple will be equal to
            the attr argument.

            Raises:

            PKILookupError - if there is no information to be returned
        """

        try:
            metamap = self.store[metadata]
        except KeyError:
            raise PKILookupError('no metadata table found')

        try:
            usermap = metamap[userid]
        except KeyError:
            raise PKILookupError('No such user %s' %userid)

        ret = []

        if attr is None:
            # Return all attributes for this user

            for innerattr, attrmap in usermap.iteritems():
                for vers, (keywrap, keylen) in attrmap.iteritems():
                    ret.append(
                        KeyInfo(innerattr, vers, metadata, keywrap, keylen))
        else:
            # Return just this attribute
            try:
                attrmap = usermap[attr]
            except KeyError:
                raise PKILookupError('No such attribute %s' %attr)

            for vers, (keywrap, keylen) in attrmap.iteritems():
                ret.append(KeyInfo(attr, vers, metadata, keywrap, keylen))
            
        if not ret:
            raise PKILookupError('no key wraps to return')

        return ret

    def remove_revoked_keys(self, userid, metadata, attr):
        """ Delete all stored key versions corresponding to the given
            revoked userid, metadata, and attribute.

            Arguments:

            self - the KeyStore object to delete elements from
            userid : string - the ID of the user whose keys are being deleted
            metadata : string - the metadata of the keys to delete
            attr : string - the attribute of the keys to delete
        """
        try:
            self.store[metadata][userid][attr] = {}
        except KeyError:
            pass

        try:
            self.metas[(userid, attr)].remove(metadata)
        except KeyError:
            pass

    def get_metadatas(self, user, attr):
        """ Get all metadatas that a given user and attribute have.

            Arguments:

            self - the KeyStore object to delete elements from
            userid : string - the ID of the user whose metadata is
                     being fetched
            attr : string - the attribute whose metadata is being fetched

            Returns:

            metadatas : string set - a set of metadata strings
        """
        try:
            return set([x for x in self.metas[(user, attr)]])
        except KeyError:
            return []

    def retrieve_latest_version_number(self, metadata, attr):
        """ Return the most recent version number for the given attribute
            and metadata. 
            
            metadata : string - the metadata of the key version to search for
            attr : string - the attribute to search for

            Returns:

            v_num : int - the version number for the appropriate key

            Raises:

            PKILookupError - if no such key is found
        """
        if (attr, metadata) not in self.vnums:
            raise PKILookupError('Key not found for latest version lookup')
        
        return self.vnums[(attr, metadata)]
