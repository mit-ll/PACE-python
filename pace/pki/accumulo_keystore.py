## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CAS
##  Description: Key storage in Accumulo
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  22 Jun 2015  CAS   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from pyaccumulo import Mutation, Range
from types import IntType
from collections import defaultdict

from pace.pki.keystore import AbstractKeyStore, KeyInfo
from pace.common.common_utils import get_single_entry
from pace.pki.abstractpki import PKILookupError, PKIStorageError
from pace.pki.attrusermap import AbstractAttrUserMap
from pace.pki.userattrmap import AbstractUserAttrMap
from pace.common.common_utils import entry_exists

class AccumuloKeyStore(AbstractKeyStore):
    """ An implementation of AbstractKeyStore (see keystore.py) that
        uses an Accumulo instance to store the key wraps.

        Overall design:
        - Index keys by metadata to allow the encryption code to perform
          efficient lookups for {en,de}cryption
        - Key info is essentially a (metadata, userid, attribute, version, 
          keywrap, keylen) tuple
        - Key infos are sorted lexicographically; importantly, this means
          it is possible to search for the most recent version, or for a
          range of versions
        - Since we assume many users but few metadatas, create one table
          per metadata, then one row per user in each of these tables.
    """

    def __init__(self, conn, meta_table='__KEYWRAP_METADATA__',
                             vers_table='__VERSION_METADATA__'):
        """ Init needs the connection that the Accumulo server used to
            store the keys lives on.
        """
        self.conn = conn
        if not conn.table_exists(meta_table):
            conn.create_table(meta_table)
        self.meta_table = meta_table
        if not conn.table_exists(vers_table):
            conn.create_table(vers_table)
        self.vers_table = vers_table

    def insert(self, userid, keyinfo):
        """ Insert a wrapped key into the key store.

            Arguments:
            
            self - the KeyStore object being written to
            userid : string - the ID of the user for whom the key is wrapped
            keyinfo : a KeyInfo tuple containing the key's metadata, attribute,
                      version, keywrap, and key length
        """

        # Table name: metadata
        # Row: userid
        # Column family: attribute
        # Column qualifier: version
        # Visibility field: attribute (non-attr keys visible to all)
        # Value: keywrap
        self.batch_insert(userid, [keyinfo])

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

        if type(vers) is not IntType:
            raise PKILookupError('version to search for must be an integer')

        tabname = metadata

        if not self.conn.table_exists(tabname):
            raise PKILookupError('No such table %s' %tabname)

        row = userid
        cf = attr
        cq = str(vers)

        cell = get_single_entry(self.conn, tabname, row=row, cf=cf, cq=cq)
    
        if cell is not None:
            keywrap, raw_keylen = cell.val.rsplit(',', 1)

            try:
                keylen = int(raw_keylen)
            except ValueError:
                raise PKILookupError('Error: found non-integer key length')
                
            return KeyInfo(attr, vers, metadata, keywrap, keylen)
        else:
            raise PKILookupError('No keywrap found')

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
        
        # Store metadata (i.e. table) names mapping to
        # BatchWriter, Mutation pairs
        writers = {}

        # Also keep a mutation to write to the keywrap metadata table
        # Schema:
        #   Table - self.meta_table
        #   Row   - userid
        #   CF    - attr
        #   CQ    - metadata
        #   vis   - [empty]
        #   value - '1' (dummy value)
        meta_mutation = Mutation(userid)
        # Use a defaultdict to return 0 if the attribute searched for is not
        # found; useful for the call to max() later on. Assumes that all
        # versions are positive.
        maxvers = defaultdict(int)

        for keyinfo in infos:
            if type(keyinfo.vers) is not IntType:
                raise PKIStorageError('versions must be integers')
            if type(keyinfo.keylen) is not IntType:
                raise PKIStorageError('key lengths must be integers')

            metadata = keyinfo.metadata

            if metadata not in writers:
                if not self.conn.table_exists(metadata):
                    self.conn.create_table(metadata)

                writers[metadata] = (self.conn.create_batch_writer(metadata),
                                     Mutation(userid))

            _, mutation = writers[metadata]

            mutation.put(cf=keyinfo.attr,
                         cq=str(keyinfo.vers),
                         cv=keyinfo.attr,
                         val='%s,%s' %(keyinfo.keywrap, str(keyinfo.keylen)))
            
            meta_mutation.put(cf=keyinfo.attr, cq=metadata, val='1')

            # Keep track of the largest version number for each attr metadata
            # pair we've seen so far.
            maxvers[(keyinfo.attr, metadata)] = max(
                maxvers[(keyinfo.attr, metadata)], keyinfo.vers)

        for wr, m in writers.itervalues():
            wr.add_mutation(m)
            wr.close()

        self.conn.write(self.meta_table, meta_mutation)

        # Go through the largest version numbers we found and see if any
        # need to be updated in the version table
        for (attr, metadata), vers in maxvers.iteritems():
            cell = get_single_entry(self.conn, self.vers_table,
                                    row=attr, cf='', cq=metadata)
            if cell:
                try:
                    old_vers = int(cell.val)
                except ValueError:
                    raise PKIStorageError('stored version must be integer')
                
                if old_vers >= vers:
                    continue

            vers_mutation = Mutation(attr)
            vers_mutation.put(cq=metadata, val=str(vers))
            self.conn.write(self.vers_table, vers_mutation)

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

        tabname = metadata

        if not self.conn.table_exists(tabname):
            raise PKILookupError('Error: no such table %s' %tabname)

        if attr is None:
            # Get everything!
            scan_range = Range(srow=userid, erow=userid)
        else:
            # Get only things from the corresponding row
            scan_range = Range(srow=userid, erow=userid, scf=attr, ecf=attr)

        ret = []

        for c in self.conn.scan(tabname, scan_range):
            try:
                vers = int(c.cq)
            except ValueError:
                raise PKILookupException('Retrieved version must be int')

            keywrap, raw_keylen = c.val.rsplit(',', 1)

            try:
                keylen = int(raw_keylen)
            except ValueError:
                raise PKILookupError('Error: found non-integer key length')

            ret.append(KeyInfo(metadata=metadata, attr=c.cf,
                               vers=vers, keywrap=keywrap, keylen=keylen))

        if not ret:
            # If we found no elements, that's an error
            raise PKILookupError(
                'Error: no results found for batch key retrieval')
        else:
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
        # Table name: metadata
        # Row: userid
        # Column family: attribute
        # Column qualifier: version
        # Visibility field: attribute (non-attr keys visible to all)
        # Value: keywrap
        del_keys = self.batch_retrieve(userid, metadata, attr)
        mutation = Mutation(userid)

        for keyinfo in del_keys:
            # Queue deletes of all these cells in a mutation
            mutation.put(cf=attr, cq=str(keyinfo.vers), cv=attr,
                         is_delete=True)

        # Write out the deletes
        self.conn.write(metadata, mutation)

        # Also need to remove this from the metadata store
        # Schema:
        #   Table - self.meta_table
        #   Row   - userid
        #   CF    - attr
        #   CQ    - metadata
        #   vis   - [empty]
        #   value - '1' (dummy value)
        mutation = Mutation(userid)
        mutation.put(cf=attr, cq=metadata, is_delete=True)
        self.conn.write(self.meta_table, mutation)

    def get_metadatas(self, user, attr):
        """ Get all metadatas that a given user has for a particular attribute.

            Arguments:

            self - the KeyStore object to delete elements from
            userid : string - the ID of the user whose metadata is
                     being fetched
            attr : string - the attribute whose metadata is being fetched

            Returns:

            metadatas : string set - a set of metadata strings
        """
        # Scan the keywrap metadata table for the metadatas
        # Row: user
        # Col. Fam: attribute
        raw_metas = self.conn.scan(self.meta_table,
                                   Range(srow=user, erow=user),
                                   cols=[[attr]])

        return set([entry.cq for entry in raw_metas])

    def retrieve_latest_version_number(self, metadata, attr):
        """ Return the most recent version number for the given attribute
            and metadata. 
            
            metadata : string - the metadata of the key version to search for
            attr : string - the attribute to search for

            Returns:

            v_num : int - the version number for the appropriate key

            Raises:

            PKILookupError - if no such version is found, or if the stored
                             value is not an integer
        """
        cell = get_single_entry(self.conn, self.vers_table,
                                row=attr, cf='', cq=metadata)

        if cell is None:
            raise PKILookupError('Cell not found for version lookup')

        try:
            return int(cell.val)
        except ValueError:
            raise PKILookupError('Stored version string does not parse as int')

class AccumuloAttrKeyStore(AccumuloKeyStore, AbstractAttrUserMap, 
                           AbstractUserAttrMap):
    """ Subclass of the AccumuloKeyStore that also keeps track of
        attr -> [user] mappings and user -> [attr] mappings in separate tables, 
        adding & removing mappings where appropriate.

        Schema:
        - The table denoted by the `attr_user_table` instance variable keeps all
          of the attribute -> user mappings. 
          Each row in this table represents a single attribute; each column 
          family in a given row represents a user who has that attribute 
          associated with them.
        - The table denoted by the `user_attr_table` instance variable keeps all
          of the user -> attribute mappings.
          Each row in this table represents a single user; each column family
          in a given row represents an attribute that the user has.
    """
    def __init__(self, conn, meta_table='__KEYWRAP_METADATA__',
                             vers_table='__VERSION_METADATA__',
                             attr_user_table='__ATTR_USER_TABLE__',
                             user_attr_table='__USER_ATTR_TABLE__'):
        super(AccumuloAttrKeyStore, self).__init__(conn, meta_table, vers_table)

        if not self.conn.table_exists(attr_user_table):
            self.conn.create_table(attr_user_table)
        self.attr_user_table = attr_user_table

        if not self.conn.table_exists(user_attr_table):
            self.conn.create_table(user_attr_table)
        self.user_attr_table = user_attr_table

    def batch_insert(self, userid, infos):
        # Do a normal insert
        super(AccumuloAttrKeyStore, self).batch_insert(userid, infos)

        # Also add key information
        # NB: this can also be done inline to avoid iterating twice
        #     though the keystore infos, at the downside of more code
        #     duplication and less modularity.
        for keyinfo in infos:
            if not entry_exists(self.conn, self.attr_user_table,
                                keyinfo.attr, userid):
                #TODO: we could batch these writes for potentially a
                #      little bit more efficiency
                m = Mutation(keyinfo.attr)
                m.put(cf=userid, val='1')
                self.conn.write(self.attr_user_table, m)

            if not entry_exists(self.conn, self.user_attr_table,
                                userid, keyinfo.attr):
                m = Mutation(userid)
                m.put(cf=keyinfo.attr, val='1')
                self.conn.write(self.user_attr_table, m)
                

    def users_by_attribute(self, attr):
        """ Return the list of all users who are currently authorized to
            read data with the given attribute.

            Arguments:

            attr : string - the attribute to query

            Returns:

            users : [string] - a (potentially empty) list of usernames
                    (as strings) that are all authorized to have the given
                    attribute `attr`
        """
        # Scan the attribute-to-user table for the row for this attribute
        raw_users = self.conn.scan(self.attr_user_table,
                                   Range(srow=attr, erow=attr))

        # Grab the column family (where the user is stored) for each entry
        return [entry.cf for entry in raw_users]

    def attributes_by_user(self, userid):
        """ Returns a list of the attributes the given user has.

            Arguments:
            userid (string) - the ID of the user whose attributes to retrieve

            Returns:
            [string] - a (potentially empty) list of the attributes that the 
                given user has 
        """
        # Scan the user-to-attribute table for the row for this user
        raw_attrs = self.conn.scan(self.user_attr_table,
                                    Range(srow=userid, erow=userid))

        # Grab the column family (where the attribute is stored) for each entry
        return [entry.cf for entry in raw_attrs]

    def delete_user(self, attr, user):
        """ Delete a user from the list of users with a given attribute.
            Used for key revocation. 

            Arguments:

            attr : string - the attribute to delete a user from
            user : string - the user to be deleted from attr
        """
        mutation = Mutation(attr)
        mutation.put(cf=user, is_delete=True)
        self.conn.write(self.attr_user_table, mutation)

    def delete_attr(self, userid, attr):
        """ Delete an attribute from the list of attributes a given user has.
            Used for key revocation.

            Arguments:
            userid (string) - the ID of the user whose attribute to delete
            attr (string) - the attribute to delete from the user's list
        """
        mutation = Mutation(userid)
        mutation.put(cf=attr, is_delete=True)
        self.conn.write(self.user_attr_table, mutation)
