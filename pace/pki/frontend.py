## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CAS
##  Description: Front-end for easily viewing the key store
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  10 Aug 2015  CAS   Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

DEFAULT_META = 'VIS_AES_CFB'
DEFAULT_USER = 'user1'

from base64 import b64encode

class KeyStoreFrontEnd(object):

    def __init__(self, keystore):
        self.keystore = keystore

    def view(self, metadata=None, user=None, attr=None):
        """ Provide a view into the key store, showing the key information
            for the given metadata, user, attribute, and version.

            If no metadata or user is specified, the default table
            and/or username will be used (see DEFAULT_META and DEFAULT_USER
            above).

            If no attribute is specified, displays all entries
            that match the given user and metadata.
        """

        # Check arguments & print usage information

        if metadata is None:
            print 'No metadata specified'
            print 'Using default metadata', DEFAULT_META
            print
            
            metadata = DEFAULT_META
        else:
            print 'Showing results for metadata', metadata
            print

        if user is None:
            print 'No username specified'
            print 'Using default username', DEFAULT_USER
            print

            user = DEFAULT_USER
        else:
            print 'Showing results for user', user
            print

        if attr is None:
            print 'No attribute specified'
            print 'Showing all attributes'
            print
        else:
            print 'Showing results for attribute', attr
            print

        # Fetch & display keys

        print 'Showing key information for user:', user
        print 'Metadata being used:', metadata
        print '========================================'
        print

        keys = self.keystore.batch_retrieve(userid=user, metadata=metadata,
                                            attr=attr)

        for keyinfo in keys:
            print 'Key attribute:', keyinfo.attr
            print 'Key version  :', keyinfo.vers
            print 'Keywrap:'
            print b64encode(keyinfo.keywrap)
            print
            print '----------------------------------------'
            print

        print 'End key display.'

    
        


