## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Objects to keep track of global constants for signatures
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  06 Jan 2015  CS    Original file
## **************

import string
import logging

import ConfigParser
from abc import abstractmethod, ABCMeta
from collections import namedtuple
from pyaccumulo import Mutation, Range, Cell

# Named tuple for signed entries
SignedEntry = namedtuple('SignedEntry', 'cell_string, metadata, sig')

class AbstractSignConfig(object):
    """ Class for keeping track of various global config options
        for signatures, such as a connection to the Accumulo instance,
        where the signatures are being stored, and whether it's doing
        batch or stream inserting.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def _add_signature(self, mutation, update, metadata, sig):
        pass

    @abstractmethod
    def _split_entry(self, entry):
        """ Extract the original visibility, signature, and other signature
            metadata from the visibility field.

            keyword arguments:
            entry - a pyaccumulo entry

            Returns two values:
            - A named tuple containing the original string, the
            metadata associated with the signature (either the signature
            algorithm's name or the signer's ID), and the signature itself.
            - A Cell object (from pyaccumulo) representing the original
            cell, without metadata
        """
        pass

    @abstractmethod
    def start_batch(self):
        pass

    @abstractmethod
    def update_batch(self, mutation):
        pass

    @abstractmethod
    def end_batch(self):
        pass

class BatchIndifferentConfigMixin(object):
    """ Mixin for configuration objects that do not batch their signatures
        at all and therefore can do nothing for all the batch-related ops.
    """
    def start_batch(self):
        pass

    def update_batch(self, mutation):
        pass

    def end_batch(self):
        pass

class VisibilityFieldConfig(BatchIndifferentConfigMixin, AbstractSignConfig):

    def __init__(self):
        pass

    def _add_signature(self, mutation, update, metadata, sig):
        # Signed visibility field format:
        # <old or default visibility field> |
        # "<metadata>,<signature>"
        # where <metadata> is either the signer's unique ID or the
        # name of the signature algorithm used (if signer IDs are not
        # provided)
        vis = '%s|",%s,"' %(update.colVisibility,
                            ','.join([metadata, sig]))
        update.colVisibility = vis
        
    
    def _split_entry(self, entry):
        """ Extract the original visibility, signature, and other signature
            metadata from the visibility field.

            This function assumes that the entry has been signed, and that the
            signature metadata is put in quotation marks and appended to the
            end of the visibility field, as follows:

            <original visibility field>|",<metadata>,<base 64 encoded signature>,"

            keyword arguments:
            entry - a pyaccumulo entry

            Returns two values:
            - A named tuple containing the original string, the
            metadata associated with the signature (either the signature
            algorithm's name or the signer's ID), and the signature itself.
            - A Cell object (from pyaccumulo) representing the original
            cell, without metadata
        """
        #split the visibility field into actual visibility and
        #signature
        full_vis = entry.cv
        pieces = full_vis.split(',')

        # Check a couple of simple invariants about the signature field.
        # Note that these will NOT prevent the code from interpreting any
        # malformed or unsigned piece of metadata, but they should catch a
        # lot of cases, and help provide better error messages in the case
        # that an entry up for verification was not actually signed.

        if len(pieces) < 4:
            raise VerificationException(
                'Visibility field contains too few entries to contain metadata')

        if not (pieces[-1] == '"' and pieces[-4][-2:] == '|"'):
            raise VerificationException(
                'Visibility field contains wrong formatting for signature metadata')

        metadata, sig = pieces[-3:-1]

        # Join up with any other commas that may have existed, and truncate
        # the trailing |" that was added to the end, before the first
        # metadata comma.
        cell_vis = ','.join(pieces[0:-3])[:-2]

        #construct the data tuple and convert it to a string
        tup = (entry.row, entry.cf, entry.cq, cell_vis, None, entry.val)
        cell_string = str(tup)

        return SignedEntry(cell_string=cell_string,
                           metadata=metadata,
                           sig=sig), Cell(*tup)

class ValueConfig(BatchIndifferentConfigMixin, AbstractSignConfig):
    
    def __init__(self):
        pass

    def _add_signature(self, mutation, update, metadata, sig):
        val = '|'.join([metadata, sig, update.value])
        update.value = val

    def _split_entry(self, entry):
        # Value format: <metadata>|<signature>|<actual value>
        metadata, sig, value = string.split(entry.val, '|', maxsplit=2)

        tup = (entry.row, entry.cf, entry.cq, entry.cv, None, value)

        return (SignedEntry(cell_string=str(tup), metadata=metadata, sig=sig),
                Cell(*tup))

class AbstractTableConfig(AbstractSignConfig):

    def __init__(self, conn, table):
        self.conn = conn
        self.table = table
        if not conn.table_exists(table):
            conn.create_table(table)

    def _add_signature(self, mutation, update, metadata, sig):
        """ Write signature metadata to a new cell in the Accumulo instance.
            The user specifies the name of the metadata table to store all this
            metadata in, the row is the stringified version of the cell tuple,
            the column family and qualifier are blank, and the signature
            metadata is stored in the value.

            NB: storing signature information in a separate column family or
                qualifier would likely be more efficient for most use cases,
                but it would require nontrivial modifications to how queries
                are handled by the user. This is something we may write later
                as a separate library, but for now, we choose this slightly
                less efficient but more compositional approach.
        """
        entry_tup = (mutation.row, update.colFamily, update.colQualifier,
                     update.colVisibility, update.deleteCell)
        cell_string = str(entry_tup)
        meta_mutation = Mutation(cell_string)
        meta_mutation.put(cf='', cq='', cv=update.colVisibility, val=','.join([metadata, sig]))
        self.update_batch(meta_mutation)

    def _split_entry(self, entry):
        tup = (entry.row, entry.cf, entry.cq, entry.cv, None, entry.val)
        cell_string = str(tup)
        lookup_string = str(tup[:-1])

        sig_entries = [x for x in 
                       self.conn.scan(self.table,
                                      scanrange=Range(srow=lookup_string,
                                                      erow=lookup_string))]
        
        assert len(sig_entries) == 1

        sig_entry = sig_entries[0]
        metadata, sig = sig_entry.val.split(',')

        return (SignedEntry(cell_string=cell_string,
                            metadata=metadata,
                            sig=sig),
                entry)      # no metadata in the entry, so just return it

class StreamingSignConfigMixin(object):
    """ Mixin for SignConfig classes that don't store up any entries
        in a batch, but write them out to self.table each time update_batch()
        is called.
    """
    def start_batch(self):
        pass

    def update_batch(self, mutation):
        self.conn.write(self.table, mutation)

    def end_batch(self):
        pass

class BatchSignConfigMixin(object):
    """ Mixin for SignConfig classes taht store up entries in a pyaccumulo
        batch writer, then write them all out at once at the end of each
        batch.
    """
        
    def start_batch(self):
        self.batch = self.conn.create_batch_writer(self.table)

    def update_batch(self, mutation):
        self.batch.add_mutation(mutation)

    def end_batch(self):
        self.batch.close()
        self.batch = None

class StreamingTableConfig(StreamingSignConfigMixin, AbstractTableConfig):
    """ Config for writing signatures to a separate Accumulo table one at
        a time as they are computed.
    """
    pass

class BatchTableConfig(BatchSignConfigMixin, AbstractTableConfig):
    """ Config for holding on to signatures, then writing them all out to
        a separate table at once at the end of each batch.
    """
    pass

def new_config(config_file, conn):
    """ Return a new configuration object based on the information received,
        perhaps from command-line arguments or a config file.

        Every config file must include a section called 'Location'.  The
        default behavior for a config file is to store the signature in the
        visibility field of each cell. To override this behavior, a config file
        should be formatted as follows:

        - In the Location section, include an option called 'loc' that
          is one of the following:

            - 'vis' (for storing the signature in the visibility field. This
                     is the default behavior)
            - 'val' (for storing the signature in the value field.)
            - 'tab' (for storing the signature in a separate table.)

        - If the location was 'tab', the following options also need to be
          included:
            
            - 'is_batch' (either 'true' or 'false', representing whether the
                          writes to the signature metadata table should be
                          batched or not.)
            - 'metadata_table' (the name of the table for the signature data
                                to be stored in.)

        The folder cfg/ contains some example configuration files.
        
        Arguments:
            config_file - a file pointer (or file-like object, such as from
                          StringIO) that points to the information in the
                          config file.

            conn - a connection to the Accumulo instance this is a configuration
                   object for.
    """

    config_parser = ConfigParser.RawConfigParser(defaults={'loc' : 'vis'})
    config_parser.readfp(config_file)

    try:
        loc = config_parser.get('Location', 'loc')
    except ConfigParser.Error as e:
        print e
        raise ConfigException('malformed config file: no location information')

    if loc == 'vis':
        return VisibilityFieldConfig()
    elif loc == 'val':
        return ValueConfig()
    elif loc == 'tab':
        try:
            metadata_table = config_parser.get('Location', 'metadata_table')
        except ConfigParser.Error:
            raise ConfigException(
                'malformed config file: no metadata table specified')

        try:
            is_batch = config_parser.getboolean('Location', 'is_batch')
        except ValueError:
            raise ConfigException(
                'malformed config file: invalid value for is_batch')
            
        if is_batch:
            return BatchTableConfig(conn, metadata_table)
        else:
            return StreamingTableConfig(conn, metadata_table)
    else:
        raise ConfigException('Invalid location %s' %loc)

class ConfigException(Exception):
    """ Exception raised when a config file is malformed.
        
        Attributes:
            msg - error message associated with the failure
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class VerificationException(Exception):
    """ Exception raised when unable to verify a signature.
        
        Attributes:
            msg - error message associated with the failure
            cell - Accumulo cell with the metadata parsed out, if any
    """
    def __init__(self, msg, cell=None):
        self.msg = msg
        self.cell = cell

    def __str__(self):
        return self.msg
