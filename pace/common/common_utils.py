## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH, SS
##  Description: Common utility functions for testing the code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  20 Jan 2015  ATLH    Original file - based on sign_utils
##  15 Dec 2015  SS      Added functionality of data generation
## **************
""" Utility functions for testing PACE software with rows written to
    Accumulo. 
    Any randomized test should use the same seed so that they are equivalent.
"""

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import random
import copy
import time, datetime
import string

from pyaccumulo import Range

class Timer(object):
    """
    Timer that works with python's 'with' syntax
    measures the time taken in seconds and milliseconds
    """
    #modified from http://www.huyng.com/posts/python-performance-analysis/
    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs

def generate_data(filename, 
                  seed, 
                  vis=False, 
                  default_vis="default",
                  vis_in_value=False, 
                  num_entries=50000, 
                  num_rows=1000, 
                  vis_length=9, 
                  row_length=9):
    """ Generate a tab-delimited text file with five columns:
        row, col fam, col qual, col vis, value

        keyword arguments:
        filename - name of file to which the data will be written
        seed - a string to be used as the seed for the random number generator
        visibility - if True, random column visibilities are added. If False,
            the default visibility string is added. (default False)
        default_vis - the default visibility string to use if 'visibiilty' is 
            set to False. (default "default")
        vis_in_value - if True, a random "column visibility" is generated, but
            this is appended to the value rather than column visibility. If
            True, the param vis is treated as False.
        num_entries - Number of entries written.
        num_rows - Number of rows in the data written.
        vis_length - The length (in chars) of the random col visibility added
            (true length will be this + 2)
        row_length - Number of chars in each row ID. Numbers are zero padded to 
            reach this length.
    """

    # seed RNG
    random.seed(seed)

    rows = map(lambda x: str(x).zfill(row_length), \
        random.sample(xrange(10 ** row_length), num_rows))
    unused_rows = copy.deepcopy(rows)

    def generate_entry():
        """ Helper function for generate_data that returns a single entry
            which will form a single line of the data file
        """

        def generate_field(length=row_length):
            """ Generates a single field (row, col fam, or col qual) randomly
            """
            return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

        def generate_row():
            """ Generates a single rowID from the list of rows.  On successive
                calls, ensures each rowID is used at least once, but makes no
                other guarantees about how many times each rowID is used
            """
            return unused_rows.pop() if unused_rows else random.choice(rows)

        def generate_colvis():
            """ Generates a single column visibility (either the default or a
                random value)
            """
            return default_vis if (vis_in_value or not vis) \
                else generate_field(vis_length).zfill(vis_length)

        def generate_value():
            """ Generates a random value, accounting for vis_in_value """
            val = generate_field()
            return val + generate_field(vis_length).zfill(vis_length) if vis_in_value else val

        return generate_row() + "\t" + \
            generate_field() + "\t" + \
            generate_field() + "\t" + \
            generate_colvis() + "\t" + \
            generate_value() + "\n"

    # Open file and generate data
    with open(filename, "w") as f:
        for i in range(num_entries):
            f.write(generate_entry())
    
def sanitize(string):
    """ Turns '-' into '_' for accumulo table names
    """
    return string.replace('-', '_')

def get_single_entry(conn, table, row=None, cf=None, cq=None):
    """ Get the single entry with the given key fields (row, column
        family, and column qualifier) from an Accumulo database.
        
        Returns:

        None if no entries were found
        The found entry if exactly one was found
        Raises an assertion error if more than one entry was found
    """

    if cf is None:
        assert cq is None
        cols = None
    elif cq is None:
        cols = [[cf]]
    else:
        cols = [[cf, cq]]

    candidates = conn.scan(table, Range(srow=row, erow=row), cols=cols)
    
    try:
        first = next(candidates)
    except StopIteration:
        # No candidates; return None
        return None

    try:
        more = next(candidates)
        assert False        # only supposed to have one result
    except StopIteration:
        return first

def entry_exists(conn, table, row, cf=None, cq=None):
    """ Check to see if at least one entry with the given information
        exists in the given Accumulo table. Takes at least a row,
        and possibly a column family & qualifier as well.

        Arguments:

        conn : Accumulo - a connection to the Accumulo instance to check
        table : string - the name of the table to check
        row : string - the name of the row to look for within the given table
        cf : optional string - the column family to look for, if desired
        cq : optional string - the column qualifier to look for, if desired

        Returns:

        bool - whether there is at least one entry in the given connection with
               the given fields

        Assumptions:

        - The given table exists on the connection
        - If cf is not specified/None, then neither is cq
    """

    if cf is None:
        assert cq is None
        cols = None
    elif cq is None:
        cols = [[cf]]
    else:
        cols = [[cf, cq]]

    candidates = conn.scan(table, Range(srow=row, erow=row), cols=cols)

    try:
        first = next(candidates)
    except StopIteration:
        # Nothing found
        return False
    else:
        # Something found
        return True

