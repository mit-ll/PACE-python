## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Code to simulate an Accumulo connection, for testing
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  25 Nov 2014  CS    Original file
##   7 Jan 2015  ATLH  Changed FakeEntry to Cell
## **************

from collections import namedtuple

Cell = namedtuple("Cell", "row cf cq cv ts val")


class FakeWriter(object):
    def __init__(self, table, conn):
        self.table = table
        self.conn = conn
        self.mutations = []

    def close(self):
        for m in self.mutations:
            self.conn.write(self.table, m)
        self.mutations = []

    def add_mutation(self, m):
        self.mutations.append(m)

class FakeConnection(object):
    """ Something that acts like an Accumulo connection, for testing.
    """

    def __init__(self):
        self.db = {}

    def write(self, table, mut):
        try:
            tdict = self.db[table]
        except KeyError:
            raise Exception('Table %s not in database' %table)

        row = mut.row

        try:
            rdict = tdict[row]
        except KeyError:
            rdict = {}
            tdict[row] = rdict

        for u in mut.updates:
            col = u.colFamily, u.colQualifier, u.colVisibility, u.timestamp

            if u.deleteCell:
                del rdict[col]
            else:
                rdict[col] = u.value

    def table_exists(self, table):
        return table in self.db

    def create_table(self, table):
        if table not in self.db:
            self.db[table] = {}
        else:
            raise Exception('Table %s already in database' %table)

    #TODO: table deletion
    
    def aggregate_db(self):
        out = {}

        for table_name, table_contents in self.db.iteritems():
            tmp = [(row, rdb.items())
                   for row, rdb in table_contents.iteritems()]
            for row, relems in tmp:
                contents = [Cell(row, cf, cq, cv, ts, val)
                            for (cf, cq, cv, ts), val in relems]
                out[table_name] = contents

        return out

    def create_batch_writer(self, table):
        return FakeWriter(table, self)

    @staticmethod
    def in_range(row, cf, cq, cv, scanrange):
        if scanrange.srow is not None and scanrange.erow is not None:
            if not scanrange.srow <= str(row) <= scanrange.erow:
                return False

        if scanrange.scf is not None and scanrange.ecf is not None:
            if not scanrange.scf <= str(cf) <= scanrange.ecf:
                return False

        if scanrange.scq is not None and scanrange.ecq is not None:
            if not scanrange.scq <= str(cq) <= scanrange.ecq:
                return False

        if scanrange.scv is not None and scanrange.ecv is not None:
            if not scanrange.scv <= str(cv) <= scanrange.ecv:
                return False

        return True

    @staticmethod
    def _matches_cols(cf, cq, cols):
        """ See if the given column family & qualifier are in the
            given set of columns. Written to match pyaccumulo
            functionality as closely as possible.
        """
        if not cols:
            # Nothing specified (either None or []), so just return True
            return True

        for col in cols:
            assert len(col) > 0
            if col[0] == cf:
                if len(col) > 1:
                    if col[1] == cq:
                        return True
                    else:
                        continue
                else:
                    return True

        # No matches found
        return False


    def scan(self, table, scanrange=None, cols=None):
        """ Scan a table, either in its entirety or over a given range.
            
            Arguments:

            table : string - the name of the table to scan
            scanrange : pyaccumulo.Range - the range of rows to scan.
                It is important to note that, while the pyaccumulo Range
                object can contain start & end column fields, as well, it
                seems to ignore those, so we also ignore them.
            cols : optional [[string]] - a list of column family/qualifier
                lists. This does not seem to be formally documented in
                pyaccumulo, but seems to work as follows:
                    - If it is None or [], return all entries in `table`
                        matching `range`
                    - If it is nonempty, treat each element as a specification
                        of which column to return. Each element should be
                        a nonempty list, where the first element is treated
                        as the column family and the second element, if any,
                        is treated as the column qualifier, further refining
                        its paired column family.

                      For example, the `cols` value [['foo', 'bar']] would
                        match a cell with the column family 'foo' and column
                        qualifier 'bar', but not one with column family 'foo'
                        and column qualifier 'baz', nor would it match one
                        with column family 'qux' and column qualifier 'bar'.
                        The `cols` value [['foo', 'bar'], ['baz']], however,
                        would match a cell with column family 'foo' and
                        column qualifier 'bar', as well as a cell with column
                        family 'baz' and any column qualifier.
        """
        if scanrange is not None:
            for row, rdb in self.db[table].iteritems():
                for (cf, cq, cv, ts), val in rdb.iteritems():
                    if FakeConnection.in_range(row, cf, cq, cv, scanrange):
                        if self._matches_cols(cf, cq, cols):
                            yield Cell(row, cf, cq, cv, ts, val)
        else:
            for row, rdb in self.db[table].iteritems():
                for (cf, cq, cv, ts), val in rdb.iteritems():
                    if self._matches_cols(cf, cq, cols):
                        yield Cell(row, cf, cq, cv, ts, val)

    def _scan(self, table, scanrange=None):
        """ Helper function for scan() that returns a generator
            NB: deprecated, since scan() is supposed to return a generator
                after all
        """
        return self.scan(table, scanrange)
                

    def list_tables(self):
        return self.db.keys()
