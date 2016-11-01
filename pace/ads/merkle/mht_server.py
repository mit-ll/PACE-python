## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: MHT server/data publisher code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  21 Jul 2014  ZS    Original file
## **************

import socket
import logging

from SocketServer import StreamRequestHandler, TCPServer, ThreadingMixIn
from threading import Thread
from base64 import b64encode, b64decode

from pace.ads.merkle.mht import MHT
from pace.ads.merkle.vo import VO

def _recv(sfile, loc=''):
    return sfile.readline().strip()

def _recvi(sfile, i, loc=''):
    return [_recv(sfile, loc) for x in range(0, i)]

def _send(wfile, msg, loc=''):
    total_msg = msg + '\n'
    wfile.write(total_msg)
    wfile.flush()

def _sendi(wfile, msgs, loc=''):
    for msg in msgs:
        _send(wfile, msg, loc)

def _batch_iterate(rfile):
    while True:
        x = _recv(rfile)

        if x == 'FINISHED_BATCH_INSERT':
            return
        else:
            yield int(x)

def _recv_iterate(rfile, name):
    while True:
        x = _recv(rfile)

        if x == name:
            return
        else:
            yield x

class MHTHandler(StreamRequestHandler):

    def handle(self):
        
        # Initialize the MHT
        # Can have a persistent MHT once batch insertion has been
        # implemented.
        elems = [int(elem) for elem in _recv_iterate(self.rfile, 'END_ELEMS')]
        mht = MHT.new(elems)

        while True:
            task = self.rfile.readline().strip()

            if task == 'QUERY':
                raw_elem = _recv(self.rfile, 'handler')
                elem = int(raw_elem)
                proof = mht.contains(elem)
                sproof = MHTHandler.serialize_query_result(proof)
                _send(self.wfile, sproof, 'handler')

            elif task == 'RANGE_QUERY':
                raw_lower, raw_upper = _recvi(self.rfile, 2, 'handler')
                lower, upper = int(raw_lower), int(raw_upper)
                vo = mht.range_query(lower, upper)
                _send(self.wfile, vo.serialize(), 'handler')

            elif task == 'BATCH_INSERT':
                mht.batch_insert(_batch_iterate(self.rfile))

            elif task == 'PING':
                _send(self.wfile, 'PONG')

            elif task == 'QUIT':
                return

    @staticmethod
    def serialize_query_result(qr):
        """ Serialization protocol for query result lists.
            The result of a query is one of the following:

            None - return the string 'None'
            list of (flag, hval) pairs - transform each boolean flag into its
                string with the str() method, then base 64 encode each hash
                value. Put each pair together with the ';' delimiter, then
                join the entire list with the ',' delimiter.
        """
        if qr is None:
            return 'None'
        
        return ','.join(['%s;%s' %(str(f), b64encode(h)) for f, h in qr])

class SocketMHTServer(ThreadingMixIn, TCPServer):
    """ An MHT server that serves the MHT over a socket, freeing
        the client from having to store anything more than a
        handle on the server to send & receive information to & from.

        (this will become more interesting once it starts to serve the same
        MHT to multiple clients)
    """
    pass

class SocketMHTClient(object):

    def __init__(self, sock):
       self.sock = sock
       self.rfile = sock.makefile('r')
       self.wfile = sock.makefile('w')

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        _send(self.wfile, 'QUIT')
        self.rfile.close()
        self.wfile.close()
        self.sock.close()
    
    @staticmethod
    def deserialize_query_result(qr):
        if qr == 'None':
            return None
        
        return [(f == 'True', b64decode(h))
                for f, h in [s.split(';') for s in qr.split(',')]]

    @staticmethod
    def new(elems, host='localhost', port=9999):
        """ Creates a connection to a server and initializes it. Assumes
            that the server's MHT has not already been initialized.
        """
        s = SocketMHTClient.connect(host, port)
        s.initialize(elems)
        return s

    def initialize(self, elems):
        """ Initialize the server being connected to with the elements
            elems. Should be called exactly once per server.
        """
        _sendi(self.wfile, [str(elem) for elem in elems])
        _send(self.wfile, 'END_ELEMS')

    @staticmethod
    def connect(host='localhost', port=9999):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        return SocketMHTClient(sock)

    def query(self, elem):
        """ Query to see whether an element is in the MHT.
            Arguments:
            self - the MHT object
            elem - the object to query

            Returns:
            None if elem was not contained in the MHT, or a proof
            that it was contained in the tree.
        """
        _send(self.wfile, 'QUERY')
        _send(self.wfile, str(elem), 'client')
        proof = _recv(self.rfile, 'client')

        return SocketMHTClient.deserialize_query_result(proof)

    def range_query(self, lower, upper):
        """ Query a range of elements beteween lower and upper (inclusive)
            Arguments:
            self - the MHT object
            lower - the (inclusive) lower bound of the range
            upper - the (inclusive) upper bound of the range
            
            Returns:
            vo - a verification object (as in vo.py) for the given range
        """
        _send(self.wfile, 'RANGE_QUERY')
        _sendi(self.wfile, [str(lower), str(upper)])
        vo = _recv(self.rfile, 'client')
        return VO.deserialize(vo)

    def batch_insert(self, expected_initial_root, elems, least, greatest):
        vo = self.range_query(least, greatest)
        vo.verify(least, greatest, expected_initial_root)
        _send(self.wfile, 'BATCH_INSERT')
        
        for elem in elems:
            _send(self.wfile, str(elem))
            vo.insert(elem)

        _send(self.wfile, 'FINISHED_BATCH_INSERT')

        return vo.root.hval

    def ping(self):
        """ Ping a server. Mostly for testing/benchmarking purposes; assumes
            it can't respond until it's finished with its previous task.
        """
        
        _send(self.wfile, 'PING')
        _recv(self.rfile)
