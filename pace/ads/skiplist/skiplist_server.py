## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Skiplist server/data publisher code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  10 Oct 2014  CS    Original file (copied from ../merkle/mht_server.py)
## **************

import socket
import logging
from abc import abstractmethod, ABCMeta

from SocketServer import StreamRequestHandler, TCPServer, ThreadingMixIn
from threading import Thread
from base64 import b64encode, b64decode

from pace.ads.skiplist.authskiplist import AuthSkipList
from pace.ads.skiplist.skiplistvo import SkipListVO
from pace.ads.skiplist.coin import SeededCoin, PrefixCoin, HashCoin

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

def _recv_iterate(rfile, name):
    while True:
        x = _recv(rfile)

        if x == name:
            return
        else:
            yield x

class SkipListServerException(Exception):
    def __init__(self, msg):
        self.msg = msg

class SLHandler(StreamRequestHandler):

    def handle(self):
        # Initialize the skiplist
        # Can have a persistent skiplist once batch insertion has been
        # implemented.

        coin_type = _recv(self.rfile, 'handler')

        if coin_type == 'SEED':
            raw_seed = _recv(self.rfile, 'handler')
            try:
                seed = int(raw_seed)
            except ValueError:
                raise SkipListServerException(
                    'Non-number %s passed in for seed value' %raw_seed)
            coin = SeededCoin(seed)
        elif coin_type == 'PREFIX':
            prefix = [p == 'True' for p in _recv_iterate(self.rfile, 'ELEMS')]
            coin = PrefixCoin(prefix)
        elif coin_type == 'HASH':
            coin = HashCoin()
        else:
            raise SkipListServerException('Invalid coin type %s' %coin_type)
            
        elems = [self.server.elemClass.deserialize(elem)
                 for elem in _recv_iterate(self.rfile, 'END_ELEMS')]

        # Protocol: send the lower bound, then the upper bound, then the entire 
        #           list of elements to insert at first
        sl = AuthSkipList.new(elems[2:], elems[0], elems[1], coin)
                              
        while True:
            task = self.rfile.readline().strip()

            if task == 'QUERY':
                raw_elem = _recv(self.rfile, 'handler')
                elem = self.server.elemClass.deserialize(raw_elem)
                proof = sl.contains(elem)
                sproof = SLHandler.serialize_query_result(proof)
                _send(self.wfile, sproof, 'handler')

            elif task == 'RANGE_QUERY':
                raw_lower, raw_upper = _recvi(self.rfile, 2, 'handler')
                lower, upper = (self.server.elemClass.deserialize(raw_lower),
                                self.server.elemClass.deserialize(raw_upper))
                vo = SkipListVO.range_query(sl, lower, upper)
                _send(self.wfile, vo.serialize(), 'handler')

            elif task == 'INSERT':
                for elem in _recv_iterate(self.rfile, 'END_INSERT'):
                    sl.insert(self.server.elemClass.deserialize(elem))

            elif task == 'REPREFIX':
                prefix = [int(y)
                          for y in _recv_iterate(self.rfile, 'END_REPREFIX')]
                sl.coin.extend(prefix)

            elif task == 'RESEED':
                seed = int(_recv(self.rfile))
                sl.coin.reseed(seed)

            elif task == 'PING':
                _send(self.wfile, 'PONG')

            elif task == 'QUIT':
                return

            else:
                raise Exception('Unknown task %s' %task)

    @staticmethod
    def serialize_query_result(qr):
        """ Serialization protocol for query result lists.
            The result of a query is the result of joining the proof list
            together with the ';' delimiter, then pairing that with the boolean
            telling whether or not the element was found with the ',' delimiter
        """
        found, proof = qr

        inner = ';'.join([b64encode(hval) for hval in proof])
        
        return ','.join([str(found), inner])

class SocketSLServer(ThreadingMixIn, TCPServer):
    """ A skiplist server that serves the skiplist over a socket, freeing
        the client from having to store anything more than a
        handle on the server to send & receive information to & from.

        (this will become more interesting once it starts to serve the same
        skiplist to multiple clients)
    """
    def __init__(self, elemClass, *args, **kwargs):
        self.elemClass = elemClass
        TCPServer.__init__(self, *args, **kwargs)

class AbstractSocketSLClient(object):

    __metaclass__ = ABCMeta

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
        found, proof = qr.split(',')

        return found == 'True', [b64decode(s) for s in proof.split(';')]

    @abstractmethod
    def new(elems, min_elem, max_elem, seed, elemClass, host='localhost', port=9999):
        """ Creates a connection to a server and initializes it. Assumes
            that the server's SkipList has not already been initialized.
        """
        pass

    @abstractmethod
    def initialize(self, elems):
        """ Initialize the server being connected to. Should be called exactly
            once per server.

            Arguments may vary depending on the child class.
        """
        pass

    @classmethod
    def connect(cls, host='localhost', port=9999):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        return cls(sock)

    def query(self, elem):
        """ Query to see whether an element is in the skiplist.
            Arguments:
            self - the skiplist object
            elem - the object to query

            Returns:
            None if elem was not contained in the skiplist, or a proof
            that it was contained in the tree.
        """
        _send(self.wfile, 'QUERY')
        _send(self.wfile, elem.serialize(), 'client')
        proof = _recv(self.rfile, 'client')

        return AbstractSocketSLClient.deserialize_query_result(proof)

    def range_query(self, lower, upper):
        """ Query a range of elements beteween lower and upper (inclusive)
            Arguments:
            self - the skiplist object
            lower - the (inclusive) lower bound of the range
            upper - the (inclusive) upper bound of the range
            
            Returns:
            vo - a verification object (as in vo.py) for the given range
        """
        _send(self.wfile, 'RANGE_QUERY')
        _sendi(self.wfile, [lower.serialize(), upper.serialize()])
        vo = _recv(self.rfile, 'client')
        return SkipListVO.deserialize(vo, self.elemClass)

    def ping(self):
        """ Ping a server. Mostly for testing/benchmarking purposes; assumes
            it can't respond until it's finished with its previous task.
        """
        
        _send(self.wfile, 'PING')
        _recv(self.rfile)


class SeededSocketSLClient(AbstractSocketSLClient):

    @staticmethod
    def new(elems, min_elem, max_elem, seed, elemClass, host='localhost', port=9999):
        """ Creates a connection to a server and initializes it. Assumes
            that the server's SkipList has not already been initialized.
        """
        s = SeededSocketSLClient.connect(host, port)
        s.initialize(seed, [min_elem, max_elem] + elems)
        s.elemClass = elemClass
        return s

    def initialize(self, seed, elems):
        _send(self.wfile, 'SEED', 'client')
        _send(self.wfile, str(seed), 'client')
        for elem in elems:
            _send(self.wfile, elem.serialize(), 'client')
        _send(self.wfile, 'END_ELEMS', 'client')

    def batch_insert(self, expected_initial_root, elems, least, greatest, seed):
        vo = self.range_query(least, greatest)
        vo.verify(least, greatest, expected_initial_root)
        _send(self.wfile, 'RESEED')
        _send(self.wfile, str(seed))
        _send(self.wfile, 'INSERT')

        vo.coin = SeededCoin(seed)
        
        for elem in elems:
            _send(self.wfile, elem.serialize())
            vo.insert(elem)

        _send(self.wfile, 'END_INSERT')

        return vo.root.label

class PrefixSocketSLClient(AbstractSocketSLClient):

    @staticmethod
    def new(elems, min_elem, max_elem, prefix, elemClass, host='localhost', port=9999):
        """ Creates a connection to a server and initializes it. Assumes
            that the server's SkipList has not already been initialized.
        """
        s = PrefixSocketSLClient.connect(host, port)
        s.initialize(prefix, [min_elem, max_elem] + elems)
        s.elemClass = elemClass
        return s

    def initialize(self, prefix, elems):
        _send(self.wfile, 'PREFIX', 'client')
        for p in prefix:
            _send(self.wfile, str(p), 'client')
        _send(self.wfile, 'ELEMS', 'client')
        for elem in elems:
            _send(self.wfile, elem.serialize(), 'client')
        _send(self.wfile, 'END_ELEMS', 'client')

    # TODO: might be a way to make sure we only have to go through elems once
    def batch_insert(self, expected_initial_root, elems, least, greatest):
        vo = self.range_query(least, greatest)
        vo.verify(least, greatest, expected_initial_root)
        vo.coin = RecordedCoin()
        
        for elem in elems:
            vo.insert(elem)

        _send(self.wfile, 'REPREFIX')
        for p in vo.coin.read():
            _send(self.wfile, str(p))
        _send(self.wfile, 'END_REPREFIX')

        _send(self.wfile, 'INSERT')
        vo.coin = PrefixCoin(seed)
        
        for elem in elems:
            _send(self.wfile, elem.serialize())

        _send(self.wfile, 'END_INSERT')
        return vo.root.label

class HashSocketSLClient(AbstractSocketSLClient):

    @staticmethod
    def new(elems, min_elem, max_elem, elemClass, host='localhost', port=9999):
        """ Creates a connection to a server and initializes it. Assumes
            that the server's SkipList has not already been initialized.
        """
        s = HashSocketSLClient.connect(host, port)
        s.initialize([min_elem, max_elem] + elems)
        s.elemClass = elemClass
        return s

    def initialize(self, elems):
        _send(self.wfile, 'HASH', 'client')
        for elem in elems:
            _send(self.wfile, elem.serialize(), 'client')
        _send(self.wfile, 'END_ELEMS', 'client')

    # TODO: might be a way to make sure we only have to go through elems once
    def batch_insert(self, expected_initial_root, elems, least, greatest):
        vo = self.range_query(least, greatest)
        vo.coin = HashCoin()
        vo.verify(least, greatest, expected_initial_root)
        
        _send(self.wfile, 'INSERT')
        
        for elem in elems:
            _send(self.wfile, elem.serialize())
            vo.insert(elem)

        _send(self.wfile, 'END_INSERT')
        return vo.root.label
