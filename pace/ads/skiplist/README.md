# Authenticated Skip Lists

This is a Python Authenticated Data Structure (ADS) library for Accumulo,
specifically implementing authenticated skip lists. ADSs allow users to verify
the correctness of entire queries from an untrusted database. To compare,
digital signatures only allow verification of one element of the query at a
time, and do not provide a mechanism for determining whether elements were
omitted from a query.

This library includes three primary components:

- An implementation of skip lists, a random, balanced tree-like data structure
  with expected `O(log(n))` insert and lookup operations.

- An implementation of authenticated skip lists, a Merkle tree-like data
  structure that is implemented over a skip list rather than a binary tree.

- A prototype embedding of our authenticated skip list implementation into
  Accumulo. The two goals behind this prototype were to determine a schema to
  use to store an ADS computed over an Accumulo table, and to implement that
  schema reusing as much of our existing authenticated skip list code as
  possible.

In this document, we focus on how a user would install, run, configure, and use
the authenticated skip list embedding to verify queries from an untrusted
Accumulo server.

## Installation

### Dependencies

This project uses the [pyaccumulo](https://pypi.python.org/pypi/pyaccumulo)
library in order to interface with Accumulo. Our code has been written and
tested using pyaccumulo version 1.5.0.6.

## Use

In addition to the authenticated skip list code, there are several classes that
support our skip list definition. We now describe these support classes, their
roles, and how to use them, before going on to explain how to use our skip list
embedding.

### Elements

In `pace.ads.skiplist.elemclass`, we define an abstract interface,
`BaseElem`, for the type of elements stored by a skip list, along with several
useful implementations oft his interface. The definition of `BaseElem`,
including its abstract methods that implementing classes must define, is as
follows:

```python
class BaseElem:
    
    __metaclass__ = ABCMeta

    def __init__(self, key):
        self.key = key
    
    def __cmp__(self, other):
        ...

    @abstractmethod
    def serialize(self):
        pass

    @abstractmethod
    def deserialize(s):
        pass
```

This interface requires two capabilities: comparison of different elements of
the same class, and (de)serialization of elements within a class. By default, a
`__cmp__()` method and a `serialize()` method are implemented using the `key`
field's comparison and to-string methods, respectively, but these default
implementations can be overridden.

The `elemclass` package also contains several useful implementations of the
`BaseElem` interface. Two of them, `IntElem` and `StrElem`, are simple wrappers
around Python's string and integer types, allowing them to be stored in skip
lists. The other two, `AccumuloKey` and `AccumuloEntry`, are for constructive
skip lists over Accumulo cells.


### Coins

In `pace.ads.skiplist.coin`, we define an abstraction, `BaseCoin`, for
simulating coin flips, i.e. generating `True` and `False` values randomly or
pseudorandomly. This class's interface has one function, as follows:

```python
def flip(self, *args):
    return random.randint(0,1) == 1
```

This uses Python's `random` module to return either `True` or `False`, each with
probability 0.5. A `BaseCoin` can be used as follows:

```python
>>> from pace.ads.skiplist.coin import BaseCoin
>>> coin = BaseCoin()
>>> flips = [coin.flip() for _ in xrange(100)]
>>> flips[:10]
[False, False, True, False, False, False, False, False, True, False]
```

In addition to this basic interface, we provide several extensions with
different capabilities, and in some cases, extra methods, for different use
cases:

- `RecordedCoin`: records the result of each flip into a list that can be
  accessed with the `read()` method, which will then reset the record to the
  empty list.
- `PrefixCoin`: takes as input to its constructor a prefix of coin flip results
  that will be drawn from before switching to randomly generating coin flips as
  in `BaseCoin`. The stored prefix can be extended by calling the `extend()`
  method with the suffix to extend it with.
- `RecordedPrefixCoin`: combines the functionalities of `RecordedCoin` and
  `PrefixCoin`.
- `SeededCoin`: generates its random numbers based on a given seed value,
  keeping track of the resulting state to make sure it will always generate the
  same sequence of values as another coin with the same seed.
- `HashCoin`: deterministically generates coin flips based on iterative
  application of a hash function to the element being inserted into the skip
  list.  This adds an extra argument to the hash function: one now calls
  `hashcoin.flip(hash)`, where `hash` is the hash value of the element being
  inserted into the skip list.

A primary motivation behind these subclasses is the ability to generate the same
coin flips on a client and server. We support three ways to do this:

- The client uses `RecordedCoin` and sends the results to the server, which
  appends them on to its `PrefixCoin`. This can also work if one or both parties
  uses a `RecordedPrefixCoin`.
- Both parties use a `SeededCoin` and agree on the seed to use beforehand.
- Both parties use a `HashCoin`. This can be done with no additional
  communication, since the flips are randomly generated from each element in the
  skip list in isolation.

We recommend using `HashCoin`, the third of these options. In situations where
this option's determinism is undesirable, there is a tradeoff: `SeededCoin`
requires no communication, but the cost of storing and restoring the RNG's state
adds considerable overhead; conversely, recording and pulling from a prefix is a
relatively fast operation, but the communication cost of sending the recorded
values across a network connection may be prohibitive.

### Embedded Skip Lists

To create an authenticated skip list embedded in Accumulo, one calls the `new()`
method from the `EmbeddedSkipList` class, located in the
`pace.ads.skiplist.accumulo.embeddedskiplist` package:

```python
from pace.ads.skiplist.accumulo.embeddedskiplist import EmbeddedSkipList
ads = EmbeddedSkipList.new(elems, lbound, rbound, coin,
                           conn_info, table, elemclass)
```

This method's first four arguments are common to all of our skip list classes:

- `elems`: the list of elements to add to the skip list.
- `lbound`, `rbound`: the left and right boundaries of the skip list's range.
  These should have the property that for all elements `e` in `elems`,
  `lbound < e < rbound`, and that each element inserted into the list in the
  future is also between `lbound` and `rbound`.
- `coin`: the coin class (as defined above) to use to generate the coin flips
  for insertion into the skip list. We recommend using `HashCoin` for this, as
  it automatically computes a skip list of the same structure for both server
  and client without any extra input from the user.

The next two arguments are embedding-specific:

- `conn_info`: a named tuple object, called `ConnInfo`, containing the
  information needed to connect to the Accumulo server in which the skip list is
  being embedded. This tuple class is also defined in `embeddedskiplist.py`. The
  fields of this named tuple are, in order, `hostname`, `port`, `username`, and
  `password`.
- `table`: the name of the table in which to store the skip list. This field
  should be different for each authenticated skip list stored in the Accumulo
  server.

Finally, the last argument is the class of elements stored in the skip list.

In order to perform a range query over the skip list, one uses the `SkipListVO`
class, defined in `pace.ads.skiplist.skiplistvo`. This computes a
verification object for the given range client-side using the information
embedded in the server. In particular, the syntax for a range query over the
skip list `ads` works as follows:

```python
from pace.ads.skiplist.skiplistvo import SkipListVO
vo = SkipListVO.range_query(ads, lbound, rbound, coin)
```

The four arguments for `range_query()` are as follows:

- `ads`: the skip list over which the range query is being performed.
- `lbound`: the lower bound (inclusive) of the range query.
- `rbound`: the upper bound (inclusive) of the range query.
- `coin`: the coin class to use to generate the coin flips for insertion into
  the VO. This is used primarily in the `insert()` method, described below, and
  _must_ be synchronized with the coin used for `ads`. As above, we recommend
  using `HashCoin` for this, as it simplifies synchronization.

The verification object returned by a range query also supports insertion
operations, in order to allow data owners to update their local root hash value
when inserting data. This means inserts should have three steps:

- Perform and verify a range query over the range of data to be inserted, from
  the minimum element to the maximum element.
- Insert into the remote skip list.
- Insert into the range query object.

## Testing the code

We use nosetests to run unit tests over the skip list code. These can by run by
invoking `nosetests` from the shell in either the `pace/ads/skiplist/`
directory, which will run all of the unit tests, or from its `accumulo/`
subdirectory, which will run only the embedded skip list tests.
