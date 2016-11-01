DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Department of Defense under Air Force Contract 
No. FA8721-05-C-0002 and/or FA8702-15-D-0001. Any opinions, findings, conclusions or 
recommendations expressed in this material are those of the author(s) and do not 
necessarily reflect the views of the Department of Defense.

&copy; 2015 Massachusetts Institute of Technology.

MIT Proprietary, Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 
or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this 
work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of 
this work other than as specifically authorized by the U.S. Government may violate any 
copyrights that exist in this work.

# Attribute Key Generation and Storage

This is a Python library for management of attribute keys for Cryptographically 
Enforced Attribute-Based Access Control (CEABAC) for Accumulo. This library 
consists of two components: the key generation system, including key derivation,
wrapping, and storage, and the key storage system. Keys in the system depend on 
four components: attribute, version, metadata (e.g., mode of operation), and 
key length. The attribute, version, and metadata are assumed to uniquely 
identify a key.

This document describes how to install and use the key generation and storage 
library to manage attribute keys for Cryptographically Enforced Attribute-Based 
Access Control (CEABAC).

## Installation

### Dependencies

This project depends on several other Python libraries and utilities. They are
listed below with links to their project pages. In addition to these packages,
it also requires a running Accumulo instance.

- [nosetests](https://nose.readthedocs.org/en/latest/), version 1.3.3+.
- [pyaccumulo](https://pypi.python.org/pypi/pyaccumulo), version 1.5.0.6+.
- [pycrypto](https://www.dlitz.net/software/pycrypto/), version 2.7a1.

## Use

### Key Generation

The code for key generation, wrapping, and revocation is contained in `keygen`.

To perform these tasks, one must first create a key generation object as 
follows:

```python
from pace.pki.keygen import KeyGen
keygen = KeyGen(msk)
```

The `KeyGen` constructor takes as input a master secret key `msk`. This key 
will be used as the key for the hash-based message authentication code (HMAC) 
used to generate attribute keys. Therefore, the master secret key must be a 
uniformly random or pseudorandom string that is at least as long as the output 
of the hash function used in the HMAC (in the case of SHA-1, 20 bytes).

#### Initializing and Adding Users
The initialization process takes users' RSA public keys and the attribute,
metadata, and version information for the keys to which they should receive
access. It generates attribute keys, encrypts each one separately using the
public key of the each user with that attribute, and stores the key wraps and
associated information in the key store. Initializing users can be done by
inputting either a dictionary or a configuration file.

To initialize using a dictionary, one calls `initialize_users` as follows:

```python
KeyGen.initialize_users(users, keystore)
```

The `users` argument is a dictionary mapping user IDs to `(RSA_pk, info)` 
tuples, where `RSA_pk` is the user's RSA public key, and `info` is a list of 
`(attr, vers, metadata, keylen)` tuples specifying the attribute, version, 
metadata, and key length (in bytes) of the keys to generate, wrap, and store 
for that user. The attribute, version, and metadata strings must not contain 
the pipe ('|') character.

The `keystore` argument is the key store to which the key wraps will be written.
It must implement the `AbstractKeyStore` interface, which is described later in 
this document.

To initialize using a configuration file, one calls `init_from_file` as follows:

```python
KeyGen.init_from_file(user_file, keystore)
```

The `user_file` argument is a user configuration file name (or a list of file 
names). Each configuration file contains information about users' RSA public 
keys and about the attributes for which they should receive keys. Configuration
files must follow a specific format described below.

The `keystore` argument is the key store to which the key wraps will be written
It must implement the `AbstractKeyStore` interface, which is described later in
this document.

The initialization functions `initialize_users` and `init_from_file` can also be
used to add new users' attributes later. To do this, one must specify all of the
version numbers of the attribute keys the user should get access to, which may 
not necessarily be just the current version number.

##### Configuration File Format
The configuration files used for initializing or adding users' attributes must 
satisfy the following format. The file contains sections, each consisting of a 
`[section]` header followed by `name: value` entries.

Each section corresponds to a user. The section header should be the user ID. 
Within each section, the entries should be as follows:

- `public_key`: the name of a file containing an exported RSA public key.

- `key_info`: a newline-separated list of pipe-delimited strings specifying an 
attribute, version, metadata, and byte length of the key to be generated. The 
attribute, version, and metadata strings must not contain the pipe ('|') 
character. A non-attribute key can be generated by letting the attribute be the 
empty string.

For example, a section might look like the following:

```python
    [user1]
    public_key: user1_pubkey.pem
    key_info: a|1|VIS_AES_CFB|16
              b|1|VIS_AES_CFB|16
              c|1|VIS_AES_CFB|16
              d|1|VIS_AES_CFB|16
              |1|Pycrypto_AES_SIV|32
              |1|Pycrypto_AES_CFB|16
              |1|Pycrypto_AES_GCM|16
```

In this example, `user1`'s RSA public key is stored in the file 
`user1_pubkey.pem`. The user `user1` should receive access to version 1 of the 
AES CFB keys for attributes `a`, `b`, `c`, and `d`, all of which are 16-byte 
(128-bit) keys. The user should also get access to version 1 of the 
non-attribute keys for AES SIV (32 bytes), AES CFB (16 bytes), and AES GCM (16
bytes).

todo mention example config

#### Revoking Attributes

To revoke attributes from a user, one can either revoke a single attribute from
a user or revoke all attributes from a user at once.

To revoke a single attribute from a user:
```python
keygen.revoke(userid, attr, keystore, attr_user_map, user_attr_map, user_pks)
```

The `revoke` function takes the following arguments:

- `userid`: the ID of the user whose keys to revoke.

- `attr`: the attribute to revoke.

- `keystore`: the key store to which to write the new key wraps for all other 
  users with the given attribute. This must implement the `AbstractKeyStore` 
  interface, which is described later in this document.

- `attr_user_map`: an attribute-to-user map that can return a list of all users 
  with the given attribute. This must implement the `AbstractAttrUserMap` 
  interface, which is described later in this document.

- `user_attr_map`: a user-to-attribute map that can return a list a of all 
  attributes of a given user. This must implement the `AbstractUserAttrMap` 
  interface, which is described later in this document.

- `user_pks`: a dictionary that maps user IDs to users' RSA public keys.

- `metas_keylens`: an optional argument; a dictionary that maps metadata strings  to new key lengths. For any metadata not in the dictionary, the new key will 
  have the same length as the current key.

The `revoke` function will delete all of the revoked user's keys for the
specified attribute for all relevant metadata strings, generate a new attribute 
key with the next version number for each affected metadata (with a new key 
length, if specified), wrap these keys for all other users with that attribute, 
and insert the key wraps into the key store. A non-attribute key can be revoked 
by letting the attribute be the empty string.

To revoke all attributes of a user:

```python
keygen.revoke_all_attrs(self, userid, keystore, attr_user_map, user_attr_map, 
                              user_pks, metas_keylens={}):
```

The arguments are the same as for `revoke`, except that there is no `attr` 
argument specifying an attribute to revoke. Instead, all of the users' 
attributes will be revoked.

### Key Storage
After the keys are generated and wrapped, the key wraps need to be written out 
to a key store that users can query to retrieve their attribute keys. Depending 
on what infrastructure is available, this key store could take many different 
forms: it could be an LDAP server, a MySQL database, or even a separate Accumulo
database. With such a range of options, we find it important to provide not 
just an implementation of a key store, but a generic interface for key stores 
that any user can implement based on what is available in their ecosystem.

#### Interface
Our interface defines the basic means of storing and retrieving key wraps as 
follows:

```python
class AbstractKeyStore(object):

    @abstractmethod
    def insert(self, userid, keyinfo):
        ...

    @abstractmethod
    def batch_insert(self, userid, infos):
        ...

    @abstractmethod
    def retrieve_info(self, userid, attr, vers, metadata):
        ...

    @abstractmethod
    def batch_retrieve(self, userid, metadata, attr=None):
        ...

    @abstractmethod
    def remove_revoked_keys(self, userid, metadata, attr):
        ...

    @abstractmethod
    def get_metadatas(self, user, attr):
        ...

    @abstractmethod
    def retrieve_latest_version_number(self, metadata, attr):
        ...

    def retrieve(self, userid, attr, vers, metadata):
        ...

    def retrieve_latest_version(self, userid, metadata, attr):
        ...
```

At a high level, the key store maps users (represented as unique strings) to
`KeyInfo` tuples, which contain a key wrap and its associated information.
More precisely, a `KeyInfo` tuple contains the following fields:

- `attr`: the attribute corresponding to the associated key wrap, stored as a 
  string.

- `vers`: the version number of the associated key wrap, stored as an integer.

- `metadata`: the metadata corresponding to the associated key wrap, stored as a
  string.

- `keywrap`: the key wrap being stored, represented as a bit array (which in 
  Python 2.* is equivalent to the `string' type).

- `keylen`: the length of the key, in bytes, stored as an integer.

In addition to associating each user with their set of `KeyInfo` tuples, the key
store allows clients to perform more nuanced searches, additionally specifying
the metadata, and potentially the attribute, to search for. This allows users to
target the keys they know they will need when performing potentially costly
key store operations.

These functions behave as follows:

- `insert(self, userid, keyinfo)`: a function that inserts a mapping from 
  `userid` to `keyinfo` into the key store.

- `batch_insert(self, userid, infos)`: similar to `insert`, but accepts a list 
  of `KeyInfo` tuples to insert all at once for a given user, allowing the 
  implementation to more efficiently write them all to the key store, if 
  applicable.

- `retrieve_info(self, userid, attr, vers, metadata)`: retrieves a specific 
  `KeyInfo` tuple from the key store, fully specified with a `userid`, `attr`, 
  `vers`, and `metadata`.

- `batch_retrieve(self, userid, metadata, attr=None)`: retrieves all `KeyInfo` 
  tuples corresponding to a given `userid` and `metadata`. Optionally takes an 
  `attr` as an argument; if none is provided, returns all found attributes.

- `remove_revoked_keys(self, userid, metadata, attr)`: removes all key wraps 
  belonging to `userid` associated with `metadata` and `attr` from the key 
  store. This is used when a user's permission for a certain attribute is 
  revoked, to avoid storing keys to which they should no longer have access.

- `get_metadatas(self, user, attr)`: returns a `set` of all metadata strings 
  associated with `user` and `attr`.

- `retrieve_latest_version_number(self, metadata, attr)`: returns the number (as
  an integer) of the most recent version of the attribute key with the given 
  metadata. Importantly, this is user-independent; it returns the most recent 
  version that has been inserted into the key store, regardless of which user 
  or users it has been assigned to.

- `retrieve(self, userid, attr, vers, metadata)`: a wrapper function around 
  `retrieve_info()`, this function returns only the key wrap itself, rather than
  the entire `KeyInfo` tuple.

- `retrieve_latest_version(self, userid, metadata, attr)`: returns the most 
  recent version of the `KeyInfo` tuple for the given `userid`, `metadata`, and 
  `attr`. By default, this is implemented as a call to 
  `retrieve_latest_version_number()` followed by a call to `retrieve_info()`, 
  but can be overridden with a more efficient implementation.

#### Instantiations

We provide two concrete implementations of our key store interface: 
`DummyKeyStore`, in `keystore.py`, and `AccumuloKeyStore`, in 
`accumulo_keystore.py`. Specific details of each implementation follow.

##### Dummy Key Store

The `DummyKeyStore` class is a local implementation of the key store interface 
using Python's built-in dictionary type. This may be suitable for use if the 
keys involved are static, or if all of the key storage and generation can happen
on a single machine. However, its main purpose is to serve as the simplest 
possible implementation with which to test our key store-dependent code.

To initialize a dummy key store, one only has to call the constructor with no
arguments, as follows:

```python
from pace.pki.keystore import DummyKeyStore
keystore = DummyKeyStore()
```

After initialization, one can call `keystore.insert(...)` and 
`keystore.batch_insert(...)` to insert the appropriate elements to be held in 
the store.

##### Accumulo Key Store

For a more realistic key store implementation, we provide the `AccumuloKeyStore`
class. This key store takes an Accumulo connection in which to store all of the 
users' key wraps, indexed to make most of the key store operations performable 
with a single write or scan.

Each key wrap is stored in a table corresponding to a single metadata string. 
Within this table, each user gets a row, with the attribute stored in both the 
column family and visibility field, the version stored in the column qualifier,
and the key wrap and key length stored in the value field. Storing the attribute
in both the column family and the visibility field allows lookup by attribute 
while allowing the trusted key store to enforce access control on the key wrap.
*Note that in order to use this schema, every user must have access to each
table in which they have a key stored.*

To efficiently implement `get_metadatas()`, we use a separate table to keep 
track of which attributes and users have which metadata string associated with 
them. This table, whose name is configurable at the time the key store is 
created, stores the user ID as the row, the attribute as the column family, 
the metadata as the column qualifier, and the string `1` as the value. This 
dummy value allows the server to perform a range query over the given users and 
attributes, then extract the resulting cells' column qualifiers to return the 
appropriate metadata strings.

To efficiently implement `retrieve_latest_version_number()`, we use another 
separate table for keeping track of the latest version number for each key wrap 
metadata string and attribute. This table, whose name is also configurable, 
stores the attribute in the row, the metadata in the column qualifier, and the 
version number as a string in the value field.

To initialize an Accumulo key store, one invokes the constructor with a
pyaccumulo connection to the hosting Accumulo instance, and optionally provides
names for the metadata storage table and version number storage table, as
follows:

```python
from pace.pki.accumulo_keystore import AccumuloKeyStore
import pyaccumulo

conn = pyaccumulo.Accumulo(...)  # connection info goes here
keystore = AccumuloKeyStore(conn, meta_table='__KEYWRAP_METADATA__',
                                  vers_table='__VERSION_METADATA__')
```

This produces a key store that stores its key wraps in the Accumulo server that
`conn` points to, stores its key wrap metadata in the table 
`__KEYWRAP_METADATA__`, and stores its version metadata in the table
`__VERSION_METADATA__`. For simplicity, the constructor includes these values as
the defaults for the metadata tables. *Again, note that users require access to
each of these tables in order to be able to use the key store.*

#### Other Interfaces

In addition to the basic interface described above, we provide two interfaces to
fetch information that is needed in order to revoke keys. One defines a way to 
fetch all of the attributes held by a given user; the other defines a way to 
fetch all of the users who hold a given attribute.

The exact interfaces we define are as follows:

```python
class AbstractAttrUserMap(object):

    def users_by_attribute(self, attr):
        ...

    def delete_user(self, attr, user):
        ...

class AbstractUserAttrMap(object):

    def attributes_by_user(self, userid):
        ...

    def delete_attr(self, userid, attr):
        ...
```

Each of these takes as input an attribute or a user, and returns a list of users
or a list of attributes, respectively. There is also a `delete` function
associated with both interfaces; this is called by the revocation functions in
`KeyGen`, in case the underlying implementation needs to be told to delete a 
particular mapping when revocation occurs.

These interfaces are split up for the sake of modularity: if PACE is being
installed in an ecosystem that already has services that provide one or both of
these abilities, then those existing systems can be plugged in to this interface
with only some glue code. In a situation where no such services already exist,
however, there needs to be a backup solution. For these situations, we provide
an add-on to our Accumulo key store that also implements both of these 
interfaces, updating the appropriate mappings whenever a key wrap is added to 
the store.

The joint interface, found in `accumulo_keystore.py`, is initialized
similarly to an Accumulo key store, but with more arguments:

```python
from pace.pki.accumulo_keystore import AccumuloAttrKeyStore
import pyaccumulo

conn = pyaccumulo.Accumulo(...)  # connection info goes here
keystore = AccumuloAttrKeyStore(conn, meta_table='__KEYWRAP_METADATA__',
                                      vers_table='__VERSION_METADATA__'
                                      attr_user_table='__ATTR_USER_TABLE__',
                                      user_attr_table='__USER_ATTR_TABLE__')
```

This creates a keystore that has the same functionality as the one described
previously, but that additionally keeps track of user-attribute and
attribute-user mappings, in tables denoted by `attr_user_table` and
`user_attr_table`. As before, the default values for these arguments are
the same as those shown above.

## Testing

Unit tests for key generation and key storage are contained in 
`keygen_test.py` and `keystore_test.py` and can be run by running `nosetests` 
from a shell in the `pace/pki` directory with nosetests installed.
