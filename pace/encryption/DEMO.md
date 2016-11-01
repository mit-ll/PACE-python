# Confidentiality Demo Commands

This document contains documentation for the commands, primarily in `demo.py`,
for quickly getting up to speed on and running our client-side encryption code
for Accumulo users. This includes field-level encryption, Cryptographically
Enforced Attribute Based Access Control (CEABAC), and the key management
infrastructure that supports CEABAC. Users should read this file if they want a
tour of what our encryption code can accomplish and a look at how this code
works behind the scenes.

## Setup

When trying out our functionality, it is useful to be able to see both the
output shown to the user and the information stored on the server. This is
particularly useful when demonstrating the protections PACE adds, in this case
in terms of how little the server can learn about the users' information it
stores.

For this demo, we will denote the client's view as a Python interpreter shell,
and the server's view as the Accumulo shell. The client view will look as
follows:

```
$ python -i demo.py
>>> run_insert
<function run_insert at 0x...>
>>> 
```

We will represent the server view as follows:

```
$ $ACCUMULO_HOME/bin/accumulo shell -u root
Password:
root@server> create_table test_table
root@server test_table> scan
...
root@server test_table> 
```

Note that throughout this demo, we provide sample table names for each of these
commands. When running the commands multiple times, it is useful to either vary
the table names or delete the old versions of the tables, to avoid collisions.

## demo.py commands

To simplify the insertion process into Accumulo, we have defined a function
`run_insert()` in demo.py, with arguments as follows:

```python
def run_insert(conn, data, table, config_name, PKI_object):
    ...
```

- `conn`: the connection to use to connect to Accumulo. Default: `None`, which
  will set the connection to `Accumulo(host='localhost', port=42424,
  user='root', password='secret')`.
- `data`: a list of five-tuples, where each field in order represents the row,
  visibility, column family, column qualifier, and value. This list is the data
  to be inserted into `conn`; we provide several sample values for this at the
  top of `demo.py`. The default value is `expressive_elems`, one of these sample
  values.
- `table`: the name of the table into which to insert `data`. Default: `'demo'`.
- `config_name`: the name of the schema to use to encrypt the data, to look up
  in the `schema` dictionary at the top of the file. Default: `'expressive'`.
- `PKI_object`: the PKI object to connect to in order to fetch encryption and
  decryption keys. Default is `None`, which defaults to `DummyEncryptionPKI`,
  from `encryption_pki.py`. Note that this has hardcoded values stored in it,
  and as such will suffice for most of this demo, but a live PKI instance will
  also work.

Dual to this, we also define `run_retrieve()`, which retrieves and decrypts
all values from a given Accumulo table:

```python
def run_retrieve(conn, table, config_name, PKI_object):
    ...
```

These arguments are the same as above, with the exception of `data`, which is
not present as an argument to `run_retrieve()`.

To perform more specific searches, we also provide `run_search()`, which
performs a targeted search for a specific deterministically encrypted row in a
table:

```python
def run_search(conn, table, config_name, PKI_object, row_range):
    ...
```

Again, the arguments are the same as above, except for the new argument,
`row_range`, which is the name of the row to search for. The default value for
this argument is `'Analytics'`, which works well with some of our default data.

For testing our PKI infrastructure, we provide two more functions,
`run_pki_insert()` and `run_revoke()`:

```python
def run_pki_insert(genpath, user, conn):
    ...

def run_revoke(user, attr, genpath, conn):
    ...
```

Each of these functions takes an argument `conn`, as previously defined, and
`genpath`, which denotes a path to a file containing a list of user information.
This defaults to `'../pki/user_info.cfg'` for both functions.

The `user` argument for `run_pki_insert()` does not change the information
inserted into the PKI, but denotes the user to connect to the PKI as in the
return value. This function returns two values: `pki`, an encryption PKI that
can be used as an argument to any of the functions above that take a
`PKI_object` argument, and `fe`, a PKI front-end object that can be used to show
the contents of the PKI, and is documented in the section on using the PKI.

`run_revoke()` is responsible for revoking a user's access to a given attribute
in the key store hosted at `conn`. It takes `user` and `attr` arguments, and
revokes that user's access to that attribute in the key store.

When running the demo, it is important not to interleave calls using a live PKI
and calls using the dummy PKI, as they will interact destructively with one
another. If this happens, it is necessary to reinitialize the PKI object with
`run_pki_insert()`.

## Field-level encryption

To insert elements into an Accumulo table with no encryption, run an insert
using `'none'` as the `config_name` argument:

```
>>> run_insert(table='demo_table_none', config_name='none')
Enrypting with the following schema: 

Currently using no encryption scheme
Inserting entry: 
 Row - MITLL,
 Column_Visibility - (a&b)|c,
 Column_Family - Analytics,
 Column_Qualifier - Rooms,
 Value - 1200
...
>>>
```

The server can then read this data as follows:

```
root@server> scan -t demo_table_none
Boston Analytics:Population [(a&b)|c]    3000000
Cambridge Analytics:Population [(a&b)|c]    400000
MITLL Analytics:Employees [(a&b)|c]    4000
MITLL Analytics:Rooms [(a&b)|c]    1200
root@server> 
```

In order to hide data from the server, we can encrypt it with a scheme. For
example, the default scheme:

```
>>> run_insert(table='demo_table_default')
Enrypting with the following schema: 

Row contains: Row encrypted with Pycrypto_AES_SIV
ColFamily contains: ColFamily & ColQualifier encrypted with Pycrypto_AES_CFB
ColQualifier contains: Nothing
Value contains: Value encrypted with AES_GCM

Inserting entry: 
 Row - MITLL,
 Column_Visibility - (a&b)|c,
 Column_Family - Analytics,
 Column_Qualifier - Rooms,
 Value - 1200
...
>>>
```

Running this server-side, all the server can see beyond the visibility field is
that several of the rows (which are encrypted with deterministic encryption)
have the same value; the rest will have different values each time, as they are
randomized:

```
root@server> scan -t demo_table_default
I\xB3\x82\xF1\xC1\xB3y\x8C\xED\xB6\xD9-\x1B\xD9\x855\xBD\x1D\x9B\x97[+ver1
\x06\xF9\xC8\xDD(w\x98\xECp\xE6\xE70)\x08\x10\xB7\xE3\xFD_r\xD9\x98\xBE\xB9lI^\x91\xF5\x95\x80\x8B\xB4M\x05\x0Aver3:
[(a&b)|c]
"\xF9\xFFE\xE4\x05\xC4\x09\\\x02\xB5\x87\xEE\xA5\xE8d\xCCV\xF7t\xBD$),f=\x98\x0E~\xB8\x8B\xEF\x8C-\xD7\xFAz\xB9\x9A\xA2\x0A\xDC\xA0\xCFxJ:\x92ver3
...
root@server> 
```

We can also get a more legible view of the server's state client-side with the
`'print_pretty'` config:

```
>>> run_retrieve(table='demo_table_default', config_name='print_pretty')
Entry: 
 Row - SbOC8cGzeYztttktG9mFNb0dm5dbK3ZlcjE=,
 Column_Visibility - (a&b)|c,
 Column_Family - BvnI3Sh3mOxw5ucwKQgQt+P9X3LZmL65bElekfWVgIu0TQUKdmVyMw==,
 Column_Qualifier - ,
 Value - Ivn/ReQFxAlcArWH7qXoZMxW93S9JCksZj2YDn64i++MLdf6ermaogrcoM94SjqSdmVyMw==
...
>>>
```

This formats the cell by field and base 64 encodes encrypted values for
legibility, but does not decrypt anything. We can also decrypt the values
client-side:

```
>>> run_retrieve(table='demo_table_default')
Entry: 
 Row - Boston,
 Column_Visibility - (a&b)|c,
 Column_Family - Analytics,
 Column_Qualifier - Population,
 Value - 3000000
...
>>>
```

As discussed previously, since the row in this data is encrypted
deterministically, we can also perform a targetted query on specific rows of
data by encrypting the row and searching on the ciphertext, using
`run_search()`:

```
>>> run_search(table='demo_table_default', row_range='Boston')
Entry: (Boston, Analytics, Population, 3000000)
Finished, decrypted 1 total entries.
>>> run_search(table='demo_table_default', row_range='MITLL')
Entry: (MITLL, Analytics, Rooms, 1200)
Entry: (MITLL, Analytics, Employees, 4000)
Finished, decrypted 2 total entries.
>>>
```

## Cryptographically enforced access control

In addition to field-level encryption, as shown above, we also support
cryptographic enforcement of Accumulo's visibility expression-based access
control. This involves two components: a key management system to generate a
different AES key for each attribute that can occur in the Accumulo
installation, and protocol that uses these keys to encrypt data in such a way
that no user without permissions that satisfy a cell's visibility field can
decrypt the value stored in that cell, since they will also not have access to a
set of keys that can decrypt it.

To generate a PKI object, one uses `run_pki_insert()`, as described earlier in
this document:

```
>>> pki, fe = run_pki_insert()
...
>>> pki
<pace.encryption.encryption_pki.EncryptionPKIAccumulo object at 0x...>
>>> fe
<pace.pki.frontend.KeyStoreFrontEnd object at 0x...>
>>>
```

This function has two return values. The first, `pki`, is what we will pass in
as an argument to functions that need to access the keys stored here. Note that
this _cannot_ be used in conjunction with the default PKI generated when no
`PKI_object` argument is provided; if these are accidentally mixed up, the PKI
object must be regenerated with `run_pki_insert()`.

The other object is `fe`, a front end to the key store from which the user
retrieves their keys. It can show all of the attributes that a user has access
to, and a base 64 encoding of their keywraps, for readability. This is done with
the `view()` method:

```
>>> fe.view()
No metadata specified
Using default metadata VIS_AES_CFB

No username specified
Using default username user1

No attribute specified
Showing all attributes

Showing key information for user: user1
Metadata being used: VIS_AES_CFB
========================================

Key attribute: a
Key version  : 1
Keywrap:
KelcP0WWpXZkIkcN...
```

Note that this uses certain default values for the metadata, username, and
attribute to view. This is because it has three arguments, as follows:

- `metadata`: the metadata to view in the key store. Defaults to `None`, which
  shows keys corresponding to all metadata values.
- `user`: the user whose keys to view. Defaults to `None`, which prints a
  message and sets `user` to `'user1'`.
- `attr`:  the attribute to view in the key store. Defaults to `None`, which
  shows keys corresponding to all attributes.

By default, we generate a key store with three users, `user1`, `user2`, and
`user3`. Users 1 and 2 have access to attributes a, b, c, and d; user 3 only has
access to a, c, and d.

Once this PKI is generated, it can be used when encrypting cells based on their
visibility field, using what we call Cryptographically Enforced Attribute Based
Access Control (CEABAC). The config name `'vis'` uses this scheme to encrypt
values in its table:

```
>>> run_insert(table='ceabac', config_name='vis', data=vis_elems, PKI_object=pki)
...
>>>
```

Note that this protects data from being disclosed to users without permissions
to access it. For example, suppose the server removes the requirement for the
attribute `b` from one of the cells:

```
root@server ceabac> insert Analytics '' '' <a&b ciphertext> -l a&a
root@server ceabac> getauths -u user3
a,c,d
root@server ceabac>
```

If user `user3` attempts to scan this table, they will not receive meaningful
output when attempting to decrypt this element:

```
>>> grant_auths(table='ceabac')
>>> run_retrieve(table='ceabac', config_name='vis', PKI_object=user3_pki)
...
Entry: 
 Row - Analytics,
 Column_Visibility - a&a,
 Column_Family - ,
 Column_Qualifier - ,
 Value - ,C�
...
>>> 
```

## Key revocation

We also support the ability to revoke a user's access to certain attributes and
keys. We support forward security (a user can still decrypt old information, but
no new information encrypted under that attribute) by assigning versions to
keys. Each time an attribute is revoked, a new version is generated for its
associated key and distributed to users. Suppose we have a user `user2` whose
permission to the attribute `b` we wish to revoke:

```
>>> user2_pki, user2_fe = run_pki_insert(user='user2')
>>> 
```

If we insert elements into a table as root, revoke the key, and perform a query
as `user2`, the data will still be decryptable if `user2` cashed their keys:

```
>>> run_insert(table='revoke', config_name='vis', data=vis_elems, PKI_object=pki)
...
>>> run_revoke('user2', 'b')
>>> run_retrieve(table='revoke', config_name='vis', PKI_object=user2_pki)
...
Entry: 
 Row - Analytics,
 Column_Visibility - a&b,
 Column_Family - ,
 Column_Qualifier - ,
 Value - 200
...
>>> 
```

However, if we re-insert the data as root, we use a new key version, thus making
it invisible to `user2`:

```
>>> run_insert(table='revoke', config_name='vis', data=vis_elems, PKI_object=pki)
>>> run_retrieve(table='revoke', config_name='vis', PKI_object=user2_pki)
...
Error: Entry failed to decrypt.
Error message: The key object does not contain keys for the necessary attributes
to decrypt this cell
...
>>> 
```
