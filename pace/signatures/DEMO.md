# Signatures Demo Commands

This document contains documentation for the commands, primarily in `demo.py`,
for quickly getting up to speed on and running our client-side signature code
for Accumulo users. Users should read this file if they want a tour of what our
signatre code can accomplish and a look at how this code works behind the
scenes.

## Setup

When trying out our code, it is useful to be able to see both the output shown
to the user and the information stored on the server. This is particularly
useful when demonstrating the protections PACE adds, in this case the server's
inability to modify signed data without detection.

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
$ accumulo shell -u root
Password:
root@server> table test_table
root@server test_table> scan
...
root@server test_table> 
```

## demo.py commands

To simplify the insertion process into Accumulo, we define a function
`run_insert()` in demo.py, with arguments as follows:

```python
def run_insert(conn, data, table, signClass, privkey, loc, default_vis, sign):
    ...
```

- `conn`: the connection to use to connect to Accumulo. Default: `None`, which
  will default to the connection `Accumulo(host='localhost', port=42424,
  user='root', password='secret')`.
- `data`: a list of row-value pairs to be stored in Accumulo. We provide a
  sample list of data, `elems`, that is also the default argument for this
  value.
- `table`: the name of the table into which to insert `data`. Default: `'demo'`.
- `signClass`: the signature class, as defined in `acc_sig.py`, to use to sign
  the elements inserted into the table. Default: `PyCryptopp_ECDSA_AccSig`,
  which signs using ECDSA.
- `privkey`: the private key to use to sign the elements of `data`. Default:
  `None`, which uses the testing key returned by `signClass.test_keys()`.
- `loc`: the location in which to store, chosen from the strings `'vis'` (store
  in the visibility field), `'val'` (store in the value), or `'tab'` (store in a
  separate table). Default: `'val'`.
- `default_vis`: when storing a signature in the visibility field of a cell, if
  the visibility field was previously empty, we add a default attribute to that
  cell that all users have access to. This is configurable by this argument,
  whose default value is `UNCLASS`.
- `sign`: whether or not to sign the data. Default: `True`; set to `False` when
  you only want to insert the data by itself into Accumulo, such as to compare
  the size overhead between signed and unsigned data.

Dual to this, we also define `run_verify()`, which retrieves and verifies the
signatures of all values in a given Accumulo table:

```python
def run_verify(conn, table, signClass, pubkey, loc):
    ...
```

These arguments are the same as above, with the exceptions of `data`, which is
not present as an argument to `run_verify()`, and `pubkey`, which replaces
`privkey` and is used to verify the signatures stored in the table.

## Usage

First, we can sign and insert data into Accumulo:

```
>>> run_insert(table='sig_demo')
Inserting signed row: Mission A, value: 0200
Inserting signed row: Mission B, value: 2200
Inserting signed row: Mission C, value: 1000
Inserting signed row: Mission D, value: 0300
Inserting signed row: Mission E, value: 1100
>>> 
```

We can then verify the data we just inserted:

```
>>> run_verify(table='sig_demo')
Finished, with 5 successes out of 5 total entries.
>>>
```

The server can see both the data stored, and the signature of that data (in this
case, stored in the value field as directed by the default value for `loc`):

```
root@server> scan -t sig_demo
Mission A : [UNCLASS]
PyCryptopp_ECDSA|5k7/xi1gbUSmctbKVaKitR4nV9f86nbns21SZPbX6HJc3aPB8F2AHMtbcM6CUp6WP8WqXU8x5frUFcDvjTACwg==|0200
root@server> 
```

In this case, there are three elements stored in the value field, denoted by
pipe characters:

- The name of the signature algorithm used, in this case `PyCryptopp_ECDSA`.
- The cell's signature.
- The value, in this case `0200`.

If the malicious server would like to modify or add a value, they can do so:

```
root@server> table sig_demo
root@server sig_demo>nsert "Mission A" "" ""
PyCryptopp_ECDSA|5k7/xi1gbUSmctbKVaKitR4nV9f86nbns21SZPbX6HJc3aPB8F2AHMtbcM6CUp6WP8WqXU8x5frUFcDvjTACwg==|2200
-l UNCLASS
root@server sig_demo> insert "Mission F" "" ""
PyCryptopp_ECDSA|5k7/xi1gbUSmctbKVaKitR4nV9f86nbns21SZPbX6HJc3aPB8F2AHMtbcM6CUp6WP8WqXU8x5frUFcDvjTACwg==|0400
-l UNCLASS
root@server sig_demo> 
```

This overwrites the prior value for Mission A with 2200, and adds a new mission,
Mission F, with value 0400. However, note that the server uses the original
signature from Mission A for both of these spurious fields. Since it is
computationally intractable for the server to determine the signature for data
if it does not have the corresponding signing key, it cannot do better than this
signature here, and consequently the client can detect these malicious changes:

```
>>> run_verify(table='sig_demo')
Error: Entry failed to verify.
Entry row: Mission A
Entry val: 2200
Error message: Failed to verify the signature

Error: Entry failed to verify.
Entry row: Mission F
Entry val: 0400
Error message: Failed to verify the signature

Finished, with 4 successes out of 6 total entries.
>>>
```

We can also try storing the signature in different locations:

```
>>> run_insert(table='sig_demo_vis', loc='vis')
...
>>> run_insert(table='sig_demo_tab', loc='tab')
...
>>>
```

```
root@server> scan -t sig_demo_vis
Mission A :
[UNCLASS|",PyCryptopp_ECDSA,ntDBZaoqHl/IqfKteOe2io1ycmKQl4bNLkWy6aTuwT++o1jXN7eQzZpOEm3n8YoYfAwRcv36WHEThDamPlH+Og==,"]
0200
...
root@server> scan -t sig_demo_tab
Mission A : [UNCLASS]    0200
...
root@server> 
```

Note that when the signatures are stored in a separate table, the signed cell
looks exactly how it would look without using signatures at all. The signatures
themselves are stored in a separate table, generated by prepending
`'__sig_metadata__'` to the name of the original table:

```
root@server> root@pace-liz sig_demo> scan -t __sig_metadata__sig_demo_tab
('Mission A', '', '', 'UNCLASS', None) : [UNCLASS]
PyCryptopp_ECDSA,kWS4OdjJyjO4HKxAhy/DfzAkBsd5HL6rh/kjpOVNXO97z7hlOtK9YMnRwDUzBPV/w6/01K+XGnBakJsBOv5CPg==
...
root@server>
```

This separate table stores mappings from a key in the original table to the
signature corresponding to the cell with that key, allowing the user to look
up signatures as they receive query results.
