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

# Accumulo Signatures

This is a Python library for client-side signing of Accumulo database entries.
It provides a function to automatically sign every entry in a pyaccumulo
mutation in an unmodified Accumulo instance.  Cryptographic signatures provide a
technical solution to guarantee end-to-end integrity of client data from
insertion to retrieval. Specifically, since malicious parties can not forge
signatures, by signing all data items inserted into Accumulo, a client can
verify that the data has remained unchanged.

## Installation

### Dependencies

This project depends on several other Python libraries and utilities. They are
listed below with links to their project pages. In addition to these packages,
it also requires a running Accumulo instance.

- [nosetests](https://nose.readthedocs.org/en/latest/), version 1.3.3+.
- [pyaccumulo](https://pypi.python.org/pypi/pyaccumulo), version 1.5.0.6+.
- [pycrypto](https://www.dlitz.net/software/pycrypto/), experimental release 
- 2.7a1.
- [pycryptopp](https://github.com/tahoe-lafs/pycryptopp), development version.
  We rely on 256-bit ECDSA signatures, which are not supported by the latest
  official release of `pycryptopp`. The latest version as of 16 September 2013,
  hosted on the project's github page, is the version we use.

## Use

To use the signature code, you must first import the signature module. You can
then create an AccumuloSigner with your private key.

```python
import pace.signatures.sign
signer = AccumuloSigner(privkey)
```

There are several optional arguments to the `AccumuloSigner` constructor, as
follows:

- `sig_f`: the signature function to be used. Must be one of the classes
  defined in `acc_sig.py` (as described below), and must be compatible with the
  private key provided as the first argument to the constructor. Default:
  `PyCryptopp_ECDSA_AccSig`.

- `default_visibility`: the name of the default visibility label, held by all
  users. Default: `"default"`.

- `signerID`: an optional identifier for the entity signing entries with the
  AccumuloSigner. This allows users to dynamically look up the verifying key to
  use to verify entries in the database (e.g. with some sort of public key
  infrastructure). If `None`, the object created will not write a signer ID to
  the metadata. Default: `None`.

- `conf`: a configuration object that stores information about the Accumulo
  database that both signers and verifiers need to have access to. This
  currently tells the Accumulo database where to store the signatures. Default:
  `VisibilityFieldConfig()`, which creates a new object that tells the signer to
  store signature metadata in the visibility field. See `signconfig.py` for more
  details and alternatives.

### Signing entries

Once you have an `AccumuloSigner` defined, you can sign a mutation created by
pyaccumulo:

```python
signer.sign_mutation(mutation, table)
```

where `table` is either `None` if the table name should not be included in the
signature (the default behavior), or the name of the table `mutation` will be
written to.

This is the only additional step needed when creating a mutation to write to an
Accumulo database. 

### Verifying entries

Verifying an entry requires an `AccumuloVerifier`, similar to signing an entry.
This function can be called in two different ways. In the first way, the public
key for everything being verified is known beforehand, so it is passed to the
verifier upon creation:

```python
verifier = AccumuloVerifier(pubkey)
```

If the signer included their unique ID in the signature metadata, the verifier
instead needs to take a PKI object (see below) as an argument, to be able to
look up the verifying key and the signature algorithm used:

```python
verifier = AccumuloVerifier(pki)
```

The `AccumuloVerifier` constructor also has an optional configuration argument,
as described above. It is important to make sure the configuration expected by
the verified matches the configuration supplied by the signer, or else the
verifier may look for metadata in the wrong place and fail.

To verify an entry with an `AccumuloVerifier`, one calls the `verify_entry`
method, as follows:

```python
verifier.verify_entry(raw_entry, table)
```

The first argument is the entry in the Accumulo table, including its metadata.
The second argument should be the name of the table the entry is in if that was
included in the signature, or `None` if the signature is independent of the
table. The default value for `table` is `None`.

The `verify_entry` method will return the entry cell without signature metadata
if the verification was successful. If not, it will raise a
`VerificationException`. This exception has two relevant fields: `msg`, for an
error message, and `cell`, which can contain either `None` if the verification
method failed before the actual signature verification stage (such as, for
instance, if it ran into malformed metadata), or the cell with the metadata
parsed out. This is useful for providing informative error messages when the
metadata is stored in the value field.

### Use example

```python
>>> # Imports
>>> import pyaccumulo
>>> import pace.signatures.sign
>>> import pace.signatures.verify
>>> from pace.signatures.signconfig import VerificationException
>>>
>>> from pace.signatures.acc_sig import PyCryptopp_ECDSA_AccSig
>>>
>>> # Connection setup
>>> conn = pyaccumulo.Accumulo(host='localhost', port='42424', user='root', password='secret')
>>> pubkey, privkey = PyCryptopp_ECDSA_AccSig.test_keys()
>>>
>>> # Create the signer and mutation
>>> signer = sign.AccumuloSigner(privkey, sig_f=PyCryptopp_ECDSA_AccSig)
>>> mutation = pyaccumulo.Mutation('test_row')
>>> mutation.put(cf='test_column_family', cq='test_cq', cv='default', val='this is a test value')
>>>
>>> # Sign the mutation and write it to a table
>>> signer.sign_mutation(mutation)
>>> conn.create_table('demo_table')
>>> wr = conn.create_batch_writer('demo_table')
>>> wr.add_mutation(mutation)
>>> wr.close()
>>>
>>> # Create the verifier
>>> verifier = verify.AccumuloVerifier(pubkey)
>>> 
>>> # Read the entry and verify its signature
>>> for entry in conn.scan('demo_table'):
...     try:
...             verifier.verify_entry(entry)
...             print 'verification succeeded'
...     except VerificationException as ve:
...             print 'verification failed:', ve.msg
...             if ve.cell is not None:
...                     print 'row:', ve.cell.row
...                     print 'val:', ve.cell.val
... 
verification succeeded
```

### PKI Objects

As mentioned above, verifiers can take in a public key interface (PKI) object as
an argument to use to look up a signer's keys. These objects are defined in the
directory `pace/pki/`, and more can be read about them in that
directory's README. We provide an abstract interface for PKIs that support
signature schemes and two implementations of this interface.

The class `SignatureMixin`, found in `signaturepki.py`, defines a method
`get_verifying_key(self, identifier)` for PKIs whose returned profiles contain a
`verifying_key` field and a `signature_scheme` field. This file also contains a
simple implementation of the PKI interface just for signatures,
`DummySignaturePKI`, used mostly for testing.

In `manualtruststore.py`, there is a more practical implementation of a
signature PKI in the form of a manually populated store of trusted entities, the
signature schemes they use, and their associated public keys. These can be
stored in a local file, where each entry contains three parts: one line for the
user's identifier, one line for the name of the signature algorithm they are
using (as defined in `vars.py`), and an arbitrary number of lines enclosed with
a public key header and footer that contain the relevant public key. For
example, if user `jdoe` wishes to store the key `ABCDE` using the PyCryptopp
implementation of ECDSA, the entry would be:

```
jdoe
ECDSA
-----BEGIN PUBLIC KEY-----
ABCDE
-----END PUBLIC KEY-----
```

In order to create a manual trust store object, one must call its constructor on
a path to the desired trust store file:

```python
ts = ManualTrustStore('keys/trust_store.txt')
```

One can then proceed to use `ts` as an argument to any signature code that
requires a PKI argument.

## Signature Algorithms

We provide a variety of options for what signature algorithm to use, each with
its own benefits and drawbacks. A brief description of them follows.

### RSA

Two different forms of RSA signatures are supported: PKCS1-v1-5 and PKCS1-PSS.

### Elliptic Curves

`Ecdsa` signatures are supported via the `pycryptopp` package. This package is
a Python wrapper for C++ code, specifically the `Crypto++` library. We currently
support 256-bit ECDSA on NIST-approved curve `secp256r1`.

### Best Practices

Currently, for performance and security reasons, we suggest using ECDSA via
`pycryptopp`, or if that is not an option, PKCS1-PSS, which is preferred to
PKCS1-v1-5 as it is robust (according to page 27 of
[RFC3447](http://www.ietf.org/rfc/rfc3447.txt)) without sacrificing significant
performance.

### Adding your own signatures

It is possible to add your own signature functions to this code. The interface
for a signature (defined in the `AbstractAccSig` class in `acc_sig.py`) requires
four definitions, as follows:

- `name`: the name of the signing algorithm as a string. Used to store the
  identity of the algorithm used as metadata in the Accumulo cell, and as a key
  in a Python dictionary.

- `sign(hash_value, privkey)`: a function that signs the hashed value of an
  entry with the private key. Returns the signature of `hash_value` with
  `privkey`.

- `verify(hash_value, signature, pubkey)`: a function that verifies a hash value
  against a signature and public key. Returns `True` if `signature` is a valid
  result of signing `hash_value` with the private key corresponding to `pubkey`,
  and `False` otherwise.

- `test_keys()`: returns a pair `(test_pubkey, test_privkey)` of a public and
  private key to be used for testing the signature algorithm.

- `parse_key()`: a function that takes a string as an argument and attempts to
  parse it into a verifying key for the class's signature algorithm. If it
  succeeds, it returns that verifying key; if it fails, it raises a
  `KeyParseError`.

- `serialize_key()`: a function that takes a verifying key and returns a
  serialization of that key as a string. This should be an inverse of
  `parse_key()`; that is, keys parsed, serialized, then parsed again should
  return the same verifying key after each parsing step.

Adding a signature algorithm takes two steps:

1. In `acc_sig.py`, implement the new algorithm in a new class ascribing to the
signature defined above.

2. In `vars.py`, add that new class to the variable `ALL_SIGNATURES`, and add a
mapping from the new signature algorithm's name to the new class in
`SIGNATURE_FUNCTIONS`.

After doing this, the new class can be used as an argument to the
`AccumuloSigner` constructor, and the testing framework (described below) will
automatically test it when run.

## Configuration Objects

Both signer and verifier objects take an optional configuration object as an
argument, as explained above. Configuration objects are a generic way of
representing configuration options common to both signers and verifiers.
Currently, the one option they support is where to store the signature metadata.

There are three options for metadata locations:

- Appended to the end of the visibility field
- Prepended to the beginning of the value field
- In a separate entry in a separate metadata table

### Creating configuration objects

We provide a function in `signconfig.py` called `new_config` to simplify the
process of creating new configuration objects to pass in to signer and verifier
objects. It takes a configuration file object and an Accumulo connection as
arguments:

```python
new_config(config_file, conn)
```

The config file should have a section called `Location`. The options for
this section are as follows:

- `loc`: where to store the signature metadata. Options are `vis` for the cell's
  visibility field, `val` for the cell's value field, and `tab` for a separate
  metadata table. If the option chosen is `tab`, the rest of the options listed
  in this section must also be provided. Default: `vis`.

- `is_batch`: whether to batch the elements inserted into the signature metadata
  table (if `yes`) or to stream them (if `no`).

- `metadata_table`: the name of the table to store the signature metadata in.

An example of a config file for writing batches of signature metadata to a table
called `__signature_metadata__` is as follows:

```cfg
[Location]
loc : tab
is_batch : yes
metadata_table : __signature_metadata__
```

This and other configuration file examples can be found in the `cfg/` directory.
Below is an example of how to use a configuration file:

```python
>>> from pyaccumulo import Accumulo
>>> from pace.signatures.signconfig import new_config
>>> 
>>> conn = Accumulo(port=42424)
>>> 
>>> with open('cfg/batch_test.cfg', 'r') as cfg_file:
...     cfg = new_config(cfg_file, conn)
... 
>>> cfg
<signconfig.BatchTableConfig object at 0x7ff99278bb90>
>>> signer = AccumuloSigner(privkey, conf=cfg)
>>> verifier = AccumuloVerifier(pubkey, conf=cfg)
```

### Configuration object methods

There are five methods over `SignConfig` objects. Two of them, `add_signature`
and `split_entry`, are only used inside the library and do not need to be used
by the user, but the other three are called by the user when the metadata is
being written to a separate table:

- `start_batch(self)` should be called when the user starts a batch to be
  created to insert into Accumulo. This should be around when a new pyaccumulo
  `BatchWriter` object is created.

- `update_batch(self, mutation)` should be called on each mutation that is
  entered into the batch.

- `end_batch(self)` should be called at the end of each batch. This should
  correspond to a call to `BatchWriter.close()`.

## Testing the code

We use a combination of nosetests for unit tests, and a larger python test
script to test against a running Accumulo instance. The unit tests can be run
just by running `nosetests` from the shell in the `pace/signatures/`
directory with nosetests installed.

The larger test scripts require a running Accumulo instance to run against. They
are located in the file `test_main.py`, and are invoked automatically by the
script `test.sh` with the arguments defined in that file, as follows:

- `TABLE`: the prefix to use for the tables created in the test. Default:
  `"newtest"`
- `HOSTNAME`: the hostname of the Accumulo instance to connect to. Default:
  `"localhost"`
- `PORT`: the port to connect to the Accumulo instance on. Default: `"42424"`
- `USER`: the username to log in to the Accumulo instance with. Default:
  `"root"`
- `PASSWORD`: the password for `USER`. Default: `"secret"`

To change any of these, modify the relevant variable in `test.sh`. Note that
these will only change the defaults in the test script; the defaults in the
python test file will remain the same when you invoke it from the command line.
