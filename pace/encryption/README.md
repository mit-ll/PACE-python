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

# Field Level Encryption and Cryptographic Enforced Attribute Based Access Control 

This is a Python library for client-side encryption of Accumulo database entries.
It provides the functionality to encrypt every entry in a pyaccumulo
mutation according to a user defined configuration. Field Level Encryption provides a solution
to the problem of providing confidentiality guarantees against a malicious server. 
The extended Cryptographic Enforced Attribute Based Access (CEABAC) library
extends that protection against curious clients in the case the malicious server does
not correctly enforce visibility labels. 

## Installation

Installation instructions for the pace module as a whole can be found in the README in the 
top level directory.

### Dependencies

This project depends on several other Python libraries and utilities. They are
listed below with links to their project pages. In addition to these packages,
it also requires a running Accumulo instance to run anything beyond the unit tests.

- [nosetests](https://nose.readthedocs.org/en/latest/), version 1.3.3+.
- [pyaccumulo](https://pypi.python.org/pypi/pyaccumulo), version 1.5.0.6+.
- [pycrypto](https://www.dlitz.net/software/pycrypto/).  This represents latest experimental release,
  2.7a1, as it implements Galios/Counter Mode.
- [Beaker](https://pypi.python.org/pypi/Beaker), version 1.7.0+.
- [enum34](https://pypi.python.org/pypi/enum34), version 1.0.4+.

## Use 

The primary interface for the confidentiality library is defined in
`acc_encrypt.py`. This is a high level interface for the encryption of
mutations and the decryption of cells. Our confidentiality library uses
pyaccumulo, a Python wrapper around Accumulo's Thrift interface, to interact with Accumulo
instances.

To encrypt or decrypt, users import the `AccumuloEncrypt`
class:

```python
    import pace.encryption.acc_encrypt.AccumuloEncrypt
    encrypter = AccumuloEncrypt(config_file, PKI_object)
```

Arguments for the class include a file pointer to a configuration file,
described in the section describing the [configuration file](#configuration-file), 
and a handle on a key management object
described in the following [section](#pki-objects). In short, the configuration file specifies
the types of encryption and what portions of the cell are to be encrypted
together, and where the ciphertext will be stored. The key management object
connects with the keystore where the user's encryption and decryption keys are
stored. Note that one configuration file represents the configuration of only
one Accumulo table. If the user wishes to use a different configuration
for another table, another `AccumuloEncrypt` object must be created with
that configuration file as a parameter.

### Configuration File

The configuration files input into the client-side encryption library
specify both the type of encryption desired as well as the formatting
of the cells. It is possible to individually encrypt each field in
the cell or to encrypt subsets of the cell in one ciphertext. In addition to 
encryption scheme and configuration information, the config file also
specifies the information needed to be given to the key object in order
to obtain encryption and decryption keys. 

This section presents the various options available in the configuration
file as well as several examples of such. More examples can be found in the 
`config` directory.

#### Basic syntax 

The files follow the basic format expected in Windows INI files and are
parsed with Python’s [configparser](https://docs.python.org/2/library/configparser.html)
tool. The basic syntax takes the form of: 

    [section]
    key_word = some_value


Each entry (a section and corresponding key words) specifies the encryption 
algorithm, key information and the parts of the cell to encrypt. The 
section title itself denotes the part of the cell where
the encrypted information will end up - the target location. For
example:

    [row]
    key_id = keyid1234
    encryption = Pycrypto_AES_CFB
    cell_sections = row
    cell_key_length = 16


In this case the row of the cell is to be encrypted with AES in 
CFB mode and placed back in the row. 

Each entry must have a `key_id` and `encryption` keyword specified, 
`cell_sections` and `cell_key_length` is optional.  

####Section
The section headers are:
* row
* colFamily
* colQualifier
* colVisibility
* value 

At this time it is not possible to encrypt either the `timestamp` or the
`to_delete` portion of an Accumulo cell - it would break functionality 
of Accumulo in a significant way. 

####Key_id
The `key_id` is the identifying information needed to obtain the keys
needed for encryption/decryption and is handed to the 
`key_object` to use (see `pki/abstract_pki.py` for more information).
The `key_id` is treated as a string before it is handed to the `key_object`.

This may be some combination of user information, the algorithm being
used, or whether it is an encryption or decryption query. Note, if the 
user wishes to have different keys for each table, this would where it
would be specified i.e. `key_id = table_A`. This value 
is what is specified in the metadata in the configuration files used in key generation, see the 
[Readme](pki/README.md) under Configuration File Format for more information.




####Encryption 
The confidentiality library uses
[Pycrypto](https://www.dlitz.net/software/pycrypto/) to implement
the different modes of AES. For semantically secure encryption we offer several
modes: Cipher Feedback Mode, Cipher Block Chaining Mode, Output Feedback Mode,
and Counter Mode. Of the four of these modes, we recommend Pycrypto's
implementation of Output Feedback Mode, as it is the fastest of the four. For
authenticated semantically secure encryption, we support Galois Counter Mode.
Finally, for deterministic encryption we use Synthentic IV mode
(SIV), which, when used without a nonce, is deterministic.

We also support an `identity` mode, which exercises the confidentiality library's logic for
parsing mutations, but does not actually encrypt the plaintext values.

The names in the configuration files are as follows: 

* Identity - Useful for testing, it is simply the identity function
* Pycrypto_AES_CFB - The Pycrypto implementation of AES in CFB mode
* Pycrypto_AES_CBC - The Pycrypto implementation of AES in CBC mode
* Pycrypto_AES_OFB - The Pycrypto implementation of AES in OFB mode
* Pycrypto_AES_CTR - The Pycrypto implementation of AES in CTR mode
* VIS_Identity - Constructs the shares of the cell_key but does not
				encrypt them, used primarily for demo purposes
* VIS_AES_CFB - Cryptographically Enforced ABAC that uses AES in CFB mode
				 to encrypt the shares and value
* VIS_AES_CBC - Cryptographically Enforced ABAC that uses AES in CBC mode
				 to encrypt the shares and value
* VIS_AES_OFB - Cryptographically Enforced ABAC that uses AES in OFB mode
				 to encrypt the shares and value
* VIS_AES_CTR - Cryptographically Enforced ABAC that uses AES in CTR mode
				 to encrypt the shares and value
* VIS_AES_GCM - Cryptographically Enforced ABAC that uses AES in GCM mode
				 to encrypt the shares and value	
	 
####Cell_sections 

`cell_sections` specifies the portions of the cell that are to be encrypted
together and placed in the target location. As stated above, it is an 
optional field, and if not specified, it is assumed that
the portion of the cell to be encrypted is the one specified in the
section header. 

If one wishes to encrypt more than one portion of the cell, the format
is a comma separated list of cell locations, as demonstrated in the 
example below:

    [colFamily]
    key_id = keyid234
    encryption = Pycrypto_AES_CFB
    cell_sections = colFamily,colQualifier

Possible values for `cell_sections` are the same as those listed in
section headers in any combination:
* row
* colFamily
* colQualifier
* colVisibility
* value 


####Cell_key_length

`cell_key_length` specifies the length (in bytes) of the cell key
that is generated to be shared amongst the different attributes. 
It is only used for encryption schemes that use Cryptographically 
Enforced ABAC - if not specified for these schemes it defaults to
16 bytes. Currently allowed values include 16, 24, and 32 bytes.
If it is present for a non-CEABAC algorithm, the value
will be ignored.


### PKI Objects 

The key management object passed into the `AccumuloEncrypt` represents the
interface to acquire keys for encryption and decryption from the keystore. We
provide an abstract interface that it must meet and an instantiation that
communicates with an Accumulo keystore. More information can be found in the 
README in the `pki` directory.

At a high-level, there are two types of key: attribute keys used for CEABAC,
and non-attribute keys strictly used for standard AES encryption modes. Symmetric key
cryptography is used throughout the confidentiality library, thus the same key
is used for encryption and decryption. The interface that all encryption key
objects meet inherits from `AbstractPKI`, which both the signature
and encryption key infrastructures are based on. The
abstract class, `EncryptionPKIBase`, is found in
`encryption_pki.py`.  Instantiations of this class must implement four
methods:

* `get_current_key(algorithm)`: retrieves the most recent version of
the non-attribute key for the associated algorithm, to be used when new records
are being encrypted and inserted into Accumulo. It is used for non-CEABAC
algorithms.

* `get_key(algorithm, version)`: retrieves that particular version of the  non-attribute key for the
associated algorithm. In this case, the algorithms that use this method are non-CEABAC schemes. This method
is used during decryption when the version information is extracted from the ciphertext to obtain the
key to decrypt the rest of the message.

* `get_current_attribute_key(algorithm, attribute)`: retrieves the current version of the
attribute key for the algorithm. Used to acquire the most recent key, which is used to encrypt new
 records to insert. This is used for CEABAC schemes, and the `attribute` parameter corresponds to the attributes found in
visibility fields in Accumulo.
* `get_attribute_key(algorithm, attribute, version)`: retrieves that version of the attribute key
for a particular attribute-algorithm pairing. The `attribute` parameter corresponds to the attributes found in
visibility fields in Accumulo. This method is used during decryption in CEABAC algorithms to obtain
the attribute key to decrypt the shares of the cell key.

Algorithms specified as arguments for all these functions are the same name
defined in the configuration file as the `key_id`, such as
`Pycrypto_AES_CBC` or `VIS_AES_CTR`.

We provide an implementation of the interface that communicates with the
Accumulo keystore. Users
can declare a `pki` instance by:

```python
    pki = EncryptionPKIAccumulo(conn, user_id, private_rsa_key)
```

The class takes in three arguments. The first, `conn`, is the connection,
as defined in Pyaccumulo, to the Accumulo instances that is storing the keys.
The second, `user_id`, is the string that represents the user currently
encrypting or decrypting records. This value must be synchronized with the key
generation process, as it used during key lookup. Note that in
this implementation a particular instance of `EncryptionPKIAccumulo`
corresponds to one particular user.  The final argument is the user's
private RSA key corresponding to the public key used during keywrapping in key
generation. Again, see the README in the `pki` for more information.

There exist two other implementations of the `EncryptionPKIBase` interface.
The first is an extension of `EncryptionPKIAccumulo`, called
`CachingEncryptionPKIAccumulo`, which uses
[beaker](http://beaker.readthedocs.org/en/latest/) to cache the
results of querying the keystore for an hour. This improves performance and
reduces hits on the keystore. The second is `DummyEncryptionPKI`, which
contains hardcoded keys and is useful for unit tests and other demos. Both are
defined in `encryption_pki.py`.


### Encrypting Entries

Once the `encrypter` is created, users can construct encrypted mutations
by passing in a plaintext mutation:

```python
    encrypted_mutations = encrypter.encrypt(mutation)
```

The mutation passed in is not changed; instead, it is used to construct a
list of encrypted mutations according to the configuration file passed in at
initialization. A list of mutations is constructed instead of a single mutation
because the row must be encrypted separately for each column/value in the mutation. 
The generated mutations only contain a single update. This list 
of encrypted mutation can now be written to Accumulo using a
writer as one would with a normal mutation.

### Decrypting Entries

Decrypting the results retrieved from Accumulo also requires an
`AccumuloEncrypt` object. The structure received from a scan is a cell,
which can be directly passed into the decrypt method of the encrypter object:

```python
    cell = encrypter.decrypt(encrypted_cell)
```

As with the mutation, the encrypted cell is not changed, but is used to
construct a decrypted version of the cell. The returned cell has its fields that
were encrypted together placed back in their original fields.

### Searching for Entries

The confidentiality library supports several types of scans, depending how the 
leading portion of the cell (the row and column) is encrypted. For configurations
that encrypt the row with semantically secure encryption, the only scan supported is
a full-table scan, where individual
records are pulled back all at once and decrypted until the information the user
wants is found:

```python
    for entry in conn.scan(table):
        cell = encrypter.decrypt(entry)
```

For configuration files that use deterministic
encryption on the cell's row or column values, it is possible
to do a targeted equality scan. For example, if the `row` is
encrypted using deterministic encryption, one can search for all instances of
the row 'a' by doing the following:

```python
    enc_row, _ = encrypter.encrypt_search('a')
    range = pyaccumulo.Range(srow = enc_row, erow = enc_row)
    entries = conn.scan(table, scanrange = range)
```
If the column is encrypted using deterministic encryption as well
it is possible to search over the columns as well. This includes 
encrypting both the colFamily and colQualifier as part of the same 
ciphertext. An example is shown below:

```python
    enc_row, enc_cols = encrypter.encrypt_search('a',[['colFam1','colQual1'],['colFam2',colQual2']])
    range = pyaccumulo.Range(srow = enc_row, erow = enc_row)
    entries = conn.scan(table, scanrange = range, cols = enc_cols)
```

Finally, when the row in a cell, or leading portion of the cell remains unencrypted, 
normal Accumulo range queries can be used. 

### Use Example

```python
# Imports
import pyaccumulo
from  pace.encryption.acc_encrypt import AccumuloEncrypt
from  pace.encryption.encryption_pki import EncryptionPKIAccumulo

# Connection setup
pki_conn = pyaccumulo.Accumulo(host='localhost', port='42424', user='root', password='secret')
conn = pyaccumulo.Accumulo(host='localhost', port='42424', user='root', password='secret')


# Create the key object, encrypter and mutation
# NB: rsa_key must be the key used to wrap keys in the keystore, and user1 must exist with the proper keys
pki = EncryptionPKIAccumulo(pki_conn, 'user1', rsa_key)
encrypter = AccumuloEncrypt('config_file.cfg', pki)
mutation = pyaccumulo.Mutation('test_row')
mutation.put(cf='test_column_family', cq='test_cq', cv='default', val='this is a test value')

# Encrypt the mutation and write it to a table
encrypted_mutations = encrypter.encrypt(mutation)
conn.create_table('demo_table')
wr = conn.create_batch_writer('demo_table')
for mutation in encrypted_mutations
    wr.add_mutation(mutation)
wr.close()

# Search for and decrypt the mutation 
range = pyaccumulo.Range(srow = 'test_row', erow = 'test_row')
encrypted_range = encrypter.encrypt_search(range)

for entry in conn.scan('demo_table', scanrange = encrypted_range):
    cell = encrypter.decrypt(entry)
    
```

## Testing Code

 The unit tests can be run just by running `nosetests` from the 
shell in the `pace/encryption/` directory with nosetests installed.
