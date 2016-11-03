# Proactively-secure Accumulo with Cryptographic Enforcement (PACE)

The PACE library's goal is to add cryptographic protections to the Accumulo
database. This currently takes the form of a client-side library containing
cryptographic protections against a malicious Accumulo server, such as a
compromised server machine or system administrator. This README serves as
high-level documentation for the entire library; more low-level information can
be found in the documentation for each subpackage.


## Installation

Once you have the [Dependencies](### Dependencies) installed, you can install PACE by running
`python setup.py install` in the main `pace-<version>` directory.  You may
need to provide sudo access.

It is recommended to run `nosetests` in the main folder when the installation
is complete, to ensure that everything installed correctly.  They typically run
in 300-500 seconds.  If it takes significantly longer, see the section on [Configuring Fastmath](### Configuring Fastmath) below.

To connect to a live Accumulo instance, you will need to run Accumulo with a proxy.  See the section on [Running the Thrift Proxy](### Running the Thrift Proxy) for more details.

### Dependencies

PACE depends on the following user installations.  These must be installed
manually on your system:
   - [python 2.x](https://www.python.org/)
   - [GCC with C++ support](https://gcc.gnu.org)
   - [MPFR](http://www.mpfr.org/)
   - [GMP](https://gmplib.org/)
   - [pycryptopp 0.6.0.39+](https://pypi.python.org/pypi/pycryptopp)
   - [pycrypto 2.7a1](https://www.dlitz.net/software/pycrypto/)
   - [thrift](https://thrift.apache.org/download)

PACE also depends on the following Python packages.  If you have a repository
source that Python can access by default, then the PACE installer will install
these automatically.  If not, you will need to install them by hand.
   - [nosetests](https://nose.readthedocs.org/en/latest/), version 1.3.3+.
   - [pyaccumulo](https://pypi.python.org/pypi/pyaccumulo), version 1.5.0.6+.
   - [Beaker](https://pypi.python.org/pypi/Beaker), version 1.7.0+.
   - [enum34](https://pypi.python.org/pypi/enum34), version 1.0.4+.
   - [distribute](https://pypi.python.org/pypi/distribute), version 0.6.14+.


### Configuring Fastmath

One of the dependencies of PACE can be configured to use "fastmath," which
means that it will use GNU's Multiple Precision arithmetic library (GMP) in 
place of Python's standard (slower) arithmetic functions.  It is recommended 
(though not required) to use fastmath, as it greatly speeds up many of PACE's
operations.

If the tests are running very slowly (more than 1000 seconds), then fastmath 
is not running, and there is
probably a configuration problem with `pycrypto` and `gmp`.  To fix it, first
note the location of `gmp.h`.  On Ubuntu, it is likely in `/usr/include/gmp.h`.
On CentOS, it is probably in `/opt/gmp/include/gmp.h`.  If you can't find it,
do `sudo find / -name "gmp.h"`.  Call the location above the include folder 
`<gmp-home>`.  For instance, in CentOS, `<gmp-home>` is `/opt/gmp`.

Inside the `pace-<version>` directory, navigate to 
`dependencies/shared/src/pycrypto`.  Run 
```bash
./configure --includedir=<gmp-home>/include --with-gmp
```
Open up src/configure.h and make sure the following definitions are set:
```
#define HAVE_DECL_MPZ_POWM 0
#define HAVE_DECL_MPZ_POWM_SEC 0
#define HAVE_LIBGMP 1
```
Warning: Make sure you do this _after_ you run the previous `configure` 
command, otherwise fastmath may not work correctly!

Now, edit the `setup.py` file in the `pycrypto` directory and search for
"`_fastmath`".  Make sure the `Extension` declaration looks like this:
```
# _fastmath (uses GNU mp library)
Extension("Crypto.PublicKey._fastmath",
          include_dirs=['<gmp-home>/include', 'src/', '/usr/include'],
          library_dirs=['<gmp-home>/lib'],
          libraries=['gmp'],
          sources=["src/_fastmath.c"]),
```

Finally, rebuild and install pycrypto with
```bash
sudo python setup.py build
sudo python setup.py install
```
If it worked, then the build command should have printed
```
building 'Crypto.PublicKey._fastmath' extension
```
and you can now enter python and try to import fastmath by doing:
```bash
python
>>> from Crypto.PublicKey import _fastmath
```

If the build command gives the following warning
```
warning: GMP or MPIR library not found; Not building Crypto.PublicKey._fastmath.
```
then try completely removing pycrypto by doing the following three steps:
1. Remove the `pycrypto` folder from the pace dependencies folder.
2. Remove the `egg-info` file from python's list of packages by running the
   following command.  Replace `<version>` with your python version, either 
   2.6 or 2.7.
   ```
   sudo rm /usr/lib64/python<version>/site-packages/pycrypto-2.7a2-py<version>.egg-info
   ```
3. Remove the `Crypto` folder from the same location:
   ```
   sudo rm -r /usr/lib64/python<version>/site-packages/Crypto
   ```
Then try completely reinstalling pycrypto.  When running PACE, you may get a 
warning about the version of `libgmp`.  This is a bug in pycrypto that should
not affect the use of PACE.

### Common Installation Issues

If the installer fails, or the tests do not pass, try these steps.

1. Any of the three following messages
```
******************************************************************************
An error occured while trying to compile with the C extension enabled
Attempting to build without the extension now
******************************************************************************
```
```
fatal error: Python.h: No such file or directory
```
```
ERROR: Failure: ImportError (No module named Signature)
```

mean that your Python installation is broken.  Try updating it and 
then re-running `./install.sh`.  
 Using `apt-get`, you can update by doing `apt-get update` then 
`apt-get install -f` and then finally `apt-get install python2.7-dev`.
Using `yum`, do `yum clean all` followed by `yum update python-devel`.

2. If you get a permission denied error, such as
```
[Errno 13] Permission denied: '/usr/local/lib/python2.7/dist-packages/test-easy-install-8988.pth'
```
try rerunning with 'sudo' or as root.


3. If, while the installer is running, you see a flood of messages like
```
[Errno 13] Permission denied: '/usr/local/lib/python2.7/dist-packages/test-easy-install-8988.pth'
```
and then when running the tests, you get errors with `pycryptopp` such as
```
ERROR: Failure: ImportError (No module named pycryptopp.publickey)
```
then your `g++` installation is likely broken.  Try updating it and then
rerunning `./install.sh`.
 Using `apt-get`, you can update by doing `apt-get update` then 
`apt-get install -f` and then finally `apt-get install g++`.
Using `yum`, do `yum clean all` followed by `yum update g++`.

4. If you compiled GMP from source, it is recommended that you add the
   following line to your `~/.bashrc` file (and use `source ~/.bashrc` to 
   make the changes take effect).  Replace `$GMP_HOME` with your main GMP install location.
      ```
      export LD_LIBRARY_PATH=$GMP_HOME/lib:$LD_LIBRARY_PATH
      ```

## Running the Thrift Proxy

   For PACE to use a live Accumulo instance, you must run Accumulo with a
   proxy so that thrift will
   function properly.  Assuming your main Accumulo folder is $ACCUMULO_HOME, 
   edit the `$ACCUMULO_HOME/proxy/proxy.properties` file to contain the correct
   information.  Notably, make sure `instance` is set to the name of your
   Accumulo instance, make sure `zookeepers` points to the host and port of
   your zookeeper server, and note the port number (the demo PACE code uses
   port 42424, but you can set this to any unused port).  Make sure your
   Accumulo instance is running, then run the Accumulo
   proxy in the terminal by running 
   ```bash
   $ACCUMULO_HOME/bin/accumulo proxy -p $ACCUMULO_HOME/proxy/proxy.properties &
   disown
   ```
   (Disowning the process at the end means that the process will no longer be
   halted when your current terminal window closes.  If you have other running
   jobs in this terminal that you do not want to disown, look up the jobID of
   the thrift proxy by typing `jobs -l` and then typing `disown <jobID>`).
   You can check to make sure the proxy is running correctly by opening
   python and typing the following, changing your Accumulo settings as
   necessary:
   ```bash
   python
   >>> from pyaccumulo import Accumulo
   >>> conn = Accumulo(user='root', password='secret', host='pacetest-client',
   ...                 port=42424)
  ```

## Subpackages

In this section, we document the subpackages contained within this project. With
the exception of `common`, each of these subpackages also has a
README.md file associated with it, that goes in to more detail about its
capabilities and use.  This file aims to provide a preliminary roadmap for users
to determine what to read about in more depth.

### ads

The `ads` subpackage contains implementations of Authenticated Data Structures,
or ADSs. These are data structures that contain extra metadata allowing
untrusted servers hosting them to return query results that can be verified by
cross-referencing with a small, verified value from a trusted user. We use these
to implement a prototype of such a scheme in Accumulo, using Authenticated Skip
Lists.

Note that this is one way of cryptographically verifying the results of queries
received from Accumulo, similar to the `signatures` subpackage described below.
However, this is currenty still prototype-level; while digital signatures can
only provide cell-level, not query-level, integrity checks, our implementation
of them is much more mature and therefore currently recommended over our ADS
library.

### common

The `common` subpackage contains several utility files common to all other
subpackages of PACE. In particular, the files in it are as follows:

- `common_utils`: contains utility functions for generating test data and
  interacting with Accumulo instances.
- `fakeconn`: defines a class `FakeConnection` used for testing
  Accumulo-dependent code without a live Accumulo instance.
- `pacetest`: defines `PACETestCase`, a subclass of the `TestCase` class from
  Python's `unittest` package, with several convenient default fields and a
  `generate_elems()` function for randomly generating test data.

### encryption

The `encryption` package contains ways to cryptographically enforce the
confidentiality of data stored in Accumulo. We have two main ways of doing this:

- Field-level encryption: a flexible library for encrypting different fields of
  Accumulo cells in different ways, allowing the user to determine what to
  encrypt and how based on security and performance needs.
- Cryptographically enforced access control: a means of
  cryptographically enforcing Accumulo's cell-level security feature, preventing
  a malicious server from leaking data to innocent users who should not have
  access to it.

### pki

The `pki` package defines an interface for a key management system for the
cryptographically enforced access control mentioned above, and implements this
interface using Accumulo to store keys.

### signatures

The `signatures` package contains ways to cryptographically enforce the
integrity of data stored in Accumulo. This uses digital signatures to sign the
entirety of each Accumulo cell, allowing clients performing queries to guarantee
that each result from the query is correct and has not been tampered with.

## Distribution Statement
A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Department of Defense under Air Force Contract 
No. FA8721-05-C-0002 and/or FA8702-15-D-0001. Any opinions, findings, conclusions or 
recommendations expressed in this material are those of the author(s) and do not 
necessarily reflect the views of the Department of Defense.

&copy; 2015 Massachusetts Institute of Technology.

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 
or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this 
work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above.

## License
Copyright (c) 2016, MIT Lincoln Laboratory
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
