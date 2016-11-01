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

# Authenticated Data Structures

Authenticated Data Structures, or ADSs, give users the ability to verify the
correctness of queries from an untrusted server given only a small
(constant-size), signed value from a trusted data owner. In looking to
implement this functionality in Accumulo, we investigated two such data
structures: Merkle Hash Trees, and Authenticated Skip Lists.

We include implementations of both data structures here. However, Merkle Hash
Trees as implemented here are more suited for static data sets, which is at odds
with Accumulo's typically high ingest rates. We implemented Authenticated Skip
Lists as an efficient option for performing rapid insert operations. For this
reason, there are two directories here:

- `merkle`: an implementation of Merkle Hash Trees. This is solely a tree
  library, and does not interface with Accumulo at all. As such, we include no
  README in this directory.
- `skiplist`: an implementation of skip lists, authenticated skip lists, and an
  embedding of the latter into Accumulo. More information about this subpackage
  can be found in its directory's README.
