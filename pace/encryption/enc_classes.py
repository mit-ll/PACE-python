## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: All the different types of algorithms  
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  19 Dec 2014  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)
 
from pace.encryption.AES_encrypt import Pycrypto_AES_CTR, Pycrypto_AES_OFB, \
    Pycrypto_AES_CFB, Pycrypto_AES_CBC, Pycrypto_AES_GCM, Pycrypto_AES_SIV
from pace.encryption.visibility.vis_encrypt import VIS_AES_CTR, VIS_AES_OFB, \
    VIS_AES_CFB, VIS_AES_CBC, VIS_AES_GCM, VIS_Identity
from pace.encryption.abstract_encrypt import Identity_AccEncrypt
                

ALGORITHMS = {"Identity"     : Identity_AccEncrypt,
              "Pycrypto_AES_CFB" : Pycrypto_AES_CFB,
              "Pycrypto_AES_CBC" : Pycrypto_AES_CBC,
              "Pycrypto_AES_OFB" : Pycrypto_AES_OFB,
              "Pycrypto_AES_CTR" : Pycrypto_AES_CTR,
              "Pycrypto_AES_GCM" : Pycrypto_AES_GCM,
              "Pycrypto_AES_SIV" : Pycrypto_AES_SIV,
              "VIS_Identity"     : VIS_Identity,
              "VIS_AES_CFB" : VIS_AES_CFB,
              "VIS_AES_CBC" : VIS_AES_CBC,
              "VIS_AES_OFB" : VIS_AES_OFB,
              "VIS_AES_CTR" : VIS_AES_CTR,
              "VIS_AES_GCM" : VIS_AES_GCM}

AES_ALGORITHMS = {"Pycrypto_AES_CFB" : Pycrypto_AES_CFB,
              "Pycrypto_AES_CBC" : Pycrypto_AES_CBC,
              "Pycrypto_AES_OFB" : Pycrypto_AES_OFB,
              "Pycrypto_AES_CTR" : Pycrypto_AES_CTR,
              "Pycrypto_AES_GCM" : Pycrypto_AES_GCM,
              "Pycrypto_AES_SIV" : Pycrypto_AES_SIV}

#modes of operation that require plaintext to be a multiple of a block length
LENGTHBOUND_AES_ALGORITHMS = {"Pycrypto_AES_CBC" : Pycrypto_AES_CBC}

IV_AES_ALGORITHMS = { "Pycrypto_AES_CFB" : Pycrypto_AES_CFB,
              "Pycrypto_AES_CBC" : Pycrypto_AES_CBC,
              "Pycrypto_AES_OFB" : Pycrypto_AES_OFB,
              "Pycrypto_AES_GCM" : Pycrypto_AES_GCM}

AUTH_ALGORITHMS = {"Pycrypto_AES_GCM" : Pycrypto_AES_GCM}

DET_ALGORITHMS = {"Pycrypto_AES_SIV" : Pycrypto_AES_SIV}

VIS_ALGORITHMS = {"VIS_Identity"     : VIS_Identity,
              "VIS_AES_CFB" : VIS_AES_CFB,
              "VIS_AES_CBC" : VIS_AES_CBC,
              "VIS_AES_OFB" : VIS_AES_OFB,
              "VIS_AES_CTR" : VIS_AES_CTR,
              "VIS_AES_GCM" : VIS_AES_GCM}
