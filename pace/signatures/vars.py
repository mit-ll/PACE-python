## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Miscellaneous global variables for the signatures code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  12 Nov 2014  CS    Original file
## **************

from collections import namedtuple

from pace.signatures.acc_sig import PKCS1_v1_5_AccSig, PyCryptopp_ECDSA_AccSig, PKCS1_PSS_AccSig, Symmetric_HMAC_SHA256_AccSig

SIGNATURE_FUNCTIONS = {
        'RSA' : PKCS1_v1_5_AccSig,
        'PKCS1_v1_5' : PKCS1_v1_5_AccSig,
        'RSASSA_PKCS1-v1_5' : PKCS1_v1_5_AccSig,
        'RSASSA-PKCS1-v1_5' : PKCS1_v1_5_AccSig,
        'RSASSA_PKCS-v1_5' : PKCS1_v1_5_AccSig,
        'PyCryptopp_ECDSA' : PyCryptopp_ECDSA_AccSig,
        'ECDSA' : PyCryptopp_ECDSA_AccSig,
        'ECC_ECDSA' : PyCryptopp_ECDSA_AccSig,
        'PSS' : PKCS1_PSS_AccSig,
        'RSASSA-PSS' : PKCS1_PSS_AccSig,
        'HMAC-SHA256' : Symmetric_HMAC_SHA256_AccSig
    }

SUPPORTED_SIGNATURES = [
        PKCS1_v1_5_AccSig,
        PyCryptopp_ECDSA_AccSig,
        PKCS1_PSS_AccSig,
    ]

ALL_SIGNATURES = SUPPORTED_SIGNATURES + [
        Symmetric_HMAC_SHA256_AccSig
    ]

MAX_ERROR_LEN = 256     # truncate error messages to a reasonable length
