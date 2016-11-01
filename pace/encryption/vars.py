## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Unit tests for cell code 
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

DET_ALGORITHMS = ["Pycrypto_AES_SIV"]

CELL_MUT_MAPPING = {'row' : 'row',
                    'colFamily' : 'cf',
                    'colQualifier' : 'cq',
                    'colVisibility': 'cv',
                    'timestamp' : 'ts',
                    'value' : 'val'}
DELIN_CHAR = '+'

KEY_LENGTHS = {"Identity"     : 0,
              "Pycrypto_AES_CFB" : 128,
              "Pycrypto_AES_CBC" : 128,
              "Pycrypto_AES_OFB" : 128,
              "Pycrypto_AES_CTR" : 128,
              "Pycrypto_AES_GCM" : 128,
              "VIS_Identity"     : 0,
              "VIS_AES_CFB" : 128,
              "VIS_AES_CBC" : 128,
              "VIS_AES_OFB" : 128,
              "VIS_AES_CTR" : 128,
              "VIS_AES_GCM" : 128}

VALID_KEYS = ['row', 'colFamily','colQualifier',
             'value','colVisibility']

CELL_ORDER = ['row','cf','cq','cv','ts','val']

