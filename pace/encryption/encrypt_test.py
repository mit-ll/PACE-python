## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Tests/benchmark against live accumulo 
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  20 Jan 2015  ATLH    Original file
## **************   

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import argparse
import profile

from pace.encryption.benchmarker import Benchmarker
from pace.encryption.enc_classes import ALGORITHMS

def main():
    parser = argparse.ArgumentParser(description=(
        'Test the encryption code with a running Accumulo server instance.'))

    parser.add_argument('--profile',
                        dest='profile',
                        action='store_const',
                        default=False,
                        const=True,
                        help='profile the test performed')
    
    parser.add_argument('--benchmark',
                        dest='benchmark',
                        action='store_const',
                        default=False,
                        const=True,
                        help='benchmark the test performed')

    parser.add_argument('--action',
                        dest='action',
                        action='store',
                        default='full',
                        choices=['full', 'encrypt', 'decrypt','none'],
                        help='determine what action to take \
                              (default: write encrypted data & then decrypt)')

    parser.add_argument('--scheme',
                        dest='scheme',
                        action='store',
                        default='Pycrypto_AES_CFB',
                        choices=ALGORITHMS.keys().append("ALL"),
                        help='specify an encryption scheme to use \
                              (default: AES_CFB)')

    parser.add_argument('--seed',
                        dest='seed',
                        action='store',
                        help='specify a seed to use for the randomness')

    parser.add_argument('--table',
                        dest='table',
                        action='store',
                        required=True,
                        help='specify the table in the accumulo database \
                              to use')

    parser.add_argument('--port',
                        dest='port',
                        action='store',
                        default='42424',
                        type=int,
                        help='the port to connect to the Accumulo instance on')

    parser.add_argument('--user',
                        dest='user',
                        action='store',
                        default='root',
                        help='the username to connect to the Accumulo instance with')

    parser.add_argument('--hostname',
                        dest='hostname',
                        action='store',
                        default='localhost',
                        help='the hostname of the Accumulo instance')

    parser.add_argument('--password',
                        dest='password',
                        action='store',
                        default='secret',
                        help='the password for the Accumulo instance')
    
    parser.add_argument('--config',
                        dest='config',
                        action='store',
                        help='Encryption configuration file')

    args = parser.parse_args()


    if args.action == 'full':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_test(config_file=args.config,\
                                encClassName=args.scheme,\
                                table=args.table,\
                                encrypt=True,\
                                decrypt=True,\
                                benchmark=args.benchmark)',
                globals(),
                locals())
        else:
            bench.run_test(config_file = args.config,
                           encClassName=args.scheme,
                           table=args.table,
                           encrypt=True,
                           decrypt=True,
                           benchmark=args.benchmark)

    elif args.action == 'encrypt':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_test(config_file=args.config,\
                                encClassName=args.scheme,\
                                table=args.table,\
                                encrypt=True,\
                                decrypt=False,\
                                benchmark=args.benchmark)',
                globals(), locals())
        else:
            bench.run_test(config_file=args.config,
                           encClassName=args.scheme,
                           table=args.table,
                           encrypt=True,
                           decrypt=False,
                           benchmark=args.benchmark)
            
    elif args.action == 'decrypt':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_test(config_file=args.config,\
                                encClassName=args.scheme,\
                                table=args.table,\
                                encrypt=False,\
                                decrypt=True,\
                                benchmark=args.benchmark)',
                globals(), locals())
        else:
            bench.run_test(config_file=args.config,
                           encClassName=args.scheme,
                           table=args.table,
                           encrypt=False,
                           decrypt=True,
                           benchmark=args.benchmark)
    
    elif args.action == 'none':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_test(config_file=args.config,\
                                encClassName=args.scheme,\
                                table=args.table,\
                                encrypt=False,\
                                decrypt=False,\
                                benchmark=args.benchmark)',
                globals(), locals())
        else:
            bench.run_test(config_file=args.config,
                           encClassName=args.scheme,
                           table=args.table,
                           encrypt=False,
                           decrypt=False,
                           benchmark=args.benchmark)
    else:
        print "Invalid action: " + args.action

if __name__ == "__main__":
    main()