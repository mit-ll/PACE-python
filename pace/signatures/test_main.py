## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Tests for signatures against a live accumulo db
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   9 Jul 2014  ZS    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import argparse
import profile

from pace.signatures.benchmarker import Benchmarker
from pace.signatures.vars import SIGNATURE_FUNCTIONS

def main():
    parser = argparse.ArgumentParser(description=(
        'Test the signature code with a running Accumulo server instance.'))

    parser.add_argument('--profile',
                        dest='profile',
                        action='store_const',
                        default=False,
                        const=True,
                        help='profile the test performed')

    parser.add_argument('--vis',
                        dest='vis',
                        action='store',
                        default=False,
                        help='the visibility field to use (currently only for fastfail benchmarking)')

    parser.add_argument('--action',
                        dest='action',
                        action='store',
                        default='full',
                        choices=['full', 'verify', 'benchmark', 'fancy-benchmark', 'full-benchmark', 'fastfail-benchmark', 'signer-id', 'signed-table', 'cfg-test'],
                        help='determine what action to take \
                              (default: write data & then verify)')

    parser.add_argument('--scheme',
                        dest='scheme',
                        action='store',
                        default='RSA',
                        choices=SIGNATURE_FUNCTIONS.keys().append("ALL"),
                        help='specify an encryption scheme to use \
                              (default: RSA)')

    parser.add_argument('--cfg',
                        dest='cfg_file',
                        action='store',
                        help='specify a config file to use')

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

    args = parser.parse_args()

    if args.action == 'benchmark':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_benchmarks(table_prefix=args.table)',
                globals(),
                locals())
        else:
            bench.run_benchmarks(table_prefix=args.table)

    elif args.action == 'fancy-benchmark':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_fancy_benchmarks(table_prefix=args.table)',
                globals(),
                locals())
        else:
            bench.run_fancy_benchmarks(table_prefix=args.table)

    elif args.action == 'full':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_test(signClassName=args.scheme,\
                                table=args.table,\
                                write=True)',
                globals(),
                locals())
        else:
            bench.run_test(signClassName=args.scheme,
                     table=args.table,
                     write=True)

    elif args.action == 'verify':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        if args.profile:
            profile.runctx(
                'bench.run_test(signClassName=args.scheme,\
                 table=args.table,\
                 write=False)',
                globals(), locals())
        else:
            bench.run_test(signClassName=args.scheme,
                           table=args.table,
                           write=False)

    elif args.action == 'full-benchmark':
        # Doesn't support profiling
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        bench.run_full_benchmarks(table_prefix=args.table)

    elif args.action == 'fastfail-benchmark':
        # Doesn't support profiling
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        bench.run_fastfail_benchmarks(table_prefix=args.table,
                                      one_vis=args.vis)

    elif args.action == 'signer-id':
        # Doesn't support profiling
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        bench.id_test(args.table)

    elif args.action == 'signed-table':
        # Doesn't support profiling
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        bench.table_test(args.table)

    elif args.action == 'cfg-test':
        bench = Benchmarker(args.hostname, args.port, args.user, args.password,
                            seed=args.seed)
        with open(args.cfg_file, 'r') as cfg_file:
            bench.location_test(table_prefix=args.table, cfg_file=cfg_file)

    else:
        print "Invalid action: " + args.action

if __name__ == "__main__":
    main()
