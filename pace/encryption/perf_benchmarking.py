## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: runs benchmarking tests for performance section
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  1 Nov 2015  ATLH   Original file
## **************


import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import logging
from optparse import OptionParser, OptionGroup
from pace.encryption.benchmarker import Benchmarker
from pace.encryption.encryption_pki import DummyCachingEncryptionPKI,  DummyEncryptionPKI
from pyaccumulo import Accumulo

visibility_labels = ['a', 
                    'a&b',
                   'a&b&c',
                   'a|b',
                   'a|b|c',
                   '(a&b)|c',
                   '(a|b)&c',
                   'a|(b&c)',
                   'a&(b|c)',
                   '(a&b)|(b&c)',
                   '(a|b)&(c|d)',
                   '((a&b)|c)&(d|e)']


def run_non_ceabac(benchmarker, table_prefix, logger, profile, options):
    """
    Runs the non-ceabac configuration files located in
    /config/non_ceabac/ in addition to a baseline
    
    Arguments:
        benchmarker - the benchmarker that contains the connection
                to Accumulo, encryptor, etc
        table_prefix - the prefix put in front of tables where the 
                data is stored
        logger - logger instance where results are logged
        profile - true if you are profiling code
        options - contains the number of cells and rows to run
    """
    
    logger.info("Running Non-CEABAC Tests")
    #run benchmarker for baseline
    logger.info("Running test for non_ceabac_baseline")
    benchmarker.run_test('',
                         table=table_prefix+'Non_ceabac_baseline',
                         vis='(a&b)|c',
                         encrypt=False,
                         decrypt=False,
                         num_entries=options.num_entries,
                         num_rows=options.num_rows)
    
    #run_test for all files in the non-ceabac configuration directory
    for file in os.listdir("./config/non-ceabac"):
        logger.info('Running test for %s' % (file))
        benchmarker.run_test('./config/non-ceabac/'+file,
                             table=table_prefix + file.split('.')[0],
                             vis='(a&b)|c',
                             profile=profile,
                             num_entries=options.num_entries,
                             num_rows=options.num_rows)
        
def run_diff_non_ceabac(benchmarker, table_prefix, logger, profile, options):
    """
    Runs the non-ceabac configuration files located in
    /config/different_schemas_non_ceabac/ in addition to a baseline
    
    Arguments:
        benchmarker - the benchmarker that contains the connection
                to Accumulo, encryptor, etc
        table_prefix - the prefix put in front of tables where the 
                data is stored
        logger - logger instance where results are logged
    """
    
    logger.info("Running Non-CEABAC with different configuration files tests")
    #run benchmarker for baseline
    logger.info("Running test for non_ceabac_baseline")
    benchmarker.run_test('',
                         table=table_prefix+'diff_non_ceabac_baseline',
                         vis='(a&b)|c',
                         encrypt=False,
                         decrypt=False,
                         num_entries=options.num_entries,
                         num_rows=options.num_rows)
    
    #run_test for all files in the non-ceabac configuration directory
    for file in os.listdir("./config/different_schemas_non_ceabac"):
        logger.info('Running test for %s' % (file))
        benchmarker.run_test('./config/different_schemas_non_ceabac/'+file,
                             table=table_prefix + file.split('.')[0],
                             vis='(a&b)|c',
                             profile=profile,
                             num_entries=options.num_entries,
                             num_rows=options.num_rows)


def run_diff_ceabac(benchmarker, table_prefix, logger, profile, options):
    """
    Runs the ceabac configuration files located in
    /config/different_schemas_ceabac/ in addition to a baseline
    
    Arguments:
        benchmarker - the benchmarker that contains the connection
                to Accumulo, encryptor, etc
        table_prefix - the prefix put in front of tables where the 
                data is stored
        logger - logger instance where results are logged
    """
    
    logger.info("Running CEABAC with different configuration files tests")
    #run benchmarker for baseline
    logger.info("Running test for ceabac_baseline")
    benchmarker.run_test('',
                         table=table_prefix+'diff_ceabac_baseline',
                         vis='(a&b)|c',
                         encrypt=False,
                         decrypt=False,
                         num_entries=options.num_entries,
                         num_rows=options.num_rows)
    
    #run_test for all files in the non-ceabac configuration directory
    for file in os.listdir("./config/different_schemas_ceabac"):
        logger.info('Running test for %s' % (file))
        benchmarker.run_test('./config/different_schemas_ceabac/'+file,
                             table=table_prefix + file.split('.')[0],
                             vis='(a&b)|c',
                             profile=profile,
                             num_entries=options.num_entries,
                             num_rows=options.num_rows)
        
        
def run_ceabac(benchmarker, table_prefix, logger, profile, options):
    """
    Runs the non-ceabac configuration files located in
    /config/ceabac/ in addition to a baseline
    
    Arguments:
        benchmarker - the benchmarker that contains the connection
                to Accumulo, encryptor, etc
        table_prefix - the prefix put in front of tables where the 
                data is stored
        logger - logger instance where results are logged
    """
    
    logger.info("Running CEABAC Tests")
    #run benchmarker for baseline
    logger.info("Running test for ceabac_baseline")
    benchmarker.run_test('',
                         table=table_prefix+'ceabac_baseline',
                         vis='(a&b)|c',
                         encrypt=False,
                         decrypt=False,
                         num_entries=options.num_entries,
                         num_rows=options.num_rows)
    
    #run_test for all files in the non-ceabac configuration directory
    for file in os.listdir("./config/ceabac"):
        logger.info('Running test for %s' % (file))
        benchmarker.run_test('./config/ceabac/'+file,
                             table=table_prefix + file.split('.')[0],
                             vis='(a&b)|c',
                             profile=profile,
                             num_entries=options.num_entries,
                             num_rows=options.num_rows)
        
def run_vis_ceabac(benchmarker, table_prefix, logger, profile, options):
    """
    Runs the CEABAC in CBC mode with different visibility labels
    
    Arguments:
        benchmarker - the benchmarker that contains the connection
                to Accumulo, encryptor, etc
        table_prefix - the prefix put in front of tables where the 
                data is stored
        logger - logger instance where results are logged
    """
    
    logger.info("Running CEABAC Test with different vis labels")

    #run_test for all files in the non-ceabac configuration directory
    for vis in visibility_labels:
        logger.info('Running test for %s' % (vis))
        benchmarker.run_test('./config/ceabac/VIS_AES_CBC.cfg',
                             table=table_prefix + vis.replace('&','_and_').replace('|','_or_').replace('(','').replace(')',''),
                             vis=vis,
                             profile=profile,
                             num_entries=options.num_entries,
                             num_rows=options.num_rows)

def run_mixed_schemas(benchmarker, table_prefix, logger, profile, options):
    """
    Runs the mixed schemas configuration files located in
    /config/mixed_schemas/ in addition to a baseline
    
    Arguments:
        benchmarker - the benchmarker that contains the connection
                to Accumulo, encryptor, etc
        table_prefix - the prefix put in front of tables where the 
                data is stored
        logger - logger instance where results are logged
    """
    
    logger.info("Running mixed schemas with different configuration files tests")
    #run benchmarker for baseline
    logger.info("Running test for mix_schemas_baseline")
    benchmarker.run_test('',
                         table=table_prefix+'mixed_schemas_baseline',
                         vis='(a&b)|c',
                         encrypt=False,
                         decrypt=False,
                         num_entries=options.num_entries,
                         num_rows=options.num_rows)
    
    #run_test for all files in the non-ceabac configuration directory
    for file in os.listdir("./config/mixed_schemas"):
        logger.info('Running test for %s' % (file))
        benchmarker.run_test('./config/mixed_schemas/'+file,
                             table=table_prefix + file.split('.')[0],
                             vis='(a&b)|c',
                             profile=profile,
                             num_entries=options.num_entries,
                             num_rows=options.num_rows)
        
        
def main():
    parser = OptionParser()
    parser.add_option("-v", '--verbose', dest="verbose",
                      action="store_true", default=False,
                      help="Verbose output")
    accumulo_group = OptionGroup(parser, 'Options that control the accumulo connection')
    accumulo_group.add_option('--host', dest='host',
                            default='localhost',
                            help = 'Host for Accumulo. Default: localhost') 
    accumulo_group.add_option('--user', dest='user',
                            default='root',
                            help = 'User for Accumulo. Default: root') 
    accumulo_group.add_option('--password', dest='password',
                            default='secret',
                            help = 'Password for Accumulo user. Default: ...') 
    accumulo_group.add_option('--port', dest='port',
                              type='int', default=42424, 
                              help="Port for Accumulo. Default: 42424") 
    parser.add_option_group(accumulo_group)
    
    output_group = OptionGroup(parser, 'Options that control output')
    output_group.add_option('--log-file', dest='log_file',
            default='output.log',
            help = 'Output file for performance numbers')
    output_group.add_option('--table-prefix', dest='table_prefix',
                            default='perf',
                            help = 'Prefix used for data tables')
    output_group.add_option('--profile', dest='profile',
                            action='store_true', default=False,
                            help="Profiles encryption code")
    output_group.add_option('--cache_key', dest='cache_key',
                            action='store_true', default=False,
                            help='Keys are now cached during encryption and decryption')
    output_group.add_option('--use_accumulo_keystore', dest='accumulo_keystore',
                            action='store_true', default=False,
                            help="Keys are stored in Accumulo if option is included, otherwise they are stored locally")
    parser.add_option_group(output_group)
    
    test_group = OptionGroup(parser, "Options that control what tests are being run")
    test_group.add_option('--all', dest='all',
                           action='store_true', default=False,
                           help='Runs all the different tests')
    test_group.add_option('--non-ceabac', dest='non_ceabac',
                           action='store_true', default=False,
                           help = 'Runs the non-CEABAC tests with a simple schema')
    test_group.add_option('--ceabac', dest='ceabac',
                           action='store_true', default=False,
                           help = 'Runs the CEABAC tests with a simple schema')
    test_group.add_option('--vis-ceabac', dest='vis_ceabac',
                           action='store_true', default=False,
                           help = 'Runs CEABAC in CBC mode with varying visibility fields')
    test_group.add_option('--diff_schemas_ceabac',dest='diff_ceabac',
                          action='store_true',default=False,
                          help='Runs several different schemas for VIS_CBC')
    test_group.add_option('--diff_schemas_non_ceabac', dest='diff_non_ceabac',
                          action='store_true', default=False,
                          help='Runs several different schemas for AES_CBC')
    
    test_group.add_option('--mixed_schemas', dest='mixed_schemas',
                          action='store_true',default=False,
                          help='Runs a set of schemas where the schemes are both CEABAC and not')
    parser.add_option_group(test_group)

    entries_group = OptionGroup(parser, "Options that control how many entries are run")
    entries_group.add_option('--num_entries', dest='num_entries',
                             type='int', default=1000,
                             help='Total number of cells being run')
    entries_group.add_option('--num_rows', dest='num_rows',
                             type='int', default=100,
                             help='Total number of rows being run')
    parser.add_option_group(entries_group)
    

    (cl_flags, _) = parser.parse_args()

    #set up logging
    if cl_flags.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(
            filename=cl_flags.log_file,
            level = log_level, 
            format = '%(levelname)s-%(asctime)s: %(message)s')

    logger = logging.getLogger("performance_testing")
    
    #check inputs
    if cl_flags.all and (cl_flags.non_ceabac or cl_flags.ceabac or cl_flags.vis_ceabac):
        logger.error('--all is already specified, do not need to define other tests to run')
    
    #create accumulo connection
    conn = Accumulo(host=cl_flags.host,port=cl_flags.port,user=cl_flags.user,password=cl_flags.password)
    
    #create benchmarker
    if cl_flags.cache_key:
        logger.info('Using the caching version of the pki')
        pki = DummyCachingEncryptionPKI(conn=conn if cl_flags.accumulo_keystore else None)
    else:
        pki = DummyEncryptionPKI(conn=conn if cl_flags.accumulo_keystore else None)
        
    benchmarker = Benchmarker(logger=logger, pki=pki, conn=conn)
    
    if cl_flags.all:
        run_non_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        run_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        run_vis_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        run_diff_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        run_diff_non_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        run_mixed_schemas(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        
    if cl_flags.non_ceabac:
        run_non_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)

    if cl_flags.ceabac:
        run_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        
    if cl_flags.vis_ceabac:
        run_vis_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        
    if cl_flags.diff_ceabac:
        run_diff_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        
    if cl_flags.diff_non_ceabac:
        run_diff_non_ceabac(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)
        
    if cl_flags.mixed_schemas:
        run_mixed_schemas(benchmarker, cl_flags.table_prefix, logger, cl_flags.profile, cl_flags)

    
if __name__ == "__main__":
    main()
