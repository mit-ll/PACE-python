## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CS
##  Description: Benchmark framework for signature code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  30 Oct 2014  CS    Original file
## **************

import random
from pyaccumulo import Accumulo, Mutation, Range
import time, datetime
from Crypto.PublicKey import RSA

from pace.signatures.sign import AccumuloSigner
from pace.signatures.signconfig import VerificationException
from pace.signatures.vars import ALL_SIGNATURES, SUPPORTED_SIGNATURES, SIGNATURE_FUNCTIONS
from pace.signatures.sign_utils import write_and_sign_data, write_data, sanitize, verify_data, generate_data
from pace.signatures.acc_sig import PKCS1_v1_5_AccSig, PyCryptopp_ECDSA_AccSig
from pace.signatures.signconfig import new_config
from pace.signatures.signaturepki import SignatureMixin, SigTuple

from pace.pki.dictpki import DictPKI

class SignedDictPKI(DictPKI, SignatureMixin):
    pass

test_ids = [('pkcsv1_test', PKCS1_v1_5_AccSig),
            ('ecdsa_test', PyCryptopp_ECDSA_AccSig)]

test_pki = SignedDictPKI({'pkcsv1_test' : (PKCS1_v1_5_AccSig.test_keys()[0],
                                           PKCS1_v1_5_AccSig.name),
                          'ecdsa_test' :(PyCryptopp_ECDSA_AccSig.test_keys()[0],
                                         PyCryptopp_ECDSA_AccSig.name)},
                         SigTuple)

class Benchmarker(object):

    BENCHMARKS = [
            (100, 10),
            (500, 50),
            (1000, 100),
            (5000, 500),
            (10000, 1000)
        ]

    FANCY_BENCHMARKS = [(2 ** i, 2 ** (i-1)) for i in range(2, 14)]

    def __init__(self,
                 host="localhost",
                 port=42424,
                 user="root",
                 password="secret",
                 num_trials=100,
                 filename='default_file.txt',
                 seed=None,
                 signer_ids=test_ids,
                 pki=test_pki):
        self.conn = Accumulo(host=host, port=port, user=user, password=password)
        self.num_trials = num_trials
        self.filename = filename
        self.seed = seed
        self.signer_ids = signer_ids
        self.pki = pki

    def run_test(self,
                 table="test_table_5",
                 default_vis="default",
                 num_entries=100,
                 num_rows=15,
                 signClassName='RSASSA_PKCS1-v1_5',
                 write=True,
                 benchmark=False):
        """ Runs one iteration of the signature test. If benchmark is set to
            True, returns the lengths of time it took to sign all the entries
            and the time it took to verify all the entries.
        """

        table = sanitize(table)
        seed = self.seed

        if signClassName == 'ALL':
            for signClass in ALL_SIGNATURES:
                self.run_test(table + '_' + sanitize(signClass.name),
                              default_vis, num_entries, num_rows,
                              signClass.name, write, benchmark)
            return

        signClass = SIGNATURE_FUNCTIONS[signClassName]
        
        pubkey, privkey = signClass.test_keys()

        if write:
            signer = AccumuloSigner(privkey, sig_f = signClass)

            if not seed:
                # set a new seed if one wasn't specified
                seed = str(time.time())

            generate_data(self.filename, seed, default_vis=default_vis,
                          num_entries=num_entries, num_rows=num_rows)

            sout = write_and_sign_data(self.filename, self.conn, table, signer,
                                       benchmark)

        vout = verify_data(self.conn, table, pubkey, benchmark)

        if benchmark:
            sign_start, sign_end = sout
            verif_success, verif_start, verif_end = vout

            print "Time taken to sign: %s" % str(sign_end - sign_start)
            print "Time taken to verify: %s" % str(verif_end - verif_start)
            
            return sign_end - sign_start, verif_end - verif_start

    def run_benchmarks(self,
                       table_prefix="benchmarking",
                       default_vis="default"):
        """ Benchmarks each different signature class on a variety of table
            sizes, measuring the time taken to sign & verify all entries of each
            table size with each signature algorithm.
        """

        table_prefix = sanitize(table_prefix)

        for entries, rows in self.BENCHMARKS:
            print "==============================================================="
            print "Current benchmark: %d entries over %d rows" %(entries, rows)
            print "==============================================================="
            print
            for signClass in SUPPORTED_SIGNATURES:
                table = "%s_%s_e%d_r%d" %(table_prefix,
                                          sanitize(signClass.name),
                                          entries,
                                          rows)
                print "Benchmarking %s" % (sanitize(signClass.name))
                self.run_test(table, default_vis, entries, rows, signClass.name,
                              write=True, benchmark=True)
                print

    def run_fancy_benchmarks(self,
                             table_prefix="benchmarking",
                             default_vis="default",
                             resfile="benchmark_results.csv"):

        """ Runs more benchmarks than run_benchmarks(), then writes the output
            to a file.
        """

        table_prefix = sanitize(table_prefix)

        results = []
        for entries, rows in self.FANCY_BENCHMARKS:
            print "==============================================================="
            print "Current benchmark: %d entries over %d rows" %(entries, rows)
            print "==============================================================="
            print
            classres = []
            for signClass in SUPPORTED_SIGNATURES:
                table = "%s_%s_e%d_r%d" %(table_prefix,
                                          sanitize(signClass.name),
                                          entries,
                                          rows)
                print "Benchmarking %s" % (sanitize(signClass.name))
                sign_time, verif_time = self.run_test(
                    table, default_vis, entries, rows, signClass.name,
                    write=True, benchmark=True)
                classres.append((signClass.name, sign_time, verif_time))
                print
            results.append((entries, classres))

        print 'time to write to file'
        with open(resfile, 'w') as f:
            f.write('num entries,name,sign time,verification time\n')
            for num_entries, classres in results:
                for name, stime, vtime in classres:
                    f.write(','.join(
                        [str(num_entries), name, str(stime), str(vtime)]))
                    f.write('\n')
        print 'wrote to file'

    def full_benchmark(self,
                       table_prefix="full_benchmarking",
                       default_vis="default",
                       signClass=None,
                       num_entries=10000,
                       num_rows=1000):
        """ Either run a single benchmark (sign & verify) on one signature
            class, or run it with no signing class (just write & read) to get
            a baseline time.
        """

        table_prefix = sanitize(table_prefix)

        conn = self.conn

        if signClass:
            table = table_prefix + '_' + sanitize(signClass.name)
        else:
            table = table_prefix + '_baseline'

        if signClass:
            pubkey, privkey = signClass.test_keys()
            signer = AccumuloSigner(privkey, sig_f = signClass)
            start_time = time.clock()
            write_and_sign_data(self.filename, conn, table, signer,
                                benchmark=False)
            end_time = time.clock()
            total_sign_time = end_time - start_time

            start_time = time.clock()
            verify_data(conn, table, pubkey, benchmark=False)
            end_time = time.clock()
            total_verif_time = end_time - start_time
        else:
            start_time = time.clock()
            write_data(self.filename, conn, table)
            end_time = time.clock()
            total_sign_time = end_time - start_time

            count = 0
            start_time = time.clock()
            for entry in conn.scan(table):
                count += 1
            end_time = time.clock()
            total_verif_time = end_time - start_time

        return (total_sign_time, total_verif_time)

    def run_full_benchmarks(self,
                            table_prefix="full_benchmarking",
                            default_vis="default",
                            num_entries=10000,
                            num_rows=1000,
                            outfile='full_benchmark_out.csv'):
        """ Benchmark each signing algorithm, writing the results to a file,
            and comparing them to a baseline write & read with no signatures.
        """

        table_prefix = sanitize(table_prefix)

        n = generate_data(self.filename, self.seed, default_vis=default_vis,
                          num_entries=num_entries, num_rows=num_rows)

        base_write_time, base_read_time = self.full_benchmark(
            table_prefix, default_vis, None, num_entries, num_rows)

        with open(outfile, 'w') as f:
            bw = (base_write_time / n) * 1000
            br = (base_read_time / n) * 1000
            f.write(','.join(['name', 'signing time', 'verification time']))
            f.write('\n')
            f.write(','.join(['baseline', str(bw), str(br)]))
            f.write('\n')
            for signClass in SUPPORTED_SIGNATURES:
                (st, vt) = self.full_benchmark(
                    table_prefix, default_vis, signClass, num_entries, num_rows)

                # convert seconds for the whole batch to milliseconds
                # per element
                st = (st / n) * 1000
                vt = (vt / n) * 1000

                f.write(','.join([signClass.name, str(st), str(vt)]))
                f.write('\n')

    def fastfail_benchmark(self, table):
        """ Check how long it takes just to read each element from a table,
            to see if there's a difference because of the changed visibility
            fields in signed tables.
        """

        table = sanitize(table)

        start = time.clock()
        
        total = 0
        for e in self.conn.scan(table):
            total += 1
        end = time.clock()

        return end - start

    def run_fastfail_benchmarks(self,
                                table_prefix="fastfail_benchmarking",
                                default_vis="default",
                                num_rows=1000,
                                num_noisy_entries=50000,
                                num_noisy_rows=1000,
                                outfile='fastfail_benchmark_out_2.csv',
                                num_trials=100,
                                one_vis=False):
        """ Benchmark to see how much overhead there is from the signature code
            making Accumulo unable to fast-fail and cache results from
            visibility field checks.

            If one_vis is False, it will randomly generate a default visibility
            value for each field. If it is a string, that string will be treated
            as the default visibility value for each 'noise' field.
        """

        table_prefix = sanitize(table_prefix)

        seed = self.seed
        noisy_filename = 'noisy_' + self.filename

        if not seed:
            # set a new seed if one wasn't specified
            seed = str(time.time())

        if one_vis:
            print 'generating noise with one visibility field'
            generate_data(noisy_filename, seed, vis=False, default_vis=one_vis,
                          num_entries=num_noisy_entries, num_rows=num_rows)
        else:
            print 'generating noise with random visibility fields'
            generate_data(noisy_filename, seed, vis=True,
                          num_entries=num_noisy_entries, num_rows=num_rows)

        noisy_table = 'noisy_' + table_prefix

        write_data(noisy_filename, self.conn, noisy_table)

        for sc in SUPPORTED_SIGNATURES:
            pubkey, privkey = sc.test_keys()
            signer = AccumuloSigner(privkey, sig_f = sc)
            write_and_sign_data(noisy_filename,
                                self.conn,
                                '_'.join([table_prefix, sanitize(sc.name)]),
                                signer)

        all_times = []

        for n in [(num_noisy_entries/10000) * (10 ** i)
                  for i in range(6)]:

            print 'n:', n

            generate_data(self.filename, str(time.time()),
                          default_vis=default_vis, num_entries=n,
                          num_rows=min(n, num_rows))
            write_data(self.filename, self.conn, noisy_table)

            base_time = sum([self.fastfail_benchmark(noisy_table)
                             for j in range(num_trials)])
            times = []

            for signClass in SUPPORTED_SIGNATURES:

                pubkey, privkey = signClass.test_keys()
                signer = AccumuloSigner(privkey, sig_f = signClass)
                table = '_'.join([table_prefix, sanitize(signClass.name)])
                
                write_and_sign_data(self.filename, self.conn, table, signer)

                times.append((signClass.name,
                              sum([self.fastfail_benchmark(table)
                                  for j in range(num_trials)])))

            all_times.append((n, base_time, times))

        with open(outfile, 'w') as f:
            for num_elems, base_time, trials in all_times:

                print 'Trial for %d elements. Base time: %s' %(
                    num_elems, str(base_time))

                f.write('%d,BASE,%s\n' %(num_elems, str(base_time)))

                for name, ttime in trials:
                    print '\t%s: %s' %(name, str(ttime))
                    f.write('%d,%s,%s\n' %(num_elems, name, str(ttime)))
                print

    def id_test(self,
                table_prefix="id_test",
                default_vis="default",
                num_entries=10000,
                num_rows=1000):

        table_prefix = sanitize(table_prefix)

        generate_data(self.filename, self.seed, default_vis=default_vis,
                      num_entries=num_entries, num_rows=num_rows)

        for signer_id, sigclass in self.signer_ids:

            _, privkey = sigclass.test_keys()
            table = table_prefix + '_' + sanitize(signer_id)
            
            signer = AccumuloSigner(privkey, sig_f=sigclass,
                                    signerID=signer_id)
            write_and_sign_data(self.filename,
                                self.conn,
                                table,
                                signer)
            verify_data(self.conn, table, self.pki, sigclass)

    def table_test(self,
                   table_prefix="table_test1",
                   default_vis="default",
                   num_entries=10000,
                   num_rows=1000):

        table_prefix = sanitize(table_prefix)

        generate_data(self.filename, self.seed, default_vis=default_vis,
                      num_entries=num_entries, num_rows=num_rows)

        for signer_id, sigclass in self.signer_ids:
            
            _, privkey = sigclass.test_keys()

            table = table_prefix + '_' + sanitize(signer_id)
            
            signer = AccumuloSigner(privkey, sig_f=sigclass)
            write_and_sign_data(self.filename,
                                self.conn,
                                table,
                                signer,
                                include_table=True)
            verif_key, _ = self.pki.get_verifying_key(signer_id)
            verify_data(self.conn, table, verif_key, False, include_table=True)

    def location_test(self,
                      cfg_file,
                      table_prefix="table_test1",
                      default_vis="default",
                      num_entries=10000,
                      num_rows=1000):

        table_prefix = sanitize(table_prefix) + '_' + sanitize(loc)

        generate_data(self.filename, self.seed, default_vis=default_vis,
                      num_entries=num_entries, num_rows=num_rows)

        for signer_id, sigclass in self.signer_ids:
            
            _, privkey = sigclass.test_keys()

            table = table_prefix + '_' + sanitize(signer_id)

            conf = new_config(cfg_file, self.conn)
            
            signer = AccumuloSigner(privkey, sig_f=sigclass, conf=conf)
            write_and_sign_data(self.filename,
                                self.conn,
                                table,
                                signer)
            verif_key, _ = self.pki.get_verifying_key(signer_id)
            verify_data(self.conn, table, verif_key, False, conf=conf)
