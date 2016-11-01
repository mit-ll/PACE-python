## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Benchmarks for the merkle tree library
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  08 Aug 2014  ZS    Original file
## **************

import random

from pace.ads.merkle.mht import MHT, MHTInsertionException
from pace.ads.merkle.mht_utils import MHTUtils
from pace.ads.merkle.mht_node import MHTNode
from pace.ads.merkle.vo import VO


class MHTBenchmark(object):

    def __init__(self,
                 mht_sizes=[100,500,1000,5000,100000], #,100000],
                 vo_size_fractions=[10000,1000,100,50,20,10,5,2],
                 input_chunks=[1,2,4,8,16]):
        self.mht_sizes = mht_sizes
        self.vo_size_fractions = vo_size_fractions
        self.input_chunks = input_chunks
    

    def benchmark(self):
        for size in self.mht_sizes:
            for num_chunks in self.input_chunks:
                elems = [random.randint(1, 99999999)
                         for i in range(0, size/num_chunks - 2)]
                elems.sort()
                elems = [0] + elems + [100000000]

                ## mht1 - iterated single-element insert
                ## mht2 - gestalt batch insert
                mht1 = MHT.new(elems)
                mht2 = MHT.new(elems)

                for i in range(1, num_chunks):
                    elems = [random.randint(1, 99999999)
                             for i in range(1, size/num_chunks)]
                    mht1.batch_insert(elems)
                    mht2._gestalt_batch_insert(min(elems), max(elems), elems)

                this_output = []

                for frac in self.vo_size_fractions:
                    if frac >= size:
                        continue

                    vo_size = size / frac

                    start = random.choice(range(1, size - vo_size - 1))
                    end = start + vo_size

                    vo1 = mht1.range_query(start, end)
                    vo2 = mht2.range_query(start, end)
                    
                    svo1 = vo1.serialize()
                    svo2 = vo2.serialize()

                    ser_length1 = len(svo1)
                    ser_length2 = len(svo2)

                    this_output.append((vo_size, ser_length1, ser_length2))

                ## Output format: (size, num_chunks, this_output) where:
                ##
                ## size - the (approximate) total number of elements in the MHT
                ## actual_size - the length of the MHT's sorted_elems field
                ## num_chunks - the number of chunks in which the elements are
                ##              inserted into the MHT
                ## this_output - the output from running range queries on the
                ##               MHT built with those properties.
                yield ((size, len(mht1.sorted_elems), num_chunks, this_output))

    @staticmethod
    def stringify_benchmark_output(output):
        lines = []
        for size, actual_size, num_chunks, runs in output:
            lines.append('MHT of size %d (%d) split into %d chunks:' %(size, actual_size, num_chunks))
            intermediate = []

            for vo_size, iter_length, batch_length in runs:
                intermediate.append(
                    'VO size: %d\n\t\tbits per element (sequential insert): %f\n\t\tbits per element (gestalt insert): %f'
                     %(vo_size, iter_length/float(vo_size), batch_length/float(vo_size)))

            lines = lines + ['\t' + line for line in intermediate]

        return '\n'.join(lines)

    @staticmethod
    def print_benchmark_output(output):
        for size, actual_size, num_chunks, runs in output:
            print 'MHT of size %d (%d) split into %d chunks:' %(size, actual_size, num_chunks)
            intermediate = []

            for vo_size, iter_length, batch_length in runs:
                print '\t%s' %(
                    'VO size: %d\n\t\tbits per element (sequential insert): %f\n\t\tbits per element (gestalt insert): %f'
                     %(vo_size, iter_length/float(vo_size), batch_length/float(vo_size)))

    def run(self):
        try:
            MHTBenchmark.print_benchmark_output(self.benchmark())
        except MHTInsertionException as e:
            print 'ERROR!!!'
            print e.msg
            raise e

def go():
    MHTBenchmark().run()
