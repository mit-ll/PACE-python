#!/bin/bash
## **************
##  Copyright 2014 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ZS
##  Description: Tests for signatures against a live accumulo db
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  17 Jul 2014  CS    Original file
## **************

TABLE='finalisher_vm_benchmarks'
HOSTNAME='localhost'
PORT='42424'
USER='root'
PASSWORD='secret'
ACTIONS='full verify benchmark fancy-benchmark full-benchmark fastfail-benchmark signer-id signed-table value-signature-test'
CONFIGS='cfg/value_test.cfg cfg/batch_test.cfg cfg/stream_test.cfg'

if [ "$1" = "help" ]; then
    echo "Test script usage: ./test.sh <args>"
    echo "Arguments:"
    echo "    help - print this message"
    echo "    all  - run tests & benchmarks against a live Accumulo instance on all available actions"
    echo "    nose - only run the unit tests in this directory"
    echo "    live - only run the live test in this directory"
    echo "    specific <action> - run the live test on the specified action"
elif [ "$1" = "all" ]; then
    for a in $ACTIONS; do
        echo "=========================="
        echo "Testing action ${a}"
        echo "=========================="
        python test_main.py --table "${TABLE}_${a}" --scheme ALL --port ${PORT} --user ${USER} --hostname ${HOSTNAME} --password ${PASSWORD} --action "${a}"
        echo
    done

    for cfg in $CONFIGS; do
        echo "=========================="
        echo "Testing config file ${cfg}"
        echo "=========================="
        python test_main.py --table "${TABLE}_${a}" --scheme ALL --port ${PORT} --user ${USER} --hostname ${HOSTNAME} --password ${PASSWORD} --action cfg-test --cfg ${cfg}
        echo
    done

elif [ "$1" = "nose" ]; then
    nosetests sign_test
    nosetests truststore_test
elif [ "$1" = "live" ]; then
    python test_main.py --table ${TABLE} --scheme ALL --port ${PORT} --user ${USER} --hostname ${HOSTNAME} --password ${PASSWORD}
elif [ "$1" = "specific" ]; then
    python test_main.py --table "${TABLE}_${a}" --scheme ALL --port ${PORT} --user ${USER} --hostname ${HOSTNAME} --password ${PASSWORD} --action "${2}"
elif [ "$1" = "cfg" ]; then
    python test_main.py --table "${TABLE}_${a}" --scheme ALL --port ${PORT} --user ${USER} --hostname ${HOSTNAME} --password ${PASSWORD} --action cfg-test --cfg "${2}"
else
    nosetests sign_test
    nosetests truststore_test
    python test_main.py --table ${TABLE} --scheme ALL --port ${PORT} --user ${USER} --hostname ${HOSTNAME} --password ${PASSWORD}
fi
