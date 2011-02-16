#!/bin/sh

DESTINATION="root@vmtom.com:cass/"
INSTALLABLES="\
    genmail3.pl \
    listmail.pl \
    pop3showafter.pl \
    cidclashrepltest.pl \
    testrunner.pl \
    Cassandane \
"


rsync -av --delete -e ssh $INSTALLABLES $DESTINATION
