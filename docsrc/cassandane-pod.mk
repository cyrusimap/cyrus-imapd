# Cassandane modules whose Pod is published to the doc site, as stems: paths
# under cassandane/, without the .pm extension.  Shared by the top-level
# Makefile.am and docsrc/Makefile so the list lives in exactly one place.
#
# When a module grows Pod worth publishing, add it here.  (This could later be
# generated at configure time instead of maintained by hand.)
CASSANDANE_POD = \
    Cassandane/TestEntity \
    Cassandane/TestEntity/DataType/AddressBook \
    Cassandane/TestEntity/DataType/Calendar \
    Cassandane/TestEntity/DataType/ContactCard \
    Cassandane/TestEntity/DataType/Email \
    Cassandane/TestEntity/DataType/Mailbox \
    Cassandane/TestUser
