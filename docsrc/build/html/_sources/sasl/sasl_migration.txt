====================
Cyrus SASL Migration
====================

When migrating the ``/etc/sasldb`` database using the ``utils/dbconverter-2``
utility, you may encounter the error message "Error opening password 
file". This is usually due to the fact your SASL V1 library was compiled 
using a different version of Berkeley DB than the SASL V2 library. 
You can work around this by using Berkeley DB's db_upgrade utility 
(possibly chaining the DB3 and DB4 upgrade utilities) to upgrade a copy 
of sasldb prior to conversion using dbconverter-2.

Here is the script we use at our installation, where SASL has to 
coexist with SASL2::

    !/bin/sh
    cp /etc/sasldb /tmp/sasldb.$$
    /usr/local/BerkeleyDB.4/bin/db_upgrade /etc/sasldb
    echo ""|/usr/local/sasl/sbin/dbconverter-2
    cp /tmp/sasldb.$$ /etc/sasldb