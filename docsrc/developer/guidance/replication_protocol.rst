.. _imap-developer-guidance-replication-protocol:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Replication Protocol v2.4+
=============================================

DList 1.0
---------

The DList protocol is based closely on the IMAP wire protocol, using
atoms and literals as the basis, but with two extended types of data:

-  kvlist
-  rfc822-object

A wart of the protocol is the rfc822-object, which contains an explicit
cyrus backend partition. This will be removed in future versions of
Cyrus.

types
~~~~~

atom
^^^^

An atom is actually a sequence of any character other than '\\0', the
NULL byte. Character encoding is not specified, but it can contain 8 bit
characters, and is probably utf8

flag
^^^^

Flag is a horrible special case of atom to allow \\word to be
represented as an IMAP atom on the wire. This is one of many special
cases in the IMAP protocol, and is duplicated into dlist just to make it
easier to read

num32/num
^^^^^^^^^

Both stored as 64 bit integers internally, and sent as decimal numbers
over the wire, this type exists only in the API, it just looks like a
string on the wire.

hex32/hex
^^^^^^^^^

Stored like num internally, but sent as an 8 or 16 character hexadecimal
string on the wire

map
^^^

Like atom, but can contain NULL. All values are parsed off the wire as
'map' type and then converted on demand into the requested type

list
^^^^

Encoded in parentheses like so (item item item) a list type can be
nested inside other lists: (item (sub sub) item)

kvlist
^^^^^^

A kvlist allows named parameters, and is indicated with a leading %
character. % is invalid in atoms, so parsing is unambiguous, e.g:

%(key1 value1 key2 (list of values) key3 value3)

rfc822-object/file
^^^^^^^^^^^^^^^^^^

Finally the ugly one. These look like a literal, but with a leading %
and two more fields:

::

    %{partition sha1 size}\r\n
    data
