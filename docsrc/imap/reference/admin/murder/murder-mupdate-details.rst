.. _murder-mupdate-details:

============================
Cyrus Murder Mupdate Details
============================

Please note that this document is not an authoritative MUPDATE protocol reference. For that, you should refer to :rfc:`3656`.

The Mailbox Update (MUPDATE) protocol is the backend that allows the CyrusMurder to function with a unified mailbox namespace, despite having multiple frontend and backend servers. This document is to serve as a reference guide to that protocol.

Past implementations of the aggregator made use of ACAP as the mailbox backend protocol. MUPDATE is designed to be more lightweight than ACAP while at the same time allowing the database to be distributed across multiple servers.

Participants
============

Within an IMAP aggregator, there are several types of MUPDATE participants.

1. **MUPDATE Master** - This component maintains the master copy of the MUPDATE database and allows operations on the database to be atomic.
2. **MUPDATE Slaves** - These components connect to the master and maintain a replica of the MUPDATE database. They also accept connections from clients, though these connections are of a read-only nature. Note that there are short periods of time between an update occuring on the master and it being reflected across all of the slaves.
3. **MUPDATE Clients** - These components query the master and slaves to obtain information from the mailbox database.

Data Formats
============

MUPDATE uses data formats similar to those used in IMAP. That is, it uses Atoms and Strings. All commands and tags in the protocol are transmitted as atoms. Every other piece of data contained within the protocol is a string, and must be quoted as such.

Atoms
-----

An atom consists of one or more alphanumeric characters.

Strings
-------

Just like IMAP, a string may be either literal or a quoted string.

A literal is a sequence of zero or more octets (including CR and LF), prefix-quoted with an octet count in the form of an open brace ("{"), the number of octets, an optional plus sign to indicate that the data follows immediately (and a ready response is not necessary), a close brace ("}"), and CRLF. If the plus sign is omitted, then the receiving side MUST send a "+ go ahead" response.

A quoted string is a sequence of zero or more 7-bit characters, excluding CR and LF, with double quote (<">) characters at each end.

The empty string is represented as either "" (a quoted string with zero characters between double quotes) or as {0} followed by CRLF (a literal with an octet count of 0).

Server Responses
================

There are three responses that the server may issue to a client for every command, and two responses that are only valid in response to a FIND, LIST, or UPDATE, and one response that is only valid for UPDATE. All responses are tagged by the same tag as the command that caused them.

Response: OK
------------

A tagged OK response indicates that the operation completed successfully. There is a mandatory implementation-defined string attached with the OK response that may be used to give the user additional information.

Response: NO
------------

A tagged NO response indicates that the operation was denied by the server. There is a mandatory implementation-defined string attached with the NO response that may be used to explain the cause of the denial.

Response: BAD
-------------

A tagged BAD response indicates that the command from the client could not be parsed. There is a mandatory implementation-defined string attached with the BAD response that may be used to explain the cause of the failure.

Response: RESERVE
-----------------

A tagged RESERVE response includes two parameters, the name of the mailbox and a location identifier in the format "server!partition". This response is valid for FIND, UPDATE, and LIST commands. It indicates that the mailbox name is currently reserved in the namespace, however the mailbox does not currently exist.

Response: MAILBOX
-----------------

A tagged MAILBOX response includes three parameters, the name of the mailbox, the location identifier (as with RESERVE), and the ACL of the mailbox. This response is valid for FIND, UPDATE, and LIST commands. IT indicates that the mailbox named is currently active on the given server with the given ACL.

Response: DELETE
----------------

A tagged DELETE response includes one parameter, the mailbox name. It indicates that the given name has been freed from the namespace and is no longer available. It is valid only in response to an UPDATE command.

Server Initial Response
=======================

The initial response from the server is a two line format. The first line MUST start with ``* OK MUPDATE`` and be followed by three strings: 
    * the server's hostname, 
    * an implementation-defined string, 
    * the version of the implementation (also implementation-defined).

The second line of the initial response begins with ``* AUTH`` and is followed by a space-separated list of SASL mechanisms that the server will accept.

Commands
========

The following are the valid commands that a client may send to the MUPDATE server: AUTHENTICATE, ACTIVATE, DELETE, FIND, LIST, LOGOUT, NOOP, RESERVE, and UPDATE. Only AUTHENTICATE and LOGOUT may be issued before a successful authentication has occured. Only LOGOUT and NOOP may be issued after UPDATE has been successfully issued. Only one successful AUTHENTICATE command may be issued per session.

AUTHENTICATE
------------

The AUTHENTICATE command initiates a SASL negotiation session between the client and the server. It has two parameters:

    1. Mandatory: the string for the authentication mechanism desired. 
    2. Optional: contents of the client first send. 
    
All SASL blobs sent across the wire must be in base64 encoded format, and followed by a CR and LF combination. Clients may cancel authentication by sending a ``*`` followed by a ``CR`` and ``LF``.

ACTIVATE
--------

The ACTIVATE command takes three parameters:

    1. a mailbox name, 
    2. a location in ``server!partition`` format, 
    3. and an ACL for the mailbox.

It will tell the server to insert into its database the given mailbox in the given location with the given ACL. An OK response indicates success, a NO response indicates some sort of failure occured. This is not a valid command to issue to a slave.

DELETE
------

The DELETE command takes one parameter:

    1. a mailbox name. 
    
The server should delete the given mailbox from its namespace, and return OK. A NO response indicates that either the session is not currently authenticated or the given mailbox does not exist. The delete command should immediately be sent to all slave databases. This is not a valid command to issue to a slave.

FIND
----

The FIND command takes a single parameter:
    
    1. a mailbox name. 
    
The server then responds with the current record for the given mailbox, if any and an OK response. A NO response is suitable if the connection is not currently authenticated.

LIST
----

The LIST command is similar to running FIND across the entire database. The LIST command takes an optional parameter:

    1. A prefix to match for the location field. 
 
Without the parameter, LIST returns results for all mailboxes in the database. For each mailbox that matches, it issues a MAILBOX or RESERVE response to the client. When all responses are complete, it issues an OK response.

LOGOUT
------

The LOGOUT command tells the server to close the connection. Its only valid response is an OK response.

NOOP
----

The NOOP command takes no parameters. An OK response indicates success. If this command is issued after an UPDATE command, then the OK response also indicates that all pending transactions have been sent to the listening slave.

RESERVE
-------

A RESERVE command takes two parameters: 

    1. the mailbox name 
    2. a location in ``server!partition`` format. 
    
It will first check for an existing reservation or activation of the given mailbox name, if there does exist such an entity, a NO response is returned, otherwise a reservation entry is put into the database, and an OK response is returned on success. NO is also returned if the connection is unauthenticated. This is not a valid command to issue to a slave.

UPDATE
------

The UPDATE command is how a slave initiates an update stream from the master (though it is valid to issue the command to a slave as well). In response to the command, the server returns a list of all mailboxes (as a LIST command with no parameters) and then an OK response. From this point forward whenever an update occurs to the master's database, it will stream the update to the slave (that is, it will send a RESERVE, MAILBOX, or DELETE response as the updates happen to its database). Only NOOP or LOGOUT are valid after this command is issued. This command may only be issued in the authenticated state.

Database Synchronization
========================

A distributed database protocol such as mupdate must address the issues of synchronization. In our case, there are two places where the database can become out of sync if a connection is not dropped cleanly. 

    1. The master mupdate database can reflect the existence of mailboxes in the namespace that do not exist (or vice versa), 
    2. The slaves need to ensure that their local database is up to date with the master whenever they come up.

Synchronization of Slaves to Master
-----------------------------------

Synchronization of slave databases to the master's database is simple. When the slave issues the UPDATE command to the master, the master dumps the entire contents of its database to the slave. The slave may then use this information to verify and update its local database.

Synchronization of Master to Backend Servers
--------------------------------------------

When server that holds mailboxes in the namespace comes up, it should perform a LIST operation against the master mupdate server, and then issue ACTIVATE and DELETE commands as necessary to bring the master's list of what is on this particular backend servers into sync with what actually exists on the backend server. Note that this document does not specify how to deal with conflicts (where one mailbox resides on multiple backend servers).



