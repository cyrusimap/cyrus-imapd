.. _cyrus-sieve:

===========
Cyrus Sieve
===========

Introduction
============

Cyrus Sieve is an implementation of the Sieve mail filtering language ( :rfc:`3028` ).

Mail filtering occurs on delivery of the message (within lmtpd).

Cyrus compiles sieve scripts to bytecode to reduce the overhead of parsing the scripts fully inside of lmtpd.

Sieve scripts can be placed either by the :cyrusman:`timsieved(8)` daemon (implementing the ManageSieve protocol, this is the preferred options since it allows for syntax checking) or in the user's home directory as a .sieve file.

Sieve scripts in shared folders
===============================

Cyrus has two types of repositories where Sieve scripts can live: 

1. **Personal** is per user and 
2. **Global** is for every user. Global scripts aren’t applied on incoming messages by default: users must include them in their scripts.
    * Note that there are two types of Global scripts: **global** and **global per domain**.

When you log into Cyrus IMAP with ``sieveshell`` you have the following combinations (Assuming there is ``manager`` and ``manager@example.com`` as admin in :cyrusman:`imapd.conf(5)`):

* ``sieveshell -a manager -u manager localhost`` - To edit global scripts.
* ``sieveshell -a manager@example.com -u manager@example.com localhost`` - To edit global script of example.com domain.
* ``sieveshell -a user@example.com -u user@example.com localhost`` - To edit personal scripts of some user.

Scripts for shared folders work different from user scripts. The last ones are loaded to the user’s repository and attached to the inbox when activated The first ones must be loaded to the global domain repository and attached to a shared folder by a user that has permission on it. Use the second combination listed above to load them and cyradm (or another compatible client) to do the attach::


    sieveshell -u manager@example.com -a manager@example.com localhost
    > put /tmp/my_script my_script
    cyradm -u user@example.com localhost
    localhost.localdomain> mboxcfg shared.folder@example.com sieve my_script

