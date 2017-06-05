.. _cyrus-sieve:

===========
Cyrus Sieve
===========

.. contents::


Introduction
============

Cyrus Sieve is an implementation of the Sieve mail filtering language ( :rfc:`3028` ). It allows a series of tests to be applied against an incoming message, with actions to take place if there is a match.

Mail filtering occurs on delivery of the message (within lmtpd).

Cyrus compiles sieve scripts to bytecode to reduce the overhead of parsing the scripts fully inside of lmtpd. This occurs automatically if :cyrusman:`sieveshell(1)` is used to place the scripts on the server.

Sieve scripts can be placed either by the :cyrusman:`timsieved(8)` daemon (implementing the ManageSieve protocol :rfc:`5804`; this is the preferred options since it allows for syntax checking) or in the user's home directory as a .sieve file.

Installing Sieve
================

This section assumes that you :ref:`compiled Cyrus <compiling>` with sieve support. If you specified ``--disable-sieve`` when running ``./configure``, you did NOT compile the server with sieve support.

Configure sieve
---------------

Depending on what's in your ``/etc/services`` file, sieve will usually be set to listen on port 2000 (old convention) or port 4190 (as specified by :rfc:`5804`).

Add lines to :cyrusman:`cyrus.conf(5)` to make the server listen to the right ports for sieveshell commands::

    sieve         cmd="timsieved" listen="servername:sieve" prefork=0
    managesieve   cmd="timsieved" listen="servername:4190" prefork=0

Configure outgoing mail
-----------------------

Some Sieve actions (redirect, vacation) can send outgoing mail.

You'll need to make sure that lmtpd can send outgoing messages. Currently, it invokes ``/usr/lib/sendmail`` by default to send messages. Change this by adding a line like::

    sendmail: /usr/sbin/sendmail

in your :cyrusman:`imapd.conf(5)`. If you're using Postfix or another MTA, make sure that the sendmail referenced in "/etc/imapd.conf" is Sendmail-compatible.

Managing Sieve Scripts
======================

Since Cyrus is based around the concept of a sealed-server, the normal way for users to manipulate Sieve scripts is through the :cyrusman:`sieveshell(1)` utility.

If, for some reason, you do have user home directories on the server, you can use the **sieveusehomedir** option in :cyrusman:`imapd.conf(5)` and have the sieve script stored in the home directory of the user as ``~/.sieve``.

Sieve scripts in shared folders
-------------------------------

Cyrus has two types of repositories where Sieve scripts can live:

1. **Personal** is per user and
2. **Global** is for every user. Global scripts aren’t applied on incoming messages by default: users must include them in their scripts.
    * Note that there are two types of Global scripts: **global** and **global per domain**.

When you log into Cyrus IMAP with :cyrusman:`sieveshell(1)` you have the following combinations (Assuming there is ``manager`` and ``manager@example.com`` as admin in :cyrusman:`imapd.conf(5)`):

* ``sieveshell -a manager -u manager localhost`` - To edit global scripts.
* ``sieveshell -a manager@example.com -u manager@example.com localhost`` - To edit global script of example.com domain.
* ``sieveshell -a user@example.com -u user@example.com localhost`` - To edit personal scripts of some user.

Scripts for shared folders work different from user scripts. The last ones are loaded to the user’s repository and attached to the inbox when activated The first ones must be loaded to the global domain repository and attached to a shared folder by a user that has permission on it. Use the second combination listed above to load them and cyradm (or another compatible client) to do the attach::


    sieveshell -u manager@example.com -a manager@example.com localhost
    > put /tmp/my_script my_script
    cyradm -u user@example.com localhost
    localhost.localdomain> mboxcfg shared.folder@example.com sieve my_script


Testing the sieve server
========================

The Sieve server, :cyrusman:`timsieved(8)`, is used for transporting user Sieve scripts to the sealed IMAP server. It is incompatible with the **sieveusehomedir** option. It is named after the principal author, Tim Martin, who desperately wanted something named after him in the Cyrus distribution.

From your normal account, telnet to the sieve port on the server you're setting up::

    telnet servername sieve

If your server is running, you'll get a message similar to the following one::

    Trying 128.2.10.192...
    Connected to servername.domain.tld.
    Escape character is '^]'.
    "IMPLEMENTATION" "Cyrus timsieved v1.1.0"
    "SASL" "ANONYMOUS PLAIN KERBEROS_V4 GSSAPI"
    "SIEVE" "fileinto reject envelope vacation imapflags notify subaddress regex"
    OK

Any message other than one similar to the one above means there is a problem. Make sure all of authentication methods you wish to support are listed. This list should be identical to the one listed by "imapd" earlier. Next terminate the connection, by typing::

    logout

Next test authenticating to the sieve server. To do this run the :cyrusman:`sieveshell(1)` utility. You must specify the server. If you run this utility from a different machine without the "sieve" entry in "/etc/services", port 2000 will be used.

::

    sieveshell servername
    Please enter your password: ******
    > quit

This should produce the message "Authentication failed" with a description of the failure if there was a problem.

Next you should attempt to place a sieve script on the server. To do this create a file named ``myscript.script`` with the following lines. Replace "foo@example.org" with an email address you can send mail from, but that is not the one you are working on now.

::

    require ["reject","fileinto"];
    if address :is :all "From" "foo@example.org"
    {
        reject "testing";
    }

To place this script on the server run the following command::

    sieveshell servername
    Please enter your password: ******
    > put myscript.script
    > activate myscript
    > quit

This should place your script on the server and make it the active script.

Test that the sieve script is actually run. Send a message to the address you're working on from the address mentioned in the sieve script. The message should be rejected.

When you're done, don't forget to delete your testing script::

    sieveshell servername
    Please enter your password: ******
    > delete myscript.script
    > quit

Cyrus Sieve Support
===================

.. _cyrus-sieve-specialuse:

Special use folders
-------------------

Some mail clients allow users to rename the system folders, such as Archive and Trash. This can make sieve scripts break if they are using folder names explicitly. Fortunately such folders have a special use flag, allowing you to access them from sieve without needing to know their current titles.

* \\Archive
* \\Drafts
* \\Junk - also known as the Spam folder
* \\Sent
* \\Trash

.. _cyrus-sieve-extensions:

Supported extensions
--------------------
Sieve has a lot of `extensions <http://www.iana.org/assignments/sieve-extensions/sieve-extensions.xhtml>`_. Cyrus supports a subset of these:

* Sieve language reference :rfc:`5228`
* Vacation Extension :rfc:`5230`
* Vacation Seconds :rfc:`6131`
* Relational Tests :rfc:`5231`
* Subaddress Extension :rfc:`5233`
* Copying Without Side Effects :rfc:`3894`
* Regular Expression Extension `Draft regex RFC <http://tools.ietf.org/html/draft-ietf-sieve-regex-01>`_
* Checking Mailbox Status and Accessing Mailbox Metadata :rfc:`5490`
* Notify Extension :rfc:`5435`
* Include :rfc:`6609`
* Date :rfc:`5260`
* Index :rfc:`5260`
* Variables :rfc:`5229`
* Editheader Extension :rfc:`5293`
* Reject and Extended Reject :rfc:`5429`
* Externally Stored Lists :rfc:`6134`
* Duplicate Extension :rfc:`7352`
* Ihave Extension :rfc:`5463`
* Delivering to Special-Use Mailboxes `Draft special-use RFC <http://tools.ietf.org/html/draft-bosch-sieve-special-use-01>`_
* IMAP flag Extension `Draft imap flags RFC <http://tools.ietf.org/html/draft-ietf-sieve-imapflags-05>`_
* Body Extension `Draft body extension RFC <http://tools.ietf.org/html/draft-ietf-sieve-body-02>`_

Note that the final RFCs of these last sieve extensions have significant changes that are not currently supported.

Sieve Tools
-----------

* :cyrusman:`timsieved(8)` - server side daemon to accept requests from sieveshell
* :cyrusman:`sievec(8)` - compile a script into bytecode. See sieved.
* :cyrusman:`sieved(8)` - decompile a script back from bytecode. See sievec.
* :cyrusman:`masssievec(8)` - compiles all the scripts in **sievedir** from ``imapd.conf``.
* :cyrusman:`sivtest(1)` - authenticate and test against a MANAGESIEVE server such as timsieved.
* :cyrusman:`sieveshell(1)` - allow users to manage scripts on a remote server, via MANAGESIEVE
* :cyrusman:`translatesieve(8)` - utility script to translate sieve scripts to use **unixhierarchysep** and/or **altnamespace**

Writing Sieve
=============

Sieve scripts can be used to automatically delete or forward messages; to send autoreplies; to sort them in folders; to mark messages as read or flagged; to test messages for spam or viruses; or to reject messages at or after delivery. `Sieve.info <http://sieve.info>`_ has more information on sieve and its uses.

There's a `good sieve reference <http://thsmi.github.io/sieve-reference/en/index.html>`_ online which describes the language.

For those who prefer a client to write code in, Sieve.info has a `list of desktop, web and command line clients <http://sieve.info/clients>`_.
