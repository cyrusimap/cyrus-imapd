Welcome
=======

This is the Cyrus IMAP Server, version series 3.0.x.

No further development work will progress on anything older than version 2.3.
Versions 2.3 and 2.4 still receive security updates, but new features or
non-security bugfixes are unlikely to be backported.  Version 2.5 still
receives security updates and non-security bugfixes. Version 3.0 is under
active development.

What is Cyrus
=============

Cyrus is an IMAP server, where IMAP (Internet Message Access Protocol) 
is a protocol for accessing messages (mail, bboards, news, etc). 

The Cyrus IMAP server differs from other IMAP server implementations in 
that it is generally intended to be run on "sealed" servers, where 
normal users are not permitted to log in. The mailbox database is stored 
in parts of the filesystem that are private to the Cyrus IMAP system. 
All user access to mail is through the IMAP, NNTP, or POP3 protocols. 

The private mailbox database design gives the server large advantages in 
efficiency, scalability, and administratability. Multiple concurrent 
read/write connections to the same mailbox are permitted. The server 
supports access control lists on mailboxes and storage quotas on mailbox 
hierarchies. 



Cyrus goals
===========

To be the best open source secure, scalable mail server, providing 
breadth and depth of functionality across email, contacts, calendar 
and related messaging services.

How to install Cyrus if you're an administrator
===============================================

PLEASE be sure to read the documentation. The latest version is online 
at http://www.cyrusimap.org, but the version current for this 
distribution can be found in the doc/ subdirectory. This is pre-packaged 
in our release tarballs from http://www.cyrusimap.org, but needs to be 
built via `make doc-html` from the top level directory if you are using 
the source from git. 

Note that we only provide a source distribution. If you run into 
problems with any binary distribution, please contact the source of the 
binary distribution. 

Quick instructions are in the INSTALL file. 

How to set up Cyrus if you are a contributor
============================================

The latest Cyrus development or stable code is available at:

https://github.com/cyrusimap/cyrus-imapd

The latest development code is on the branch called 'master',
and the latest code destined for the stable release is on
the branch 'cyrus-imapd-$major.$minor'.  So the current
stable is called cyrus-imapd-2.5

Unlike releases, the git repository doesn't have a pre-built
./configure script.  You need to generate it with autoreconf:

    autoreconf -i

(See the autoreconf(1) man page for other options.)

Read through doc/build/html/imap/developer.html or the latest version is 
online at http://www.cyrusimap.org/imap/developer.html 

The doc is pre-packaged in our release tarballs from 
http://www.cyrusimap.org, but needs to be built via `make doc-html` from 
the top level directory if you are using the source from git. 


Are you upgrading?
==================

Be sure to read doc/legacy/install-upgrade.html

Think you've found a bug or have a new feature?
===============================================

Fantastic! We'd love to hear about it, especially if you have a patch to 
contribute. 

Check https://github.com/cyrusimap/cyrus-imapd/issues/ for any 
outstanding bugs. Old bugs can be found at 
https://bugzilla.cyrusimap.org/ 

Our guide at http://www.cyrusimap.org/feedback-bugs.html has all the 
information about how to contact us and how best to get your bug filed 
or your change accepted. 



Licensing Information
=====================

See the COPYING file in this distribution.

Contact us
==========

Whether you have a success story to share, or a bug to file, or a 
request for help or a feature to add or some documentation to contribute 
or you'd just like to say hi, we want to hear from you! See 
http://www.cyrusimap.org/feedback.html for various ways you can get hold 
of us. 


