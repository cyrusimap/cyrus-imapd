.. _jmap:
============
JMAP support
============

`JMAP <http://jmap.io/>`_ is an alternate mechanism for synchronising a mail client with a mail server, intended as a replacement for IMAP. It is s a transport-agnostic, stateless JSON-based API, aiming to be compatible with the IMAP data model, but with reduced data usage and more efficient synchronisation.

Cyrus administration
====================

Compile JMAP support into Cyrus
-------------------------------

How to. Flags.

JMAP client
===========

Install sample JMAP client
--------------------------

You can set up the `JMAP Proxy (perl) <https://github.com/jmapio/jmap-perl>`_ to sit in front of a standard IMAP server and query that over a custom JMAP client.

Or you can install a sample `JMAP web client <https://github.com/jmapio/jmap-demo-webmail>`_ which requires the `Overture.js library <https://github.com/fastmail/overture>`_ and `JMAP JS library <https://github.com/jmapio/jmap-js>`_ to talk to a JMAP-enabled Cyrus server and build from there (subject to the `MIT license <https://tldrlegal.com/license/mit-license>`_.

Running the sample client
-------------------------

The web client is a simple example (no compose, contacts or calendars). When you create your account, the most recent 50 emails will be downloaded in their entirety, so the first page should be snappy immediately. After that, you are redirected to the landing page. A background task will continue to pull in batches of messages and add them to your account, so you will see older messages appear while you are using the interface.

Developing the client further
-----------------------------

You'll want to become deeply familiar with the `JMAP developer documentation <http://jmap.io/#i-want-to-get-involved-with-jmap.-what-do-i-need-to-know?>`_


JMAP implementation in Cyrus
============================

Working
-------

* **Contacts**
    * Mostly
* **Calendars**
    * Mostly

In Progress
-----------

* **Messages**
    * *getMessages*: works mostly. Not supported: message threads, inReplyTo or proper html-to-text body conversion (see `http_jmap.c:2248 <https://github.com/rsto/cyrus-imapd/blob/jmap/imap/http_jmap.c#L2248>`_).
    * *setMessages*: supports to create drafts, send mails. Does not support creation of messages in multiple mailboxes, or any mailbox moves.
    * *getMailboxes*: mostly working, except conversations.
    * *setMailboxes*: mostly working
    * *getMessageList*: supports filters


Not yet implemented
-------------------


* **Authentication**
    * All the JMAP methods in httpd currently require an account logged in via Basic Authentication.

* **Attachments**

    *Information taken from* `JMAP: Current status <https://www.mail-archive.com/cyrus-devel%40lists.andrew.cmu.edu/msg03450.html>`_ *thread on the cyrus-devel mailing list*
    
    I have worked on a proof-concept of supporting the JMAP File API (aka
    “blobs”) in Cyrus, but it’s far from complete and it didn’t seem
    promising enough to merge it into the main JMAP branch. As discussed
    with Bron, I rather would like to get back to the design stage. For
    that, I welcome any input! 

    My current assumptions are that the majority of blobs will belong to
    exactly one JMAP object, and most of the blobs uploaded by an account
    will only be attached to one object. Also: while I assume most blobs
    belong to mails, some users may have (rarely changing) avatar blobs in
    most of their contacts. I assume calendar event attachments to be rarely
    used.

    Under these assumptions, I plan the blob service to keep a blob in its
    containing object as long as possible. E.g. if a JMAP client wants to
    download a mail attachment, the blob service should be able to use the
    blobId to locate the containing message in the mailboxes. It should not
    create a copy of the blob. That’s very similar to the current JMAP proxy
    implementation. Things get tricky though, once such a blob is used as an
    attachment for another object or even another entity (e.g. from message
    blob to avatar blob). In order to better understand what a JMAP client
    might want to do, I’ve summarised all use cases I could come up with in
    a `Google
    spreadsheet <https://docs.google.com/spreadsheets/d/15CvwT-aYw8ks3PbCS3Svm2sPfKWTbIB_JNBEBLMoGSc/edit?pref=2&pli=1#gid=0>`_.
    Note that the prioritisation is solely mine and some of these use cases
    probably shouldn’t be supported at all. Also, in a sane blob service,
    one control flow should over multiple use cases.

    The JMAP blob ref-counting will require a tight grip on what happens to
    mails, calendars and contacts. Maybe the notify service could be used to
    support asynchronous ref-counting? Also: Since calendar managed
    attachments are almost a subset of the more generic JMAP blobs (except
    for deletions!), these two features might even be merged. The blob
    service might deserve its own httpd and I could imagine it being
    decoupled from the JMAP code. The blob HTTP service should also be
    configurable to only redirect to “safe” URLs for custom calendar or
    contact URL attachments.

* **Multi-user accounts**
    All the current JMAP code operates on the userid currently authenticated
    to Cyrus httpd. That is, the `‘accountId`` property in JMAP requests is
    not really supported.


* **Remote mailboxes**
* **Events**
    * The JMAP event service hooks into notifications, so that’s almost done.
    * What’s missing is the service layer (Bron knows more).
* **Messages**
    * Search snippets
    * Conversations
    * Anything else not mentioned in the "In Progress" section above
* **Phrase-Matching search**
    * The JMAP filters require phrase matching for text properties, but as a placeholder we currently only support case-insensitive substring search.

Needs improvement
-----------------

* **Lookup message by guid**
    * We use message guids as JMAP message ids. Currently, that requires O(n), where n is the number of records across all a users mailboxes. That really should become O(1) or O(lgN)
* **Lookup mailbox by unique-id**
    * We use mailbox unique-ids for JMAP mailbox ids. To look them up,  there is a stub in `mboxlist <https://github.com/rsto/cyrus-imapd/blob/jmap/imap/mboxlist.c#L598>`_, but it’s O(n) (n is the number of a users mailboxes). Should be O(1) or O(lgN) 
* **Filters**
    * The contacts and calendar code reuses the same JMAP filter code. We agreed to first implement naive search for these objects. Currently, we match every record in a a users calendar or contacts mailboxes against the JMAP filter. At least for calendar events, this could be sped up, e.g. it would be straight-forward to only pull out calendar events for a custom time range or even create the SQL statements on demand based on the filter contents.
    * Also, for message filters, there is a very naive filter implementation. That’s just meant as a placeholder, and should be refactored to make use of Xapian.
* **Error reporting**
    * The JMAP spec requires all invalid properties of a request to be reported. 
    * Contacts fail at the first property error. 
    * Calendars and Messages try hard to report all erroneous properties. 
    * None of the JMAP error handlers report an error description.


