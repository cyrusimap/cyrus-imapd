.. _developer-jmap:

============
JMAP support
============

`JMAP <http://jmap.io/>`_ is an alternate mechanism for synchronising a mail client with a mail server, intended as a replacement for IMAP. It is a transport-agnostic, stateless JSON-based API, aiming to be compatible with the IMAP data model, but with reduced data usage and more efficient synchronisation.

Cyrus administration
====================

Compile JMAP support into Cyrus
-------------------------------

Set the ``--enable-http`` option when running autoconf to enable JMAP (and DAV) support in Cyrus. Once installed, the ``jmap`` module must be enabled in ``imapd.conf``, such as

    ``httpmodules: caldav jmap tzdist``

JMAP client
===========

Test JMAP support
-----------------

Once Cyrus is running, you can test JMAP on the command line for any existing Cyrus user. The user must at least have an INBOX provisioned but is not required to have any calendars, contacts or messages.

To obtain the JMAP calendars for user ``test``, issue the following request:

.. code-block:: bash

    curl -X POST \
         -H "Content-Type: application/json" \
         -H "Accept: application/json" \
         --user test:test \
         -d '[["getCalendars", {}, "#1"]]' \
         http://localhost/jmap

you should get a response which looks similar to

.. code-block:: none

    [
        [
            "calendars",
            {
                "accountId": "test@localhost",
                "list": [
                    {
                        "color": "#FD8208FF",
                        "id": "Default",
                        "mayAddItems": true,
                        "mayDelete": true,
                        "mayModifyItems": true,
                        "mayReadFreeBusy": true,
                        "mayReadItems": true,
                        "mayRemoveItems": true,
                        "mayRename": true,
                        "name": "Default",
                        "sortOrder": 1,
                        "x-href": "/dav/calendars/user/test@localhost/Default"
                    }
                ],
                "notFound": null,
                "state": "184"
            },
            "#1"
        ]
    ]

Similar requests exist to obtain contacts and messages. For details, see the
JMAP specification.

Optional: Install sample JMAP client
------------------------------------

.. note::

    Cyrus does not yet implement JMAP authentication. Instead, it requires for
    each request the HTTP Basic Auth header set with the account's username and
    password. If you intend to use the JMAP perl or web clients, make sure to add
    the required authentication headers for each request.

You can set up the `JMAP Proxy (perl) <https://github.com/jmapio/jmap-perl>`_ to sit in front of a standard IMAP server and query that over a custom JMAP client.

Or you can install a sample `JMAP web client <https://github.com/jmapio/jmap-demo-webmail>`_ which requires the `Overture.js library <https://github.com/fastmail/overture>`_ and `JMAP JS library <https://github.com/jmapio/jmap-js>`_ to talk to a JMAP-enabled Cyrus server and build from there (subject to the `MIT license <https://tldrlegal.com/license/mit-license>`_.

The web client is a simple example (no compose, contacts or calendars). When you create your account, the most recent 50 emails will be downloaded in their entirety, so the first page should be snappy immediately. After that, you are redirected to the landing page. A background task will continue to pull in batches of messages and add them to your account, so you will see older messages appear while you are using the interface.

Developing the client further
-----------------------------

You'll want to become deeply familiar with the `JMAP developer documentation <http://jmap.io/#i-want-to-get-involved-with-jmap.-what-do-i-need-to-know?>`_


JMAP implementation in Cyrus
============================
The JMAP implementation in Cyrus is at various stages of maturity.

Working
-------

* **Contacts**
    * Mostly. All JMAP methods are implemented. JMAP blobs are not supported.
    
* **Calendars**
    * Mostly. All JMAP methods are implemented. JMAP blobs are not supported.

If you encounter any bug for these object types, please let us know.

In Progress
-----------

* **Messages**
    * *getMessages*: works mostly. 
    * *setMessages*: supports to create drafts, send mails. Does not support creation of messages in multiple mailboxes, or any mailbox moves.
    * *getMailboxes*: mostly working, except conversations.
    * *setMailboxes*: mostly working
    * *getMessageList*: supports filters

In general, messages are minimally supported and are under development.


Not yet implemented
-------------------

* **Authentication**
    * Cyrus does not yet implement the JMAP authentication workflow. All the JMAP methods in httpd currently require an account logged in via Basic Authentication.

* **Attachments**
    * Attachments and JMAP blobs are not implemented. There are technical
      reasons for this and we are working on it. As a workaround, you might
      make use of the ``x-href`` properties, to obtain the respective JMAP
      object in iCalendar, vcard or mail representation.

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
    * The JMAP filters require phrase matching for text properties, but as a placeholder we currently only support case-insensitive substring search. We are working on Sphinx/Xapian integration.

Needs improvement
-----------------

* **Lookup message by guid**
    * We use message guids as JMAP message ids. Currently, that requires O(n), where n is the number of records across all a users mailboxes. That really should become O(1) or O(lgN)
    
* **Lookup mailbox by unique-id**
    * We use mailbox unique-ids for JMAP mailbox ids. Currently, the lookup is O(n) (n is the number of a users mailboxes). Should be O(1) or O(lgN) 
    
* **Filters**
    * Message filters currently build on a very naive filter implementation. As a
      consequence, filtering messages is slooooow. We are working on Xapian
      integration. Until then, you might not want to filter for messages.
    * Calendar and contacts similarly use naive filters but typically operate
      on a significantly smaller database. Still, we are working on speeding up
      these filters as well.
      
* **Error reporting**
    * The JMAP spec requires all invalid properties of a request to be reported. 
    * Contacts fail at the first property error. 
    * Calendars and Messages try hard to report all erroneous properties. 
    * None of the JMAP error handlers report an error description.
