.. _developer-jmap:

============
JMAP support
============

`JMAP <http://jmap.io/>`_ is an alternate mechanism for synchronising a mail client with a mail server, intended as a replacement for IMAP. It is a transport-agnostic, stateless JSON-based API, aiming to be compatible with the IMAP data model, but with reduced data usage and more efficient synchronisation.

Cyrus administration
====================

Compile JMAP support into Cyrus
-------------------------------

1. Enable JMAP (and DAV) in Cyrus:

    * ``./configure --enable-http --enable-jmap --enable-xapian`` along with your other configuration options.

2. Enable :ref:`conversation support <imap-concepts-deployment-db-conversations>`

    * In :cyrusman:`imapd.conf(5)`, set ``conversations: 1``, ``conversations_db: twoskip``
    * Create a conversations.db for each user: ``ctl_conversationsdb -b -r``

3. JMAP depends on Xapian. For full support (to gain full word boundary
distinctions in CJK languages - Chinese, Japanese and Korean), this needs to be
manually compiled due to extra patches needing to be applied.
Our :ref:`Xapian install guide <imapinstall-xapian>` shows how.

4. Once installed, the ``jmap`` module must be enabled in
:cyrusman:`imapd.conf(5)`: ``httpmodules: jmap``

JMAP client
===========

Test JMAP support
-----------------

Once Cyrus is running, you can test JMAP on the command line for any existing Cyrus user. The user must at least have an INBOX provisioned but is not required to have any calendars, contacts or messages.

To obtain the JMAP mailbox folders for user ``test``, issue the following request:

.. code-block:: bash

    curl -X POST \
         -H "Content-Type: application/json" \
         -H "Accept: application/json" \
         --user test:test \
         -d '{
           "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail" ],
           "methodCalls": [[ "Mailbox/get", {}, "c1" ]]
         }' \
         http://localhost/jmap/

you should get a response which looks similar to

.. code-block:: none

    {
      "methodResponses": [
        ["Mailbox/get", {
          "state": "0",
          "list": [{
            "id": "7c76ec2b-9bd8-4091-a665-640e232e3877",
            "name": "Inbox",
            "parentId": null,
            "myRights": {
              "mayReadItems": true,
              "mayAddItems": true,
              "mayRemoveItems": true,
              "mayCreateChild": true,
              "mayDelete": false,
              "maySubmit": true,
              "maySetSeen": true,
              "maySetKeywords": true,
              "mayAdmin": true,
              "mayRename": false
            },
            "role": "inbox",
            "totalEmails": 0,
            "unreadEmails": 0,
            "totalThreads": 0,
            "unreadThreads": 0,
            "sortOrder": 1,
            "isSubscribed": false
          }, {
            "id": "5d9e4f44-7df9-4489-b8b3-32625b552aa1",
            "name": "Trash",
            "parentId": null,
            "myRights": {
              "mayReadItems": true,
              "mayAddItems": true,
              "mayRemoveItems": true,
              "mayCreateChild": true,
              "mayDelete": true,
              "maySubmit": true,
              "maySetSeen": true,
              "maySetKeywords": true,
              "mayAdmin": true,
              "mayRename": true
            },
            "role": null,
            "totalEmails": 0,
            "unreadEmails": 0,
            "totalThreads": 0,
            "unreadThreads": 0,
            "sortOrder": 10,
            "isSubscribed": true
          }],
          "notFound": [],
          "accountId": "test"
        }, "c1"]
      ],
      "sessionState": "0"
    }

Similar requests exist to obtain contacts and calendars. For details, see the
JMAP specification.

Optional: Install sample JMAP client
------------------------------------

.. note::

    Cyrus does not yet implement JMAP authentication. Instead, it requires for
    each request the HTTP Basic Auth header set with the account's username and
    password. If you intend to use the JMAP perl or web clients, make sure to add
    the required authentication headers for each request.

You can set up the `JMAP Proxy (perl) <https://github.com/jmapio/jmap-perl>`_ to sit in front of a standard IMAP server and query that over a custom JMAP client.

Or you can install a sample `JMAP web client <https://github.com/jmapio/jmap-demo-webmail>`_ which requires the `Overture.js library <https://github.com/fastmail/overture>`_ and `JMAP JS library <https://github.com/jmapio/jmap-js>`_ to talk to a JMAP-enabled Cyrus server and build from there (subject to the `MIT license <https://tldrlegal.com/license/mit-license>`_).

The web client is a simple example (no compose, contacts or calendars). When you create your account, the most recent 50 emails will be downloaded in their entirety, so the first page should be snappy immediately. After that, you are redirected to the landing page. A background task will continue to pull in batches of messages and add them to your account, so you will see older messages appear while you are using the interface.

Developing the client further
-----------------------------

You'll want to become deeply familiar with the `JMAP developer documentation <http://jmap.io/#i-want-to-get-involved-with-jmap.-what-do-i-need-to-know?>`_


.. note::

    JMAP implementation in Cyrus is a work in progress. Current status can be
    viewed on the main :ref:`JMAP configuration page <jmap-implementation>`.
