Using Squatter for Faster IMAP SEARCH
=====================================

IMAP SEARCH, as described in :rfc:`3501`, is a IMAP4 (Rev1) command issued by
the client, but executed on the server. The Cyrus IMAP server will search the
mailbox for the content matching the search command issued. This may be an
intensive operation if executed on large mailboxes, and may therefor delay the
response to the client.

To significantly speed up the searching, Cyrus IMAP can create a cache of
message contents and meta-data using cyrus-squatter(8). This chapter explains
how to generate and maintain these caches.

Squatter Invocation
-------------------

Consider the following implications of running cyrus-squatter;

* Squatter creates the search index from all messages in the mailbox

.. todo:: list not complete


Generating the Search Indexes
-----------------------------

To generate the search index for all mailboxes, issue the following command::

    $ squatter -v

While the Cyrus IMAP server now has the search index available for the mailbox
contents, it does not automatically update the search index with new messages
coming in.

.. todo:: So how does the search index get updated? Do you run squatter on a
          daily basis from the EVENTS section of /etc/cyrus.conf
