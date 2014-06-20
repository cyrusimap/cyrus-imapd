New Features in Cyrus IMAP 2.5
==============================

The following new features are available in Cyrus IMAP 2.5.

Support for RFC 5464: IMAP METADATA
-----------------------------------

Cyrus IMAP now fully supports `RFC 5464: "The IMAP METADATA Extension" <http://tools.ietf.org/html/rfc5464>`__. This also means the support for the ANNOTATEMORE draft for IMAP has been dropped.

Mailbox Distribution
--------------------

Thanks to the work of Julien Coloos and colleagues, a new mode is available for server and partition selection upon mailbox creation. Prior to Cyrus IMAP 2.5, the server and/or partition on which to create a new mailbox was selected by detecting the largest amount of absolute free disk space on all servers and partitions. The mailbox distribution feature allows for more intelligent and flexible routines to be used in the selection. Please see our Administrator Guide for more details.

Catchall Mailbox for LMTP
-------------------------

Thanks to the work by Carsten Hoeger and Ralf Haferkamp, this new feature enables administrators to configure a target mailbox for mail delivered through LMTP to targetted mailboxes that do not exist.

For example, a mail that LMTP would deliver to **user/bovik**, which for the sake of argument does not exist in this example, setting **lmtp_catchall_mailbox** to **admin** will instead deliver the mail to **user/admin**.

.. note::
    **Mailbox name, not Email Address**

    Note that **lmtp_catchall_mailbox** must be a user mailbox name, not an email address. Also note that the **user/** namespace indicator as well as the hierarchy separator are to be omitted.

Does this impact lmtp_fuzzy_mailbox_match?
++++++++++++++++++++++++++++++++++++++++++

Environments that have **lmtp_fuzzy_mailbox_match** enabled, in order to have LMTP seek from the targetted, non-existent mailbox sub-folder (example: **user/bovik/spam/probably**) all the way to the toplevel mailbox folder (i.e. **user/bovik**) until it finds a mailbox (sub-)folder that does exist (example: **user/bovik/spam**), are not impacted by this setting.

Can the lmtp_catchall_mailbox include the path to a sub-folder of a target mailbox?
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

UNCONFIRMED

Can the lmtp_catchall_mailbox be a shared folder?
+++++++++++++++++++++++++++++++++++++++++++++++++

UNCONFIRMED 

