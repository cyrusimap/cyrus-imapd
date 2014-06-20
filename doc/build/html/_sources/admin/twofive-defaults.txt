Changes to Default Settings from 2.4 to 2.5
===========================================

Several settings have changed defaults. For environments that upgrade from 2.4 to 2.5, please be aware of the consequences of these defaults having been changed, listed below. 

lmtp_downcase_rcpt
------------------
Before Cyrus IMAP 2.5, **lmtp_downcase_rcpt** had defaulted to 0, meaning the recipient address had always been case-sensitive. `RFC 2821`_ however states:

    *However, exploiting the case sensitivity of mailbox local-parts impedes interoperability and is discouraged.*

Cyrus IMAP developers and users alike therefor consider converting the mailbox local-parts to lowercase is therefor justified.

Preserving Old Behavior
+++++++++++++++++++++++

To preserve the old behaviour, please make sure ``/etc/imapd.conf`` has the following snippet:

::

    (...)
    lmtp_downcase_rcpt: 0
    (...)

Reference
+++++++++

This switch has been suggested and discussed on the `Cyrus Development mailing list <https://lists.andrew.cmu.edu/mailman/listinfo/cyrus-devel>`__, in `this thread <https://lists.andrew.cmu.edu/pipermail/cyrus-devel/2011-February/001734.html>`__. 

.. _RFC 2821: http://tools.ietf.org/html/rfc2821

