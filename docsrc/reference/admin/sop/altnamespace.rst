Alternative Namespace
=====================

.. _imap-switching-alt-namespace-mode:

Switching the Alternative Namespace
-----------------------------------

When switching the alternative namespace configuration variable in
:cyrusman:`imapd.conf(5)`, bear in mind that client applications might
conclude folders to have been removed and to have been added, as opposed
to having been moved, resulting in a complete download of all folders
and messages.

