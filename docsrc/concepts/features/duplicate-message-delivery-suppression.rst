======================================
Duplicate Message Delivery Suppression
======================================

Messages are delivered to IMAP users in a seemingly endless stream and
near continuous flow, but sometimes something fails.

A sending MTA awaits confirmation from a receiving MTA or MDA, and a
receiving MTA or MDA often waits giving out that confirmation until
after it has assured delivery was actually successful.

In cases where exactly in between the receiving MTA or MDA receiving
that assurance, and the sending MTA being sent the confirmation,
something fails, the sending MTA has not received confirmation, and it
will therefore re-attempt delivery.

This constitutes duplicate delivery -- of the same message, and should,
for a better user experience, be avoided -- unless your helpdesk is
idling and you want to keep it busy.

Cyrus IMAP employs technology to detect an attempt to deliver a
duplicate of a message already delivered, and can suppress the duplicate
from being posted to the users' mailboxes.

.. note::

    This section needs more content. Would you like to
    :ref:`help out <contribute-docs>`?

.. todo:: Please write me.

Back to :ref:`imap-features`
