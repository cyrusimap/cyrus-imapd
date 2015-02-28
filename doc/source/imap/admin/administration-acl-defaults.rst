Default Access Control Information on new folders
-------------------------------------------------

.. todo:: How is this calculated?

GETACL and MYRIGHTS
-------------------

GETACL
++++++

::

 |   Arguments:  mailbox name
 |
 |   Data:       untagged responses: ACL
 |
 |   Result:     OK - getacl completed
 |               NO - getacl failure: can't get acl
 |              BAD - command unknown or arguments invalid

The GETACL command returns the access control list for mailbox in an untagged ACL reply.

::

 |   Example:    C: A002 GETACL INBOX
 |               S: * ACL INBOX Fred rwipslda
 |               S: A002 OK Getacl complete
 |

The first string is the mailbox name for which this ACL applies.  This is followed by zero or more pairs of strings (identifier rights pairs), each pair contains the identifier for which the entry applies followed by the set of rights that the identifier has.

MYRIGHTS
++++++++

::

 |   Arguments:  mailbox name
 |
 |   Data:       untagged responses: MYRIGHTS
 |
 |   Result:     OK - myrights completed
 |               NO - myrights failure: can't get rights
 |              BAD - command unknown or arguments invalid

The MYRIGHTS command returns the set of rights that the user has to mailbox in an untagged MYRIGHTS reply.

::

 |   Example:    C: A003 MYRIGHTS INBOX
 |               S: * MYRIGHTS INBOX rwipslda
 |               S: A003 OK Myrights complete

The first string is the mailbox name for which these rights apply. The second string is the set of rights that the client has.

