Access Rights
-------------

Access rights in Cyrus IMAP are -or should be- fully compatible with `RFC 4314`_.

Access Rights available in Cyrus IMAP
+++++++++++++++++++++++++++++++++++++

``l``
    Stands for **lookup**.

    The ACI subject can lookup this folder, and see that the folder exists, meaning the folder will appear in a **LIST "" "*"**.

    Folders to which the ACI subject has no lookup rights may still be subscribed to. The lookup right is only required if Cyrus IMAP has been configured with the **allowallsubscribe** setting to **false** (0). In Cyrus IMAP 2.5, this setting defaults to **false** (0). In a Cyrus IMAP Murder, this setting is typically set to **true** (1).

    The ``l`` right can be assigned to a folder, without the ``l`` right having been given out for the parent folder. Cyrus IMAP will pretend the parent folder does not exist;

.. note::

    | Example 2.1. Example Client - Server Session with ``l`` Right on Subfolder Only
    | `RFC 4314`_, section 4., page 13, states the following example:
    | 
    | Note that if the user has ``l`` right to a mailbox "A/B", but not to its parent mailbox "A", the LIST command should behave as if the mailbox "A" doesn't exist, for example::
    | 
    |   C: A777 LIST "" *
    |   S: * LIST (\NoInferiors) "/" "A/B"
    |   S: * LIST () "/" "C"
    |   S: * LIST (\NoInferiors) "/" "C/D"
    |   S: A777 OK LIST completed

.. todo::

   Fix formatting in the above example

``r``
    Stands for **read**.
    The ACI subject can read the contents of this folder, meaning that the ACI subject is allowed to **SELECT** or **EXAMINE** the folder, query its **STATUS**, **FETCH** data, **SEARCH** the contents, and **COPY** contents from the folder.

    The ``r`` right also allows the user to **GETMETADATA** when used in conjunction with the ``l`` right, as defined in `RFC 5464`_. 

``s``
    Stands for **seen**.
    The ACI subject is permitted to maintain the ACI subject's seen state for this folder, or the shared seen state in case the **/vendor/cmu/cyrus-imapd/sharedseen** has been set to **true** (see mboxconfig in Chapter 3, cyradm). Additionally, the \\Recent flags are preserved for the ACI subject. 

.. todo::
   Make the mboxconfig word above into a link to the appropriate cyradm subsection

``w``
    Stands for **write**.
    The ACI subject is permitted to write to the folder, actually meaning the ACI subject is permitted to maintain flags and keywords other then \\Seen and \\Deleted, which are controlled using the ``s`` and ``t`` rights respectively.
    The ``w`` right also allows the user to **SETMETADATA** when used in conjunction with the ``l`` and ``r`` rights, as defined in `RFC 5464`_.

.. note::
    **IMAP Clients**

    IMAP clients may expect to be able to set flags other then \\Seen and \\Deleted and attempt to set those flags immediately along with a "Mark as read" action, without the ACI subject actually being permitted to set some of those flags through the ``w`` right.
    `RFC 4314`_, section 4., page 15, states that the server SHOULD NOT fail, as the tagged NO response is not handled very will by deployed clients. In order to comply, we have `Bug #3488 <https://bugzilla.cyrusimap.org/show_bug.cgi?id=3488>`__, as Cyrus IMAP currently does seem to issue a tagged NO response. 

``i``
    Stands for **insert**.
    The ACI subject is permitted to insert content into a folder, meaning the ACI subject may **COPY** messages with this folder as the target folder, and may **APPEND** messages to this folder. 

``p``
    Stands for **post**.
    The post right currently is exclusive to Cyrus IMAP, and allows the ACI subject to send email to the submission address for the mailbox.
    This right differs from the ``i`` right in that the delivery system inserts trace information into submitted messages.
    Example implementations using the ``p`` right include shared folders to which specific recipient addresses are delivered through LMTP pre-authorized as the **postuser**, which must then also have the ``p`` right on the target folder. 

``c``
    Stands for **create**.
    The create right is a right introduced with `RFC 2086`_ (IMAP4 ACL extension), indicating the ACI subject's right to create new sub-folders in the parent folder on which this right has been assigned, but also to delete the same folder.
    Since `RFC 4314`_, the ``c`` right has been replaced with the ``k`` right to **CREATE** folders with, the ``x`` right to **DELETE** folders with.

.. important::
    **The ``c`` right should no longer be used.**

    Even though Cyrus IMAP is backwards compatible when it comes to the ``c`` right, which it implements as implying as the ``k`` right, implementations should not count on the ``c`` right backwards compability to be around forever, and to fully implement the legacy ``c`` right, use ``kx``. 

``k``
    The ACI subject has the right to **CREATE** a new folder if the ``k`` right exists on the parent folder of the folder created.
    The rights required for a **RENAME** to be successful could be illustrated by describing a **RENAME** as a **CREATE** of the new folder, not exactly followed by a **COPY** on the old folder's contents, but more like a move like on a filesystem, and finally a **DELETE** on the old folder.
    As such, the ``k`` is the right required on the parent folder of the target folder, and the ``x`` right on the source folder. To further illustrate;

.. note::
    Example 2.2. Example Client Session with RENAME

    Suppose the ACI subject has the k right on folder "C/", and the x right on folder "A/B", then a RENAME A/B C/B would succeed.

.. todo:: Fix formatting of above example.

``a``
    Stands for **administer**.
    The ACI subject is allowed to administer the folder, meaning the ACI subject is allowed to perform administrative operations on the folder. The ``a`` right is needed to successfully execute **SETACL**, **DELETEACL** (short for **SETACL ""**) and to execute **GETACL** or **LISTRIGHTS**.

.. note::
    **IMAP Clients**

    IMAP clients may issue a **GETACL** in order to obtain the ACI subject's rights on the folder, where they should be using **MYRIGHTS**, as **GETACL** or **LISTRIGHTS** return the full Access Control List, including other ACI subject's identifiers.

    Unless the ACI subject has the ``a`` right on a folder, issuing a **GETACL** or **LISTRIGHTS** will cause Cyrus IMAP to send a tagged "NO: Permission denied" response if the ACI subject has the ``l`` (lookup) right on the folder, and a "NO: No Such Mailbox" response otherwise, as per section 8. of `RFC 2086`_ and section 6. of `RFC 4314`_ – both conveniently called "Security Considerations". 

``x``
    use this to indicate the ACI subject has the right to delete the mailbox, as opposed to ``c`` or ``d`` 

``t``
    The ACI subject is allowed to delete messages from this folder, meaning that the ACI subject is allowed to flag messages as \\Deleted.

    In IMAP, messages are only actually deleted in a way that at least makes them invisible to the folder's users need to be expunged. For the corresponding **EXPUNGE** however, the ``x`` right is required. 

``n``
    The ACI subject is allowed to annotate individual messages in this folder, in compliance with `RFC 5257`_.

    The ACI subject must also have the ``r`` right, as otherwise the subject won't know which messages are available to annotate. 

``e``
    Stands for **expunge**.

    The ACI subject is allowed to expunge messages in this folder, meaning the ACI subject has the right to remove all messages that have been flagged as \\Deleted from all visibility.

    In IMAP, expunging messages only applies to messages flagged as \\Deleted. For the ACI subject to be able to flag messages as \\Deleted, the however, the ``t`` right is required.

    We say "remove from all visibility", because the implementation of expunging messages in Cyrus IMAP is ACI subject to the **expunge_mode** in ``/etc/imapd.conf``, which when set to **delayed** only causes the reference to the expunged messages to be deleted from the folder index database - effectively removing the expunged message(s) from all visibility, while they remain in place on the Cyrus IMAP server filesystem.

.. note::
    **IMAP Clients**

    IMAP clients may expect to be able to **EXPUNGE** a folder regardless of the availability of this right. 

``d``
    Stands for **delete**.

    This is the legacy, `RFC 2086`_ access control right for the delete right. In versions of Cyrus IMAP implementing only this right, ACI subjects were allowed to flag messages as \\Deleted and expunge folders.

    The delete right has been split in to three separate rights, ``t`` (flag messages as deleted), ``e`` (expunge folder) and ``x`` (delete folder).

.. note:: **deleteright setting**

    The **deleteright** setting in ``/etc/imapd.conf`` controls the `RFC 2086`_ right which controls whether or not the ACI subject may delete a folder. However, this setting (as the original specification for the delete right was considered ambiguous) is ignored, and if it is set to ``c``, is automatically converted to the ``x`` right.

.. important::
    **The d right should no longer be used**

    Even though Cyrus IMAP is backwards compatible when it comes to the ``d`` right, which it implements as implying as the ``e`` and ``t`` rights, implementations should not count on the ``d`` right backwards compability to be around forever, instead use ``te`` rights. 

.. _RFC 2086: http://tools.ietf.org/html/rfc2086

.. _RFC 4314: http://tools.ietf.org/html/rfc4314

.. _RFC 5257: http://tools.ietf.org/html/rfc5257

.. _RFC 5464: http://tools.ietf.org/html/rfc5464

