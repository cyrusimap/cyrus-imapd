:tocdepth: 1

.. _imap-admin-access-control-lists-rights-reference:

=====================================
Access Control Lists Rights Reference
=====================================

Access rights in Cyrus IMAP are fully compatible with :rfc:`4314`,
*IMAP4 Access Control List (ACL) Extension*, which has obsoleted
:rfc:`2086`.

Additional documentation on Access Control is available in the following
documents:

*   :ref:`imap-admin-access-control-combining-rights`
*   :ref:`imap-admin-access-control-defaults`

Individual Rights Reference
===========================

.. _imap-admin-access-control-right-l:

``l``
-----

    Stands for **lookup**.

    The ACI subject can lookup this folder, and see that the folder
    exists, meaning the folder will appear in the response to a
    ``LIST "" "*"`` command issued by a client.

    Folders to which the ACI subject has no lookup rights may still be
    subscribed to. The lookup right is only required if Cyrus IMAP has
    been configured with the ``allowallsubscribe`` setting to ``0``.

    This setting defaults to ``0``. In a Cyrus IMAP Murder, this setting
    is typically set to ``1``.

    The :ref:`imap-admin-access-control-right-l` right can be assigned
    to a folder, without the :ref:`imap-admin-access-control-right-l`
    right having been given out for the parent folder. Cyrus IMAP will
    pretend the parent folder does not exist;

    :rfc:`4314`, states the following example in section 4:

    .. epigraph::

        Note that if the user has
        :ref:`imap-admin-access-control-right-l` right to a mailbox
        ``A/B``, but not to its parent mailbox ``A``, the ``LIST``
        command should behave as if the mailbox ``A`` doesn't exist, for
        example:

        .. parsed-literal::

            C: A777 LIST "" *
            S: * LIST (\\NoInferiors) "/" "A/B"
            S: * LIST () "/" "C"
            S: * LIST (\\NoInferiors) "/" "C/D"
            S: A777 OK LIST completed

.. _imap-admin-access-control-right-r:

``r``
-----

    Stands for **read**.

    The ACI subject can read the contents of this folder, meaning that
    the ACI subject is allowed to ``SELECT`` or ``EXAMINE`` the folder,
    query its ``STATUS``, ``FETCH`` data, ``SEARCH`` the contents, and
    ``COPY`` contents from the folder.

    The :ref:`imap-admin-access-control-right-r` right also allows the
    user to ``GETMETADATA`` when used in conjunction with the
    :ref:`imap-admin-access-control-right-l` right, as defined in
    :rfc:`5464`.

.. _imap-admin-access-control-right-s:

``s``
-----

    Stands for **seen**.

    The ACI subject is permitted to maintain the ACI subject's seen
    state for this folder, or the shared seen state in case the
    ``/vendor/cmu/cyrus-imapd/sharedseen`` has been set to ``1`` (see
    :ref:`imap-reference-manpages-systemcommands-cyradm`).

    Additionally, the ``\Recent`` flags are preserved for the ACI
    subject.

.. _imap-admin-access-control-right-w:

``w``
-----

    Stands for **write**.

    The ACI subject is permitted to write to the folder, actually
    meaning the ACI subject is permitted to maintain flags and keywords
    other then ``\Seen`` and ``\Deleted``, which are controlled using
    the :ref:`imap-admin-access-control-right-s` and
    :ref:`imap-admin-access-control-right-t` rights respectively.

    The :ref:`imap-admin-access-control-right-w` right also allows the
    user to ``SETMETADATA`` when used in conjunction with the
    :ref:`imap-admin-access-control-right-l` and
    :ref:`imap-admin-access-control-right-r` rights, as defined in
    :rfc:`5464`.

    .. NOTE::

        IMAP clients may expect to be able to set flags other than
        ``\Seen`` and ``\Deleted`` and attempt to set those flags
        immediately along with a "Mark as read" action, but without the
        ACI subject actually being permitted to set some of those flags
        through the :ref:`imap-admin-access-control-right-w` right.

        :rfc:`4314`, section 4., page 15, states that the server SHOULD
        NOT fail, as the tagged NO response is not handled very well by
        deployed clients.

        In order to comply, we have `Bug #1375 <https://github.com/cyrusimap/cyrus-imapd/issues/1375>`__, as
        Cyrus IMAP currently does seem to issue a tagged ``NO``
        response.

.. _imap-admin-access-control-right-i:

``i``
-----

    Stands for **insert**.

    The ACI subject is permitted to insert content into a folder,
    meaning the ACI subject may ``COPY`` messages with this folder as
    the target folder, and may ``APPEND`` messages to this folder.

.. _imap-admin-access-control-right-p:

``p``
-----

    Stands for **post**.

    The post right currently is exclusive to Cyrus IMAP, and allows the
    ACI subject to send email to the submission address for the mailbox.

    This right differs from the :ref:`imap-admin-access-control-right-i`
    right in that the delivery system inserts trace information into
    submitted messages.

    Example implementations using the
    :ref:`imap-admin-access-control-right-p` right include shared
    folders to which specific recipient addresses are delivered through
    LMTP pre-authorized as the ``postuser``, which must then also have
    the :ref:`imap-admin-access-control-right-p` right on the target
    folder.

.. _imap-admin-access-control-right-c:

``c``
-----

    Stands for **create**.

    The create right is a right introduced with :rfc:`2086`, indicating
    the ACI subject's right to create new sub-folders in the parent
    folder on which this right has been assigned, but also to delete the
    same folder.

    Since :rfc:`4314`, the :ref:`imap-admin-access-control-right-c`
    right has been replaced with the
    :ref:`imap-admin-access-control-right-k` right to allow the ACI
    subject to ``CREATE`` folders, and the
    :ref:`imap-admin-access-control-right-x` right to allow the ACI
    subject to ``DELETE`` folders.

    .. IMPORTANT::

        The :ref:`imap-admin-access-control-right-c` right should no
        longer be used. It will be deprecated completely in version
        |imap_version_rfc2086_dropped|.

        While Cyrus IMAP is backwards compatible when it comes to the
        :ref:`imap-admin-access-control-right-c` right, which it
        implements as implying as the
        :ref:`imap-admin-access-control-right-k` right, implementations
        should not count on the :ref:`imap-admin-access-control-right-c`
        right backwards compatibility to be around forever, and fully
        implement the successor rights
        :ref:`imap-admin-access-control-right-k` and
        :ref:`imap-admin-access-control-right-x`.

.. _imap-admin-access-control-right-k:

``k``
-----

    The ACI subject has the right to ``CREATE`` a new folder if the
    :ref:`imap-admin-access-control-right-k` right exists on the parent
    folder of the folder to be created.

    The rights required for a ``RENAME`` to be successful could be
    illustrated by describing a ``RENAME`` as a ``CREATE`` of the new
    folder, not exactly followed by a ``COPY`` on the old folder's
    contents, but more like a move like on a filesystem, and finally a
    ``DELETE`` on the old folder.

    As such, the :ref:`imap-admin-access-control-right-k` is the right
    required on the parent folder of the target folder, and the
    :ref:`imap-admin-access-control-right-x` right on the source folder.

    To further illustrate, suppose the ACI subject has the
    :ref:`imap-admin-access-control-right-k` right on folder
    ``C/``, and the :ref:`imap-admin-access-control-right-x` right on
    folder ``A/B``. The execution of the command ``RENAME A/B C/B``
    would succeed.

.. _imap-admin-access-control-right-a:

``a``
-----

    Stands for **administer**.

    The ACI subject is allowed to administer the folder, meaning the ACI
    subject is allowed to perform administrative operations on the
    folder.

    The :ref:`imap-admin-access-control-right-a` right is needed to
    successfully execute ``SETACL``, ``DELETEACL`` (short for
    ``SETACL ""``) and to execute ``GETACL`` or ``LISTRIGHTS``.

    .. NOTE::

        IMAP clients may issue a ``GETACL`` in order to obtain the ACI
        subject's rights on the folder, where they should be using
        ``MYRIGHTS``, as ``GETACL`` or ``LISTRIGHTS`` return the full
        Access Control List, including other ACI subject's identifiers.

        However unless the ACI subject has the
        :ref:`imap-admin-access-control-right-a` right on a folder,
        issuing a ``GETACL`` or ``LISTRIGHTS`` will cause Cyrus IMAP to
        send a tagged ``NO: Permission denied`` response if the ACI
        subject has the :ref:`imap-admin-access-control-right-l` right
        on the folder, and a ``NO: No Such Mailbox`` response otherwise,
        as per section 8 of :rfc:`2086` and section 6 of :rfc:`4314` --
        both conveniently called *Security Considerations* -- which
        state that the IMAP server must not inadvertently admit the
        mailbox exists.

.. _imap-admin-access-control-right-x:

``x``
-----

    Use the :ref:`imap-admin-access-control-right-x` right to indicate
    the ACI subject has the right to ``DELETE`` the folder on which the
    ACL is set, as opposed to the now obsolete
    :ref:`imap-admin-access-control-right-c` right or
    :ref:`imap-admin-access-control-right-d` right.

.. _imap-admin-access-control-right-t:

``t``
-----

    The ACI subject is allowed to delete messages from this folder,
    meaning that the ACI subject is allowed to flag messages as
    ``\Deleted``.

    In IMAP, messages are only actually deleted (i.e. in a way that
    makes them invisible to users of the folder) after the folder's
    contents have been expunged.

    For the corresponding ``EXPUNGE`` command however, the
    :ref:`imap-admin-access-control-right-e` right is required.

.. _imap-admin-access-control-right-n:

``n``
-----

    The ACI subject is allowed to annotate individual messages in this
    folder, in compliance with :rfc:`5257`.

    .. NOTE::

        The ACI subject must also have at least the
        :ref:`imap-admin-access-control-right-r` right, as otherwise the
        ACI subject won't know which messages are available to annotate.

        This is not explicitly mentioned in the :rfc:`5257`, but
        implied.

.. _imap-admin-access-control-right-e:

``e``
-----

    Stands for **expunge**.

    The ACI subject is allowed to expunge messages in this folder,
    meaning the ACI subject has the right to remove all messages that
    have been flagged as ``\Deleted`` from all visibility.

    In IMAP, expunging messages only applies to messages flagged as
    ``\Deleted``. For the ACI subject to be able to flag messages as
    ``\Deleted`` however, the :ref:`imap-admin-access-control-right-t`
    right is required.

    We say "remove from all visibility", because the implementation of
    expunging messages in Cyrus IMAP is subject to the ``expunge_mode``
    setting in :cyrusman:`imapd.conf(5)`, which when set to ``delayed``
    only causes the reference to the expunged messages to be deleted
    from the folder index database -- effectively removing the expunged
    message(s) from all visibility, while the individual message files
    remain in place on the Cyrus IMAP server filesystem.

    .. seealso::

        *   :ref:`imap-admin-sop-restoring-expunged-messages`

    .. NOTE::

        IMAP clients may expect to be able to ``EXPUNGE`` a folder
        regardless of the availability of the
        :ref:`imap-admin-access-control-right-e` right to the current
        user.

.. _imap-admin-access-control-right-d:

``d``
-----

    Stands for **delete**.

    This is the legacy :rfc:`2086` access control right for the
    ``DELETE`` command.

    In versions of Cyrus IMAP implementing only this right (prior to
    2.3.7), ACI subjects were allowed to flag messages as
    ``\Deleted``, and ``EXPUNGE`` and ``DELETE`` folders.

    The delete right has been split in to three separate rights,
    :ref:`imap-admin-access-control-right-t` (flag messages as
    ``\Deleted``), :ref:`imap-admin-access-control-right-e`
    (``EXPUNGE`` folder) and :ref:`imap-admin-access-control-right-x`
    (``DELETE`` folder).

    .. NOTE::

        The ``deleteright`` setting in :cyrusman:`imapd.conf(5)`
        controls the :rfc:`2086` right which controls whether or not the
        ACI subject may delete a folder. However, this setting (as the
        original specification for the delete right was considered
        ambiguous) is ignored, and if it is set to
        :ref:`imap-admin-access-control-right-c`, is automatically
        converted to the :ref:`imap-admin-access-control-right-x` right.

    .. IMPORTANT::

        Even though Cyrus IMAP is backwards compatible when it comes to
        the :ref:`imap-admin-access-control-right-d` right, which it
        implements as implying as the
        :ref:`imap-admin-access-control-right-e` and
        :ref:`imap-admin-access-control-right-t` rights, implementations
        should not count on the :ref:`imap-admin-access-control-right-d`
        right backwards compatibility to be around forever, and instead
        fully implement the successor rights
        :ref:`imap-admin-access-control-right-e`,
        :ref:`imap-admin-access-control-right-t` and
        :ref:`imap-admin-access-control-right-x` rights.
