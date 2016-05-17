:tocdepth: 2

==================
Mailbox Namespaces
==================

Cyrus IMAP supports the personal, the other users and zero or more
shared namespaces.

With a history in news-groups, Cyrus IMAP versions prior to version
|imap_version_unixhierarchysep_default_on| default to using the
**netnews** namespace convention.

.. NOTE::

    Cyrus IMAP documentation is a work in progress. The completion of
    this particular part of the documentation is pending the resolution
    of :task:`47`.

Namespace Convention: **netnews**
=================================

By default, up to versions prior to Cyrus IMAP version
|imap_version_unixhierarchysep_default_on|, Cyrus IMAP uses the
*netnews* namespace convention -- a ``.`` (dot) character is used as the
hierarchy separator.

Further implications and limitations of this convention include:

*   Mailbox names are case-sensitive,
*   A mailbox name may not start with a ``.`` (dot) character,
*   A mailbox name may not contain two ``.`` (dot) characters in a row,
*   non-ASCII characters and shell meta-characters are not permitted in
    mailbox names.

While the aforementioned implications of the **netnews** namespace
convention apply under all circumstances, some of the implications
imposed by the **netnews** namespace convention can be influenced by
specifying additional configuration options to Cyrus IMAP, such as is
the case with the hierarchy seperator.

When using the **netnews** namespace convention, the default, a user's
shorthand qualifier (e.g. ``john`` for ``john@example.org``) MAY NOT
contain a ``.`` (dot) character, as the character is being used as a
hierarchy separator in mailbox names, and would thus create a personal
mailbox rather then a user's INBOX. Therefore, using ``john.doe`` for
the INBOX name for user *John Doe <john.doe@example.org>* does not work,
as it would create a sub-folder ``doe`` for the INBOX ``user.john``.

The same limitation goes for the use of virtual domains. Since a mailbox
in a virtual domain typically uses a fully qualified user identifier
(e.g. ``john@example.org``, thus including a valid (sub-)domain name),
the ``.`` (dot) character is inherited from the Domain Name System
naming convention. This poses a problem without the use of the ``.``
(dot) character as a mailbox hierarchy separator.

To illustrate the effects on an environment, please examine the
following procedure, starting from a clean Cyrus IMAP installation:

Example Effects of Using the Netnews Namespace Convention
---------------------------------------------------------

In :cyrusman:`imapd.conf(5)`, ensure the following settings are
configured:

*   ``unixhierarchysep``: ``0``, to ensure the use of the **netnews**
    namespace convention regardless of defaults, and

*   ``delete_mode``: ``immediate``, to allow us to clean up afterward,

*   ``virtdomains``: ``userid``, to allow both realmed and unrealmed
    mailbox names.

.. seealso::

    *   Check configuration settings with
        :ref:`imap-admin-systemcommands-cyr_info`

We'll attempt to create a mailbox for the user
*John Doe <john@example.org>* using the shorthand qualifier (e.g.
``john``), and the fully qualified user identifier (e.g.
``john@example.org``).

.. parsed-literal::

    $ :command:`cyradm -u cyrus localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost> :command:`lm`
    localhost> :command:`cm user/john`
    createmailbox: Invalid mailbox name
    localhost> :command:`cm user.john`
    localhost> :command:`lm`
    user.john (\HasNoChildren)
    localhost> :command:`lam user.john`
    john lrswipkxtecda

The mailbox ``user.john`` has been created succesfully using the
shorthand qualifier, and could not be created using the unix hierarchy
separator.

However, realmed mailboxes can also not be created:

.. parsed-literal::

    localhost> :command:`cm user.john@example.org`
    createmailbox: Permission denied

Let's try to avoid the possibility of any conflict occuring, and remove
``user.john`` first:

.. parsed-literal::

    localhost> :command:`sam user.john cyrus all`
    localhost> :command:`dm user.john`
    localhost> :command:`cm user.john@example.org`
    createmailbox: Permission denied

A mailbox name of ``user.john@example.org`` is still not considered
valid.

Namespace Convention: "not netnews"
===================================

An alternative hierarchy separator can be used to allow the use of ``.``
(dot) characters in mailbox names: the UNIX hierarchy separator.

The UNIX hierarchy separator is a ``/`` (forward slash) character, and
is configured by setting in :cyrusman:`imapd.conf(5)`:

*   ``unixhierarchysep: 1``

.. seealso::

    *   Check configuration settings with
        :ref:`imap-admin-systemcommands-cyr_info`

Restart the **cyrus-imapd** service and attempt to create a mailbox for
user ``john@example.org`` using the shorthand qualifier (e.g. ``john``),
and the fully qualified user identifier (e.g. ``john@example.org``).

.. parsed-literal::

    $ :command:`cyradm -u cyrus localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost> :command:`lm`
    localhost> :command:`cm user/john`
    localhost> :command:`lm`
    user/john (\HasNoChildren)
    localhost> :command:`cm user/john@example.org`
    localhost> :command:`lm`
    user/john (\HasNoChildren)
    user/john@example.org (\HasNoChildren)
    localhost> :command:`lam user/john`
    john lrswipkxtecda
    localhost> :command:`lam user/john@example.org`
    john@example.org lrswipkxtecda
    localhost> :command:`sam user/john cyrus all`
    localhost> :command:`sam user/john@example.org cyrus all`
    localhost> :command:`dm user/john`
    localhost> :command:`dm user/john@example.org`
    localhost> :command:`lm`
    localhost>

As you can see, the mailbox has been created succesfully using the
shorthand qualifier, and has been created using the fully qualified user
identifier as well.

Alternate Namespace
===================

In a default situation, with Cyrus IMAP versions prior to version
|imap_version_unixhierarchysep_default_on| using the *netnews* namespace
convention, a user *John Doe <john@example.org>* would start out with a
mailbox ``INBOX``, and will quickly want to create sub-folders such as
for drafted and sent messages.

These mailboxes will be presented to John's client as follows:

*   ``INBOX``
*   ``INBOX.Drafts``
*   ``INBOX.Sent Items``

With the UNIX hierarchy separator enabled, the list would look as
follows:

*   ``INBOX``
*   ``INBOX/Drafts``
*   ``INBOX/Sent Items``

Cyrus IMAP allows the configuration of an alternative namespace, where
the ``INBOX`` folder holds no sub-folders. Compared to the previous two
lists this would look as follows (independent from the use of the UNIX
hierarchy separator):

*   ``INBOX``
*   ``Drafts``
*   ``Sent Items``

To configure the use of the alternative namespace, use the
``altnamespace`` setting in :cyrusman:`imapd.conf(5)` and set it to
``1``.

.. NOTE::

    Changing ``altnamespace`` in a currently operating environment will
    cause all IMAP clients to need to resync the entire hierarchy.

Internal Namespace
==================

The internal namespace refers to how Cyrus IMAP maintains lists of
mailboxes. It is literaly internal to Cyrus IMAP, and should be
considered in contrast to :ref:`imap-features-namespaces-administrator`.

Personal Namespace
------------------

A mailbox in the :ref:`imap-features-namespaces-personal` is a mailbox
that belongs to a user account. As such, in the internal namespace,
these mailboxes start with the literal string ``user.``.

For a realmed mailbox such as ``user/john@example.org`` however --
remember we have needed to configure ``virtdomains`` to any value other
than ``off``, and ``unixhierarchysep`` to ``1`` --, is stored internally
as ``example.org!user.john``.

Since dot characters are allowed in the mailbox names, one may have a
naming convention that leads user *John Doe* to hold an email address of
``john.doe@example.org``. The internal representation of this mailbox is
``example.org!user.john^doe``.

.. NOTE::

    A second user mailbox, if shared with *John*, would present itself
    to *John* as being in the
    :ref:`imap-features-namespaces-other-users`, however the internal
    accounting for it remains the same.

.. _imap-features-namespaces-administrator:

Administrator Namespaces
========================

An administrator -- a user for which the username is included in the
``admins`` setting in :cyrusman:`imapd.conf(5)` -- has a different
perspective when using the IMAP protocol to perform administrative
tasks.

An administrator user ``cyrus`` for example, may see the following
mailboxes:

*   ``user.jane``
*   ``user.jane.Drafts``
*   ``user.jane.Sent Items``
*   ``user.john``
*   ``user.john.Drafts``
*   ``user.john.Sent Items``

This would be the case with the *netnews* namespace convention (i.e.
``unixhierarchysep: 0``), and regardless of the ``altnamespace``
setting.

With the UNIX hierarchy separator enabled, the list would look as
follows:

*   ``user/jane``
*   ``user/jane/Drafts``
*   ``user/jane/Sent Items``
*   ``user/john``
*   ``user/john/Drafts``
*   ``user/john/Sent Items``

Continuing with the UNIX hierarchy separator enabled, should virtual
domains be in use, the list may appear to the administrator user
``cyrus`` as follows:

*   ``user/jane@example.org``
*   ``user/jane/Drafts@example.org``
*   ``user/jane/Sent Items@example.org``
*   ``user/john@example.org``
*   ``user/john/Drafts@example.org``
*   ``user/john/Sent Items@example.org``

But the ``admins`` setting in :cyrusman:`imapd.conf(5)` allows for a
username of ``admin@example.org`` to be specified as an administrator as
well. Should ``admin@example.org`` take a peek, then the following list
would appear:

*   ``user/jane``
*   ``user/jane/Drafts``
*   ``user/jane/Sent Items``
*   ``user/john``
*   ``user/john/Drafts``
*   ``user/john/Sent Items``

.. IMPORTANT::

    In multi-domain or multi-tenant environments, the following
    mailboxes may exist:

    *   ``user/john``
    *   ``user/john@example.com``
    *   ``user/john@example.org``

    Let it be understood that an unrealmed ``cyrus`` administrator user
    can administrator mailboxes in each of the three realms (null for
    ``user/john``, ``example.com`` for ``user/john@example.com`` and
    ``example.org`` for ``user/john@example.org``), but a realmed
    administrator ``admin@example.org`` will only be able to administer
    mailboxes within the ``example.org`` authorization realm, and will
    only see mailboxes within that realm ``example.org``, in this case
    being presented as ``user/john`` -- not to be confused with the
    actually unrealmed ``user/john`` mailbox that exists on the system
    as well.

.. _imap-features-namespaces-personal:

Personal Namespace
==================

The personal namespace refers to the hierarchy of mailboxes that a
Cyrus IMAP user owns, such as user *John Doe <john.doe@example.org>*
being the owner of the ``user/john.doe@example.org`` hierarchy.

John will typically view his personal namespace such that sub-folders of
his INBOX may not have a distinguished prefix -- other than perhaps
``INBOX`` if ``altnamespace`` is disabled:

.. parsed-literal::

    INBOX
    Drafts
    Sent Items
    Spam
    Trash

With *John* and *Jane* in the same environment, in case mailboxes from
each user's personal namespace are shared with the other user, the
:ref:`imap-features-namespaces-other-users` namespace kicks in when
these mailboxes are viewed.

For *John Doe <john.doe@example.org>*, with
*Jane Doe <jane.doe@example.org>* sharing a selection of the mailboxes
in **her personal namespace**:

.. parsed-literal::

    INBOX
    Drafts
    Sent Items
    Spam
    Trash
    Other Users/jane.doe
    Other Users/jane.doe/Subfolder

Note that the prefix used here is "Other Users" to indicate the mailbox
in question is in fact a part of another user's personal namespace.

.. _imap-features-namespaces-other-users:

Other Users Namespace
=====================

The Other Users namespace is a namespace that is reserved for mailboxes
in other user's personal namespaces, that have been shared with the
current user.

The other users namespace can be suppressed in LIST commands by setting
``disable_user_namespace`` to ``1`` in :cyrusman:`imapd.conf(5)`. This
can be advantageous to larger environments because of the nature of the
:ref:`imap-features-access-control-lists-discretionary` Cyrus IMAP
entertains by default.

.. _imap-features-namespaces-shared:

Shared Namespaces
=================

Shared namespaces contain -- as the name already suggests -- mailboxes
that are not owned by any one particular user, albeit one or more actual
users may have administrative rights on the folders.

Multiple shared namespaces can be created, aside from those named
``user`` -- as this hierarchy is reserved for the
:ref:`imap-features-namespaces-personal` of each user.

Examples of shared folders could include:

.. rubric:: Shared mail folders for mailing list traffic

*   ``lists/cyrus.foundation/announce@example.org``
*   ``lists/cyrus.foundation/devel@example.org``

.. rubric:: Shared mail folders for common email addresses

*   ``shared/contact@example.org``
*   ``shared/hostmaster@example.org``
*   ``shared/info@example.org``
*   ``shared/postmaster@example.org``
*   ``shared/root@example.org``
*   ``shared/webmaster@example.org``

The shared namespace can be suppressed in LIST commands by setting
``disable_shared_namespace`` to ``1`` in :cyrusman:`imapd.conf(5)`. This
can be advantageous to larger environments that want to avoid all LIST
operations to result in very large, long lists of folders.

Back to :ref:`imap-features`
