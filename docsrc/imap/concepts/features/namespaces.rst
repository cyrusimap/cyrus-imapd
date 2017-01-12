:tocdepth: 2

.. _mailbox-namespaces:

==================
Mailbox Namespaces
==================

.. TODO: Virtual domains info/new page
   don't share cross-domain in netnews mode with virtual domains. Bad Things happen.
   virtual domains don't display if you're sharing (other users/shared) within the same domain

Namespace Basics
==================

**What is a namespace?** A namespace is a hierarchical list of mailboxes a user has access to, named to maintain uniqueness and provide access control.

There are four different uses of the term "namespace" within Cyrus:

1. **IMAP NAMESPACE command**

    This is the set of mailboxes a user has access to and is the namespace as defined by :rfc:`2342` in response to the ``IMAP NAMESPACE`` command.

    A user can have access to three different kinds of mailboxes: their own (known as *personal*), other people's mailboxes that they have shared access to (known as *other users*) and any mailboxes that have more than one owner (known as *shared*).

    More info at :ref:`imap-admin-namespaces-user-access`.

2. **User namespace mode: altnamespace**

    Cyrus's user namespace mode controls how it responds to the ``IMAP NAMESPACE`` command and what the heirarchy of mailboxes looks like in response to an ``IMAP LIST`` command for a user. The config setting *altnamespace*: on or off in :cyrusman:`imapd.conf(5)` manages the mode. It is also affected by the hierarchy separator, which can be "/" (default: on) or "." (off) controlled by *unixhierarchysep* in :cyrusman:`imapd.conf(5)`.

    1. altnamespace: on (default)

        * personal: "" (empty string)
        * other users: "Other Users" (The string can be changed in :cyrusman:`imapd.conf(5)` with ``userprefix``)
        * shared: "Shared Folders" (The string can be changed in :cyrusman:`imapd.conf(5)` with ``sharedprefix``)

    2. altnamespace: off (was known as standard or regular)

        * personal: INBOX
        * other users: user
        * shared: "" (empty string)

    .. NOTE::

        altnamespace mode is valid only for the *user* namespace: it doesn't affect the :ref:`administrator's view <imap-admin-namespaces-administrator>`.

    Consider a user "uhura". Uhura can see all the folders from user "spock", some folders from users "kirk", as well as the shared folder "commandcrew".

    Under altnamespace:off mode with a ``.`` separator, she sees her folders as:

        * INBOX
        * INBOX.folder-1
        * INBOX.folder-2 (etc)
        * user.spock (this is INBOX for "spock")
        * user.spock.folder-x
        * user.kirk.folder-y ("kirk" hasn't shared their INBOX)
        * commandcrew

    Under altnamespace:on mode with a ``/`` separator, she sees her folders as:

        * INBOX (INBOX is special in IMAP and is always the users Inbox)
        * folder-1
        * folder-2 (etc)
        * Other Users/spock
        * Other Users/spock/folder-x
        * Other Users/kirk/folder-y
        * Shared Folders/commandcrew

    .. warning::

        When using a ``.`` separator (unixhierarchysep: off), user names and folder names
        internally swap the ``.`` with ``^``. This is because dots mark a subfolder if
        you're not using unixhierarchy separators. Some IMAP clients do not cope well with the ^ character, which is why
        unixhierarchysep: on is now the default as it allows dots in usernames and folder names.

    More info at :ref:`imap-admin-namespaces-mode`.

3. **Administrator namespace**

    While a user has their three kinds of mailboxes they have access to, an administrator can see all mailboxes (optionally restricted to the administrator's own domain). As a result, the response to ``LIST`` commands is different for administrators.

    In the administrator namespace, all user mailboxes are presented as ``user/<username>/<folder>`` (with unixhierarchysep: on) and with ``@<domain>`` appended in virtual domain mode. Shared folders appear at the top level. The user namespace mode (altnamespace on/off) does NOT affect administrator mode; only the hierarchy separator affects display.

    For unixhierarchy separators:

        * shared/commandcrew
        * user/uhura@example.com
        * user/uhura/folder-1@example.com
        * user/spock@example.com
        * user/spock/folder-x@example.com
        * user/kirk@example.com
        * user/mc.coy@example.com

    More info at :ref:`imap-admin-namespaces-administrator`.

4. **Internal namespace**

    Developer reference only. This is how each mailbox is uniquely stored inside ``mailboxes.db``. Each mailbox name has a unique representation that is the "key" in the mailboxes.db key-value database.

        * commandcrew (??)
        * example.com!user.uhura
        * example.com!user.uhura.folder-1
        * example.com!user.spock
        * example.com!user.spock.folder-x
        * example.com!user.kirk
        * example.com|user.mc^coy

    More info at :ref:`imap-developer-namespaces`.

----

.. _imap-admin-namespaces-user-access:

User Access Namespaces
======================

.. _imap-features-namespaces-personal:

Personal Namespace
------------------

The personal namespace refers to the hierarchy of mailboxes that a
Cyrus IMAP user owns, such as user *Nyota Uhura <nyota.uhura@example.com>*
being the owner of the ``user/nyota.uhura@example.com`` hierarchy.

Mailboxes in the personal namespace start with the literal string ``user``.

Uhura will typically view her personal namespace such that sub-folders of
her INBOX may not have a distinguished prefix -- other than perhaps
``INBOX`` if ``altnamespace`` is disabled:

.. parsed-literal::

    INBOX
    Drafts
    Sent Items
    Spam
    Trash

.. _imap-features-namespaces-other-users:

Other Users Namespace
---------------------

The Other Users namespace is a namespace that is reserved for mailboxes
in other user's personal namespaces, that have been shared with the
current user.

With *Spock* and *Kirk* in the same environment, who are also sharing
their personal mailboxes with *Uhura*, the
:ref:`imap-features-namespaces-other-users` namespace kicks in when
these mailboxes are viewed.

For *Nyota Uhura <nyota.uhura@example.org>*, with
*James Kirk <james.kirk@example.org>* sharing a selection of his mailboxes, Uhura's mailbox list looks like:

.. parsed-literal::

    INBOX
    Drafts
    Sent Items
    Spam
    Trash
    Other Users/james.kirk
    Other Users/james.kirk/Subfolder

Note that the prefix used here is "Other Users" to show the mailbox
in question is part of another user's personal namespace.

The other users namespace can be suppressed in LIST commands by setting
``disable_user_namespace`` to ``1`` in :cyrusman:`imapd.conf(5)`. This
is useful in larger environments because of the nature of the
:ref:`imap-features-access-control-lists-discretionary` Cyrus IMAP
entertains by default.

.. _imap-features-namespaces-shared:

Shared Namespaces
-----------------

Shared namespaces contain mailboxes
that are not owned by any one user, though one or more actual
users have administrative rights on the folders.

More than one shared namespaces can be created (aside from those named
``user`` as this hierarchy is reserved for the
:ref:`imap-features-namespaces-personal` of each user).

Examples of shared folders could include:

.. rubric:: Shared mail folders for mailing list traffic

*   ``lists/cyrus.imap/announce@example.org``
*   ``lists/cyrus.imap/devel@example.org``

.. rubric:: Shared mail folders for common email addresses

*   ``shared/contact@example.org``
*   ``shared/hostmaster@example.org``
*   ``shared/info@example.org``
*   ``shared/postmaster@example.org``
*   ``shared/root@example.org``
*   ``shared/webmaster@example.org``

The shared namespace can be suppressed in LIST commands by setting
``disable_shared_namespace`` to ``1`` in :cyrusman:`imapd.conf(5)`. This
is useful in larger environments that want to avoid all LIST
operations which can result in large, long lists of folders.

.. _imap-admin-namespaces-mode:

User Namespace Mode
===================

altnamespace: on or off
-----------------------

.. note::
    If you are upgrading an existing server which uses :cyrusman:`timsieved(8)` to manage Sieve scripts and choose to swap namespace modes, you should run the script :cyrusman:`translatesieve(8)` after configuring the namespace option(s). This script will translate the folder names in fileinto actions.

By default  Cyrus IMAP uses *altnamespace: on* , and unixhierarchysep: on "/" (slash) character for the
hierarchy separator.

The following limits also apply:

*   Mailbox names are case-sensitive,
*   A mailbox name may not start with a ``.`` (dot) character,
*   A mailbox name may not contain two ``.`` (dot) characters in a row,
*   Non-ASCII characters and shell meta-characters are not permitted in
    mailbox names.

While these limits apply under all circumstances, use of the unix hierarchy separator can also affect the display.

When using the altnamespace:off namespace mode, a user's
shorthand qualifier (e.g. ``john`` for ``john@example.org``) MAY NOT
contain a ``.`` (dot) character, as the character is being used as a
hierarchy separator in mailbox names, and would thus create a personal
mailbox rather then a user's INBOX. Using ``john.doe`` for
the INBOX name for user *John Doe <john.doe@example.org>* does not work,
as it would create a sub-folder ``doe`` for the INBOX ``user.john``.

The same limitation goes for the use of virtual domains. Since a mailbox
in a virtual domain typically uses a fully qualified user identifier
(e.g. ``john@example.org``, thus including a valid (sub-)domain name),
the ``.`` (dot) character is inherited from the Domain Name System
naming convention. This poses a problem without the use of the ``.``
(dot) character as a mailbox hierarchy separator.


Example
-------

In a default situation using the altnamespace:on namespace
mode, a user *John Doe <john@example.org>* would start out with a
mailbox ``INBOX``, and will want to create sub-folders such as
for drafted and sent messages.

These mailboxes will be presented to John's client as follows (assuming dot separator):

*   ``INBOX``
*   ``Drafts``
*   ``Sent Items``

Where altnamespace is set to off, this looks like:

*   ``INBOX``
*   ``INBOX.Drafts``
*   ``INBOX.Sent Items``

.. warning::

    Changing ``altnamespace`` in an active operating environment will
    cause all IMAP clients to need to resync the entire hierarchy.

----

.. _imap-admin-namespaces-administrator:

Administrator Namespaces
========================

An administrator -- a user for which the username is included in the
``admins`` setting in :cyrusman:`imapd.conf(5)` -- has a different
perspective when using the IMAP protocol to perform administrative
tasks.

.. NOTE::
    The administrator namespace is not affected by the user namespace mode (altnamespace: on/off)

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

    Be aware that an unrealmed ``cyrus`` administrator user
    can administrator mailboxes in each of the three realms (null for
    ``user/john``, ``example.com`` for ``user/john@example.com`` and
    ``example.org`` for ``user/john@example.org``), but a realmed
    administrator ``admin@example.org`` will be able to see and administer
    mailboxes restricted to the ``example.org`` authorization realm.
    In this case they will see ``john@example.com``
    being presented as ``user/john`` -- not to be confused with the
    actually unrealmed ``user/john`` mailbox that exists on the system
    as well.
