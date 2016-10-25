:orphan:

========
Glossary
========

.. glossary::
    :sorted:

    HBA
    Host Bus Adapter

       A Host Bus Adapter is a device to connect a computer to a storage device.

       .. seealso::

        * `Host adapter <https://en.wikipedia.org/wiki/Host_adapter>`_

    backend

       The part of a Cyrus configuration which contains the data.

       .. seealso::

        * :term:`frontend`

    frontend

       The part of a Cyrus configuration which contains the components which talk to clients.

       .. seealso::

        * :term:`frontend`

    authorization realm

        The authorization realm is the target user authorization ID's namespace.

        When, for example, a user *John Doe* logs in with username ``doe`` (the
        "authentication ID"), the original authorization realm (as specified in
        the original username) is ``null``.

        After user login name :term:`canonification` -- a process to translate
        an authentication ID in to an authorization ID -- the resulting
        authorization ID may have become ``john.doe@example.org``.

        The canonification process is important, because it will also be the
        authorization ID that is used to compose the mailbox path to the user's
        INBOX.

        Continuing our example user, the authorization ID having become
        ``john.doe@example.org`` will result in the session using
        ``user/john.doe@example.org`` as the INBOX.

        The **authorization realm** at this point is one of ``example.org``. The
        user will not be able to access any mailboxes outside this authorization
        realm, meaning the user will be unable to access any mailboxes for which
        the mailbox path does not end in ``@example.org``.

    canonification

        Canonification is the process of translating a login username in
        to the targeted value to use throughout the rest of the
        infrastructure.

        Suppose, for example, a user ``John Doe <doe@example.org>`` has an
        email address of ``doe@example.org``, and a user
        ID of ``doe``. Suppose therefore his mailbox is
        ``user/doe@example.org``, and his authorization ID is
        ``doe@example.org``.

        When John logs in however, he may also use one of his secondary
        recipient addresses, such as ``john.doe@example.org`` or
        ``jdoe@example.org``.

        This login username needs to be translated to
        ``doe@example.org`` in order to obtain the correct INBOX, and
        allow applications to consistently retrieve profiles with user
        preferences.

    disk volume
    disk volumes

        A disk volume is an entity that "can contain a filesystem". This
        may be a complete disk, a set of disks, a disk partition, a
        logical volume, a copy-on-write snapshot, a disk image (file),
        a fiber-channel or iSCSI LUN, or any other such volume.


    domain name space
    domain name spaces

        A domain name space is, among other things, the qualification of a
        recipient's local-part. It is the domain name appended to the local part
        of an email address, the two of them divided by an '@' character (sender
        specified routing notwithstanding).

        Without domain name spaces, user 'john' would only ever know about user
        'jane' if -- pardon my French to those in the know -- if both 'john' and
        'jane' considered eachother local. In other words, if both 'john' and
        'jane' used the same physical *system environment*. As you may be aware,
        the Internet is composed of a quite a few thousands of such system
        environments.

        What *qualifies* users 'john' and 'jane' to all other users on the
        Internet is a *name space*. The name space must be globally unique
        (literally "globally" -- but technically speaking more like
        "universally unique").

        The only name spaces available to Internet registrars and therefore
        service providers and therefore users, are called *domains* -- they are
        composed of a *top-level domain (name space)* such as .org and .com, and
        a name that a service provider would allow you to register with the
        Internet registrar (a NIC) - each domain is therefore at least one but
        possible more *domain name spaces*.

        To further illustrate, you require an Internet registrar to obtain your
        own *domain name* -- unless you are an Internet registrar yourself, of
        course, though you still need one, but it just so happens you are one.

        Once you have registered a domain name (and, contrary to popular belief,
        you don't actually own it, ever) nothing prevents you from creating
        additional domain name spaces within the name space of that domain.

        You could, for example, register ``example.org``, and create a domain
        name space of ``customer1.example.org`` and/or ``family2.example.org``.

        In fact, every :term:`fully qualified domain name` is a domain name
        space in and of its own -- but it identifies on the individual system
        level as opposed to the environment level.


    FQDN
    fully qualified domain name

        A Fully Qualified Domain Name is intended to refer to a single node (or
        "operating system instance", if you will) whether it be traditionally
        physical or virtual, in a manner that is globally ("universally")
        unique.

        As such, it SHOULD be composed of at least three (3) name space segments
        divided by a dot (.) character -- exluding the implicit top-level dot
        (.), even if a domain (system environment) is comprised of a single
        system.

    mandatory access control

        `Mandatory access control`_ is a type of access control where
        a set of (static) rules controlled (centrally) by a security
        policy administrator describe the level of access subjects to
        objects. As such, no subject controls the level of access of
        other subjects.

    MTBF

        Mean time between Failure -- a statistical determination of the
        time between failures.

    msa
    Mail Submission Agent

        The Mail Submission Agent (*MSA*) (...)

    mta
    Mail Transfer Agent

        The Mail Transfer Agent (*MTA*) (...)

    mua
    Mail User Agent

        The Mail User Agent (*MUA*) (...)

    mydestination

        ``mydestination`` is a setting in Postfix, commonly used to
        refer to a list of :term:`domain name spaces` that the local
        :term:`MTA` is considered the final destination for.

    operating system disks

        Storage used for the operating system installation.

        .. seealso::

            *   :term:`payload disks`

    partition
    partitions

        A partition in Cyrus IMAP (...)

    payload disks

        Storage used for information.

    storage volume level replication

        Please see the generic section on
        :ref:`imap-deployment-storage-redundancy`.


.. _Discretionary access control: http://en.wikipedia.org/wiki/Discretionary_access_control
.. _Mandatory access control: http://en.wikipedia.org/wiki/Mandatory_access_control
