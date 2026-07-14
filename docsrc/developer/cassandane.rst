.. _developer-cassandane:

The Cassandane test suite
=========================

.. contents::

.. sectnum::

Introduction
------------

Cyrus IMAP includes two test suites.  One is written in C, using CUnit, and is
primarily *unit testing*.  The other, known as Cassandane, is written in Perl,
using Test::Unit, and is primarily *integration testing*.  This page covers the
Cassandane test suite.

Tests are grouped into *suites*, and each suite is a Perl module: those under
``Cassandane/Cyrus/`` exercise Cyrus, and those under ``Cassandane/Test/``
exercise Cassandane itself.  Most Cyrus tests are written as *tiny-tests* — one
subroutine per file under ``cassandane/tiny-tests/{Suite}/``, sharing the
suite module's setup.

If you just want to get productive fast, the :ref:`developer quickstart
<developer-quickstart>` takes you from a fresh checkout to a first passing test
and the conventions to write it with the grain.  This page is the fuller
story: how a test is put together and what the framework gives you to work
with.

Running the tests
-----------------

Almost all the time you run Cassandane through ``dar test`` (from the host) or
``cyd test`` (inside the container), which builds Cyrus, writes a
``cassandane.ini``, and runs the suite as the ``cyrus`` user for you.  See the
:ref:`developer quickstart <developer-quickstart>` for that workflow.

Whether you go through ``dar test`` or the runner directly, you choose what to
run by naming suites and individual tests:

.. code::

    dar test Quota               # the whole Quota suite
    dar test Quota.quotarename   # a single test
    dar test Admin Quota         # several suites
    dar test ~Quota              # everything except the Quota suite

Names accumulate from left to right, and any name can be negated with ``!`` or
``~`` (``~`` is usually easier to slip past the shell).  ``dar test`` also
exposes the options most people reach for — ``--slow``, ``--rerun``,
``--valgrind``, ``-j``, and so on; run ``dar test --help`` to see them.

Underneath, the actual runner is ``cassandane/testrunner.pl``, run as the
``cyrus`` user from inside the ``cassandane`` directory.  You need it directly
only when you want something ``dar test`` doesn't expose, or when debugging the
runner itself.  It documents itself:

.. code::

    ./testrunner.pl --help       # the full, authoritative option list
    perldoc ./testrunner.pl      # what it is, and notes on driving it

When a single test misbehaves, ``./testrunner.pl -f pretty -vvv Suite.test``
prints each failure's error report inline and turns up the Cassandane and Cyrus
logging; ``perldoc ./testrunner.pl`` explains where the logs land.

Writing a test
--------------

A test is a subroutine whose name begins with ``test_``.  Most live as
*tiny-tests*: one such subroutine to a file under
``cassandane/tiny-tests/{Suite}/``, the file beginning with ``#!perl`` and
``use Cassandane::Tiny;``.  Drop the file into the suite's directory and the
suite module in ``Cassandane/Cyrus/`` picks it up automatically; run it with
``dar test Suite.name``.

The example that follows shows only the subroutine — the ``use
Cassandane::Tiny;`` wrapper is understood.  The best way to see how the pieces
fit together is to read a real one, lightly polished:

.. code-block:: perl
   :linenos:

    sub test_card_query_inaddressbook
        :needs_dependency_icalvcard
        ($self)
    {
        my $user = $self->default_user;
        my $jmap = $user->jmap;

        xlog $self, "create cards in default address book";
        my $c1 = $user->contacts->create;
        my $c2 = $user->contacts->create;

        xlog $self, "create cards in second addressbook";
        my $abook2 = $user->addressbooks->create;
        my $c3 = $abook2->create_card;
        my $c4 = $abook2->create_card;

        xlog $self, "query by addressBookId";
        my $res = $jmap->request([
            ['ContactCard/query', { filter => { inAddressBook => $abook2->id } } ],
        ]);

        $self->assert_cmp_deeply(
            bag($c3->id . "", $c4->id .""),
            $res->single_sentence('ContactCard/query')->arguments->{ids},
        );

        xlog $self, "query by bogus addressBookId";
        $res = $jmap->request([
            ['ContactCard/query', { filter => { inAddressBook => 'foo' } } ]
        ]);

        $self->assert_deep_equals(
            {
                type => 'invalidArguments',
                arguments => [ 'filter/inAddressBook' ]
            },
            $res->single_sentence('error')->arguments,
        );
    }

This example shows off many of the most common things you'll be using when
writing Cassandane tests.

First, we see the ``needs_dependency_icalvcard`` attribute, telling the test
planner to skip this test when ``icalvcard`` is not compiled into Cyrus.  These
attributes go between the subroutine name and its signature; see `Test
attributes`_ below.

The ``xlog`` calls scattered through the test log a line to Cassandane's output
describing what's about to happen.  They're not required, but they make a
failing test far easier to follow, so use them liberally.

The test then sets ``$user`` to the default user.  Most tests only need one
user, and so can use the default user instead of creating one.  It calls
``$user->jmap`` to get a JMAP client for the user.  Although the client is a
Cassandane::JMAPTester, you'll find most of the relevant documentation in
`JMAP::Tester <https://metacpan.org/pod/JMAP::Tester>`__, its parent class.
That JMAP client has methods for performing JMAP upload and download, and even
performing arbitrary HTTP requests (with the ``http_request`` method), but most
of the time, you'll just use ``request``, which takes a hash or array reference
and turns it into a JMAP request.  Hash references can provide any JMAP request
properties needed.  Array references become the methodCalls property, with any
missing call ids automatically populated.

The result of a method call might be a `failure
<https://metacpan.org/pod/JMAP::Tester::Result::Failure>`__ object, indicating
a non-2xx response, but most of the time it will be a `response
<https://metacpan.org/pod/JMAP::Tester::Response>`__ object.  That object
represents any JMAP response, even if every method response is an error.  It
implements the `sentence collection
<https://metacpan.org/pod/JMAP::Tester::Role::SentenceCollection>`__ interface,
meaning it has (among others) these methods:

sentences
    This returns a list of Sentence objects, which represent the elements in
    the ``methodResponses`` property.  Each Invocation (per RFC 8620) becomes a
    Sentence.

sentence_named
    This takes a sentence name (like "Email/get") and returns the sentence from
    the response that has that name.  If there isn't exactly one sentence with
    that name, an exception is thrown.

single_sentence
    This method asserts that the response has exactly one sentence in it.  If a
    sentence name is passed as an argument to this method, it also asserts that
    the sentence has that name.  If both assertions are true, the sentence is
    returned.

Every sentence has methods for accessing the first, second, and third items in
the array it represents:  name, arguments, and client_id.

From lines 8 through 15, the test is creating test data.  To make it easy to
make test data (for example, to hide the creation of boring mandatory
properties), TestUser objects have factories for creating test data.  Here, we
see ``$user->contacts`` used to get the ContactCard factory, and then to create
two cards.  The calls to ``create`` aren't being passed any arguments because
this test doesn't care about any of the properties the objects might have.  If
it did, then those properties could be supplied in a hash reference passed to
the method.  Missing mandatory properties will still be filled in.

Line 13 creates an AddressBook using the address book factory and then lines 14
and 15 create new contact cards by using the ``create_card`` method on that
address book object.  Most test entity objects have methods for finding or
creating related data.  For a more comprehensive look at the methods available,
look at the files in ``cassandane/Cassandane/TestEntity/DataType``.  You can
view them in your editor, or using the ``perldoc`` program to format their
documentation.

With all the test data created, line 18 performs a JMAP request and gets back a
Response object.  Then, line 22 starts a deep comparison assertion against the
result.  We use a few of the JMAP::Tester methods described above:
``single_sentence`` to find the query result (and to assert that it was all we
got), and ``arguments`` to get at the arguments returned with the
ContactCard/query response.

The rest of the test is more of the same.

Assertions
^^^^^^^^^^

A test passes unless it dies or an assertion fails, so assertions are how you
state what "correct" means.  The ones you'll reach for most often come from
Test::Unit:

``assert($bool)``, ``assert_str_equals($expect, $got)``,
``assert_num_equals($expect, $got)``, ``assert_null`` / ``assert_not_null``,
and ``assert_matches($regex, $string)`` for scalars; and
``assert_deep_equals($expect, $got)`` for nested data structures.

Cassandane adds more in ``Cassandane::Unit::TestCase``.  The most generally
useful is ``assert_cmp_deeply``, which compares against `Test::Deep
<https://metacpan.org/pod/Test::Deep>`__ matchers — ``bag`` (order-insensitive
lists, as in the example above), ``superhashof`` (partial hashes), and so on —
when an exact ``assert_deep_equals`` would be too strict.  There are also
domain-specific assertions such as ``assert_mailbox_structure`` and
``assert_syslog_matches``.

Run ``perldoc Cassandane/Unit/TestCase.pm`` for the Cassandane assertions, and
see the Test::Unit and Test::Deep documentation for the rest.

Test attributes
---------------

A test subroutine can carry *attributes*, written between its name and its
signature, that tell the test planner how and whether to run it.  These apply
to suites inheriting from ``Cassandane::Cyrus::TestCase`` (which is almost all
of them); suites inheriting directly from ``Cassandane::Unit::TestCase`` ignore
them, but you shouldn't be inheriting from that unless you're testing
Cassandane itself.

The ones you'll meet first are the ``:needs_*`` family, which skip a test
unless Cyrus was built with some capability:

* ``:needs_component_NAME`` — a Cyrus component (e.g. ``httpd``) is enabled.
* ``:needs_dependency_NAME`` — a compiled-in library (e.g. ``icalvcard``) is
  present.

Next are the version guards, which skip a test outside a range of Cyrus
versions:

* ``:min_version_x_y_z``
* ``:max_version_x_y_z``

…where ``y`` and ``z`` are optional.  These used to be required on any test for
a new feature, and you'll still see them on a great many older tests, but they
now matter only when a newer Cassandane runs against an *older or external*
Cyrus — a replication test against a stable-branch server, say.  A test runs
against the Cyrus in its own branch by default, so a new feature usually needs
no guard at all.  When you do want one, a feature new in 3.0 is guarded with:

.. code:: perl

    sub test_my_new_feature
        :min_version_3_0
    {
         # [...]
    }

and a feature that survives only on a stable branch with:

.. code:: perl

    sub test_my_obsolete_feature
        :max_version_2_5
    {
        # [...]
    }

There is also a family of ``:want_*`` "magic" attributes that switch on
services or features (replication, and so on) before the test runs.  For the
full, current set of magic and ``:needs_*`` categories, read
``Cassandane/Cyrus/TestCase.pm`` — this is exactly the kind of list that rots
in prose, so the source is the reference.

If you need to branch on the Cyrus version *inside* a test (or inside
infrastructure) rather than skip the whole thing, ``Cassandane::Instance``
offers ``get_version()``, which can detect versions as far back as 2.5.0:

.. code:: perl

    my ($major, $minor, $revision, $extra) = Cassandane::Instance->get_version()

The skip handling itself lives in ``Cassandane::Test::Skip``.

The object model
----------------

You can write a great many tests knowing only ``default_user`` and its
factories, as above.  When you need more — a non-default configuration, several
users, or a protocol other than JMAP — these are the objects underneath.  This
is a conceptual map; for method-level detail, ``perldoc`` the modules named
here.

Cassandane::Instance
    A running Cyrus: its own directory tree, config, ``master`` process, and
    services such as ``imapd``.  A test's ``set_up`` normally builds one, starts
    it, and tears it down afterward, so most tests never touch it directly.
    An Instance also mints users — ``create_user('name')`` sets a user up on
    disk, ``create_user_without_setup('name')`` just makes the object — and
    ``default_user`` returns the standard user (usually ``cassandane``).  A
    service on the Instance can hand you a message store, and from that a
    protocol client (for imapd, a `Mail::IMAPTalk
    <https://metacpan.org/pod/Mail::IMAPTalk>`__).

Cassandane::TestUser
    A single Cyrus user, and your usual entry point.  It vends protocol
    clients — ``jmap`` and ``jmap_ws`` (cached) or ``new_jmap`` / ``new_jmap_ws``
    (fresh, and able to select capabilities), ``caldav`` and ``carddav``, and
    ``imap`` — and the test-data factories (``emails``, ``mailboxes``,
    ``contacts``, ``addressbooks``, …) used in the example above.

Cassandane::Config
    An ``imapd.conf`` in object form, used to start an Instance with particular
    options.  There's a shared default you should never mutate; instead clone it
    and ``set`` what you need:

    .. code:: perl

        my $config = Cassandane::Config->default()->clone();
        $config->set(conversations => 'on');
        my $instance = Cassandane::Instance->new(config => $config);

    Cloning is copy-on-write and ``get`` walks back up the ancestry, so a clone
    sees its parent's values until it overrides them.

Two more classes come up once you're generating or inspecting mail directly
rather than through the factories: ``Cassandane::Message`` (an RFC822 message
plus non-RFC822 attributes, as returned by a message store or the generator)
and ``Cassandane::Generator`` (which produces plausible random messages).  Both
are best read about at the source: ``perldoc Cassandane/Message.pm`` and
``perldoc Cassandane/Generator.pm``.

Module reference
----------------

Some Cassandane modules are documented in their source using Perl's Pod system.
The pages below are rendered from that Pod when the docs are built.  (You can
read the same text offline with ``perldoc``.)

.. include:: cassandane-api/summary.inc

.. The pages themselves are listed above; this hidden toctree is what actually
   puts them in the navigation tree.

.. toctree::
    :glob:
    :hidden:

    cassandane-api/*
