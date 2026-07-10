.. _developer-cassandane:

The Cassandane test suite
=========================

.. contents::

1. Introduction
---------------

Cyrus IMAP includes two test suites.  One is written in C, using CUnit, and is
primarily *unit testing*.  The other, known as Cassandane, is written in Perl,
using Test::Unit, and is primarily *integration testing*.  This page covers the
Cassandane test suite.

2. Running The Tests
--------------------

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

3. Adding Your Own Tests
------------------------

The source code for tests are Perl modules located in two directories under the
Cassandane main directory.

``Cassandane/Test/``
    contains tests which exercise the Cassandane core classes,
    i.e. self-tests.

``Cassandane/Cyrus/``
    contains tests which exercise Cyrus.

Cassandane uses the Perl Test::Unit framework.  For more detailed information
consult the Test::Unit documentation.  Each Cassandane test module derives from
the Cassandane::Unit::TestCase class, and is logically a group of related
tests.  The module can define the following methods.

``new``
    Constructor, creates and returns a new TestCase.  For Cassandane
    tests, this will typically create Cassandane::Config and
    Cassandane::Instance objects (see later).

``set_up``
    Optional method which is called by the framework before every
    test is run.  It has no return value and should 'die' if anything
    goes wrong.  For Cassandane tests, this will typically start an
    Instance (see later).

``tear_down``
    Optional method which is called by the framework after every
    test is run.  It has no return value and should 'die' if anything
    goes wrong.  For Cassandane tests, this will typically stop an
    Instance (see later).

``test_foo``
    Defines a test named "foo".  It has no return value and should
    either call $self->assert(boolean) or 'die' if anything goes wrong.
    Multiple test_whatever methods can be defined in a module.

3.1 Helper Classes
^^^^^^^^^^^^^^^^^^

Cassandane contains a number of helper classes designed to make easier
the job of writing tests that access Cyrus.  This section provides a
brief overview.

Cassandane::Instance
    Encapsulates an instance of Cyrus, with its own directory
    structure, configuration files, master process, and one or more
    services such as imapd.

    To create a default Instance:

    .. code:: perl

        my $instance = Cassandane::Instance->new();

    To create an Instance with a non-default parameter in the
    configuration file:

    .. code:: perl

        my $config = Cassandane::Config->default()->clone();
        $config->set(conversations => 'on');
        my $instance = Cassandane::Instance->new(config => $config);

    By default the Instance has no services, but just runs the master
    daemon.  This is rarely a useful setup.  To add a service, in this case
    the imapd daemon:

    .. code:: perl

        $instance->add_service(name => 'imap');

    Starting the Instance creates the directory structure and
    configuration files, then starts the master process and waits for
    all the defined services to be running (as reported by netstat).

    .. code:: perl

        $instance->start();

    Stopping the instance kills all master process and all services
    as gracefully as possible, and waits for them to die.

    .. code:: perl

        $instance->stop();

    Interactions with services are handled via one of the classed
    derived from the abstract Cassandane::MessageStore class.  To create
    a store for a particular service in an Instance:

    .. code:: perl

        $store = $instance->get_service('imap')->create_store();

    For the imapd service in particular, Cassandane::IMAPMessageStore
    wraps a Mail::IMAPTalk object which can be retrieved thus:

    .. code:: perl

        my $imaptalk = $store->get_client();

    The Cassandane::Instance can also produce TestUser objects for handling the
    data of individual users.  There are two methods:

    .. code:: perl

       # This will perform initialization for the user, ensuring some basic
       # normal bookkeeping was done, and then return a TestUser object:
       my $testuser = $instance->create_user('username');

       # This will just create the TestUser object, without touching any data
       # on disk.  (Its protocol clients will work, and Cyrus will create
       # whatever records are needed as they're accessed.)
       my $testuser = $instance->create_user_without_setup('username');

    Also, the method ``default_user`` will return a default user for the
    running test, generally named ``cassandane``.

Cassandane::TestUser
    This class represents a Cyrus user, and provides methods for getting
    protocol clients and creating test data.

    You can get a TestUser by calling ``create_user`` or
    ``create_user_without_setup`` on the Cassandane::Instance object.

    The following methods are provided:

    ``jmap`` and ``jmap_ws``
        These methods provide cached JMAP clients (Cassandane::JMAPTester and
        Cassandane::JMAPTesterWS, respectively).  They have all of Cyrus's
        capabilities enabled by default.

    ``new_jmap`` and ``new_jmap_ws``
        These methods construct new JMAP clients (Cassandane::JMAPTester and
        Cassandane::JMAPTesterWS, respectively).  They have all of Cyrus's
        capabilities enabled by default, but you can pass an array of using
        strings to pick different capabilities.  Alternatively, you can pass a
        hashref of options, which will be passed along to the JMAP::Tester
        constructor.

    ``carddav`` and ``caldav``
        These methods return cached Net::CardDAVTalk and Net::CalDAVTalk
        objects, respectively, for interacting with the user's data over those
        protocols.

    ``imap``
        This method returns a new Mail::IMAPTalk object, for interacting with
        the user's data over IMAP.

    test data entity methods
        These methods return test data factories.  For more information run
        ``perldoc cassandane/Cassandane/TestEntity/DataType/{TYPE}.pm`` for the
        type you're interested in.  In general, they will have the methods
        ``get`` and ``create``, to retrieve or create new instances of that
        datatype.

        * addressbooks
        * contacts
        * emails
        * mailboxes

Cassandane::Config
    Encapsulates the configuration information present in an imapd.conf
    format configuration file.  Config objects are useful for passing
    to the Cassandane::Instance constructor to set up Cyrus instances
    with particular configuration options.

    The Config module keeps a global Config object.  This object should
    not be modified directly but should be cloned (see below).  To get
    the default object:

    .. code:: perl

        my $config = Cassandane::Config->default();

    Configs use a lightweight copy-on-write cloning mechanism.  The
    clone() method can be used to create a new Config object based on a
    parent Config object.  The child remembers it's parent.

    .. code:: perl

        my $child_config = $parent_config->clone();

    The set() and get() methods can be used to set and get key-value
    pairs from a Config object.  The set() method always works on the
    object itself, but get() will walk back up the ancestry chain until
    it finds a matching key.

    .. code:: perl

        $config->set(conversations => 'on');
        $config->set(foo => '1', bar => '2');

        my $foo = $config->get('foo');

    The typical use for a Config object is:

    .. code:: perl

        my $config = Cassandane::Config->default()->clone();
        $config->set(conversations => 'on');
        my $instance = Cassandane::Instance->new(config => $config);

Cassandane::Message
    Encapsulates an RFC822 message, plus a set of non-RFC822 attributes
    expressed as key-value pairs.   Message objects are returned from
    MessageStore->read_message() and Generator->generate().

    To create a new default Message object

    .. code:: perl

        my $msg = Cassandane::Message->new();

    To create a Message object read from a file handle

    .. code:: perl

        my $fh = ...
        my $msg = Cassandane::Message->new(fh => $fh);

    To get all the RFC822 headers of a given name, as a reference
    to an array of strings:

    .. code:: perl

        my $values = $msg->get_headers('Received');

    To get an RFC822 header and enforce that there is only a single
    header of that name, use

    .. code:: perl

        my $value = $msg->get_header('From');

    To set an RFC822 header, replacing any previous headers of
    the same name:

    .. code:: perl

        $msg->set_headers('From', 'Foo Bar <foo@bar.org>');

    To set multiple RFC822 headers with the same name, replacing
    any previous headers of that name:

    .. code:: perl

        my @values = ('baz', 'quux');
        $msg->set_headers('Received', @values);

    To add an RFC822 header:

    .. code:: perl

        $msg->add_header('Subject', 'Hello World');

    To set the RFC822 body (as one big string)

    .. code:: perl

        $msg->set_body('....one enormous string...');

    To get a non-RFC822 attribute (this may have be placed on the message
    as a side effect of it's creation e.g. during an IMAP FETCH command):

    .. code:: perl

        my $cid = $msg->get_attribute('cid');

Cassandane::Generator
    Creates new Message objects with a number of useful default values
    based on random words.  Has a constructor and a single function

    .. code:: perl

        my $gen = Cassandane::Generator->new();
        my $msg = $gen->generate();

    By default, messages will have values for the RFC822 body and the
    following headers:

    * Return-Path
    * Received
    * MIME-Version - 1.0
    * Content-Type - text/plain; charset="us-ascii"
    * Content-Transfer-Encoding - 7bit
    * Subject
    * From
    * Message-ID
    * Date
    * To
    * X-Cassandane-Unique - a string of hex digits, unique per generator call

    Some of these can be overridden by providing options to generate()

    .. code::

      my $msg = $gen->generate(subject => "Hello world");

    The following options can be used:

    date
        a DateTime object
    from
        a Cassandane::Address object
    subject
        a string
    to
        a Cassandane::Address object
    messageid
        a string

3.2 Targeting specific versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you're writing a new Cyrus feature, you can (and should) mark tests for that
feature as requiring the new version of Cyrus.  Because a newer version of
Cassandane is sometimes run against older versions of Cyrus, this lets the test
running skip tests that absolutely require a newer Cyrus.

There are two new magical subroutine attribute patterns:

* ``:min_version_x_y_z``
* ``:max_version_x_y_z``

…where in both cases y and z are optional.

These only apply to test suites inheriting from Cassandane::Cyrus::TestCase.
Test suites inheriting from Cassandane::Unit::TestCase will ignore these
attributes entirely -- but you probably shouldn't inherit from this anyway
(unless you're testing Cassandane itself).

So for example, you might test a feature that's new in master with
something like:

.. code:: perl

    sub test_my_new_feature
        :min_version_3_0
    {
         # [...]
    }

And you might continue to test some hypothetical feature that's been
discontinued on master but still exists in the stable branch with
something like:

.. code:: perl

    sub test_my_obsolete_feature
        :max_version_2_5
    {
        # [...]
    }

Cassandane::Instance offers ``get_version()``.  It's able to detect versions as
far back as 2.5.0.  So if you need to do some version-based conditionalisation
within a test function (or within infrastructure), you can use something like:

.. code:: perl

    my ($major, $minor, $revision, $extra) = Cassandane::Instance->get_version()

Cassandane::Test::Skip implements the skip handling.

4. An example test
------------------

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
writing Cassandane tests.  First, we see the ``needs_dependency_icalvcard``
attribute, telling the test planner to skip this test when ``icalvcard`` is not
compiled into Cyrus.

It then sets ``$user`` to the default user.  Most tests only need one user, and
so can use the default user instead of creating one.  The test calls
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
    the sentence has that name.  If both assertions are true, the sentence in
    returned.

Every sentence has methods for accessing the first, second, and third items in
the array it represents:  name, arguments, and client_id.

We'll see much of this used in this test, soon!

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

