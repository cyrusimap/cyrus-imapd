.. _imap-developer-cassandane:

The Cassandane test suite
=========================

Table of Contents
-----------------

-  `1. Introduction <#introduction>`__
-  `2. Running The Tests <#running-the-tests>`__

   -  `2.1. Consider using cyrus-docker <#consider-using-cyrus-docker>`__
   -  `2.2. Setting up the machine <#setting-up-the-machine>`__
   -  `2.3. Running tests <#running-tests>`__

-  `3. Adding your own tests <#adding-your-own-tests>`__

   -  `3.1. Helper classes <#helper-classes>`__
   -  `3.2. Targeting specific versions <#targeting-specific-versions>`__

1. Introduction
---------------

Cyrus IMAP includes two test suites.  One is written in C, using CUnit, and is
primarily *unit testing*.  The other, known as Cassandane, is written in Perl,
using Test::Unit, and is primarily *integration testing*.  This page covers the
Cassandane test suite.

2. Running The Tests
--------------------

This section takes you through the process of running Cyrus' unit tests.

2.1. Consider using cyrus-docker
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before you proceed with the instructions below, consider whether you could just
use cyrus-docker, cyd, and dar.  Those tools let you hack on Cyrus without
setting up your own development environment.  They're documented on `the
developer overview page <imap/developer>`.

2.2. Setting up the machine
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you're not going to use cyrus-docker, you need to set up Cassandane, Cyrus
and your system.  This slog is described here:

Cassandane is designed to be operated on a day-to-day basis as an
unprivileged user.  However, Cassandane needs root to make some small
one-time adjustments to be performed to your system before it will run
at all.  This section documents those steps.

#.  Before doing anything else, make sure you have all the pre-reqs
    listed in ``cassandane/doc/README.deps`` installed.  A good way to check
    is:

    ::

        $ cd ~/my/cassandane/workarea
        $ make -j4
        ...
        testrunner.pl syntax OK
        Cassandane/ThreadedGenerator.pm syntax OK
        Cassandane/MasterEvent.pm syntax OK
        Cassandane/PortManager.pm syntax OK
        Cassandane/IMAPMessageStore.pm syntax OK
        ...

#.  The passwd and group maps need valid entries for user "cyrus" and group
    "mail".  If you want to generate coverage reports eventually, you probably
    also want a group called "cyrus", and make that the "cyrus" user's primary
    group.  Use your system's adduser/addgroup or equivalent tools for this.

    On Debian, something like this:

    ::

        $ sudo adduser --system --group cyrus
        $ sudo adduser cyrus mail

    NOTE: User 'cyrus' must actually be in 'group' mail, or the annotator
    will fail to start.

#.  You need to be able to run a program as the "cyrus" user, preferably
    without entering your password all the time.  And you need processes
    that you start with sudo to inherit your core file settings.  One way of
    doing this is to add the following at the *end* of your /etc/sudoers file

    ::

        Defaults:username rlimit_core=default
        username ALL = (cyrus) NOPASSWD: ALL

    Obviously, replace 'username' with your username.

#.  You need to tell Cassandane how to find Cyrus, which means you need to
    decide where to put Cyrus.  You've got two main options:

      *  Fully installed Cyrus build in some prefix, specified by passing
         --prefix=/some/prefix to configure.  The default prefix is
         /usr/local, but that's a nuisance cause you have to install as root.
         If you do this, you'll need to always pass the correct --prefix
         argument to configure when building Cyrus for testing.

         ::

             $ cd ~/my/cyrus/workarea
             $ ./configure --prefix=/some/prefix \
                 [your other configure options]
             $ make && make install

      *  Partially installed Cyrus build in a temp directory.  If you do this,
         you'll need to always pass the correct DESTDIR when installing Cyrus
         for testing.

         ::

             $ cd ~/my/cyrus/workarea
             $ ./configure [your other configure options]
             $ make && make DESTDIR=/var/tmp/cyrus install

    Whichever you choose, for best results, install Cyrus to a directory
    on a tmpfs filesystem.  You'll probably end up making a small wrapper
    script with all your usual configure options anyway, so adding --prefix to
    that is low additional effort.

    Now copy the cassandane.ini.example from the source tree to a file called
    "cassandane.ini" in your home directory, and start configuring.

    ::

        $ cp /path/to/cyrus-imapd/cassandane/cassandane.ini.example ~/cassandane.ini
        $ vi ~/cassandane.ini
        [cyrus default]
        prefix = [the --prefix Cyrus is configured for]
        destdir = [the DESTDIR you passed to make install, if any]

    Also note that you can do other combinations too, the trick is to
    set up the 'cyrus default' section in the cassandane.ini such that

      * 'prefix' is the value of --prefix you used when you ran the Cyrus
        configure script.  Default is /usr/cyrus (which is not the default for
        the Cyrus configure script!)

      * 'destdir' is the value of DESTDIR when you did 'make install' in
        the Cyrus directory.  Default is empty.

#.  More cassandane.ini configuration.

    You need to tell Casssandane where to keep its run-time state.  For
    best performance, this should be a directory on a tmpfs filesystem.
    You set this in the cassandane.rootdir setting in cassandane.ini

    While you're in there anyway, there's some other things you really ought to
    set:

    * cassandane.cleanup: default is no, but "yes" is more sensible.  You can
      always override this as needed with the --no-cleanup option at run time
    * cassandane.maxworkers: default is "1", but this is excruciatingly slow.
      Anecdotally, two times the number of CPUs in your system seems about
      right, if your system is not otherwise heavily loaded.
    * config.zoneinfo_dir: set this to the path to the zoneinfo directory
      from the cyrus-timezones package.  If you got this from cyruslibs, it's
      probably /usr/local/cyruslibs/share/cyrus-timezones/zoneinfo

    But for the most part, read the comments from the example file, they are
    the authoritative documentation here.

#.  It's also a good idea to set some kernel tunables.

    When dumping core files, use the PID of the dumping process
    in the name, so that if multiple processes dump core during the
    test you'll see all the core files instead of just one named "core".

    ::

        # echo 1 >/proc/sys/kernel/core_uses_pid

    As a security feature, Linux won't generate cores for processes
    which have changed ownership.  This prevents any of the Cyrus
    processes in your test ever dumping core, so you want to turn
    that feature off.

    ::

        # echo 1 >/proc/sys/fs/suid_dumpable

    Finally, some Linux systems might require to unlimit the size of
    core dumps. As suid_dumpable, this shouldn't normally be set on
    production systems.

    ::

        # ulimit -c unlimited

Now, to run Cassandane use this command

    ::

        $ cd ~/my/cassandane/workarea
        $ ./testrunner.pl

NOTE: Cassandane will internally run 'sudo' to become user 'cyrus'

2.3. Running tests
^^^^^^^^^^^^^^^^^^

Cassandane tests are run out of the Cassandane directory itself, without
installing Cassandane anywhere.  This is not the result of deliberate policy so
much as implementation laziness.

All runtime state is created under the cassandane rootdir configured in
cassandane.ini (by default: ``/var/tmp/cass``).

Internally, Cassandane (or more precisely, the Cyrus code it exercises) needs
to be run either as the superuser or as the "cyrus" user.  But you should
generally invoke Cassandane as yourself, not as "cyrus" or "root".  It will
try to re-run itself using sudo, which you already configured during setup
(didn't you?)

The script 'testrunner.pl' is your interface for running Cassandane tests.
There are several other Perl scripts in the directory, but they are utilities
which were helpful during manual testing rather than part of the test suite
itself.

With no arguments, testrunner.pl runs all the tests that come with Cassandane
and reports the results to the terminal in the 'prettier' test report format.
The testrunner.pl exit code will be 0 if all tests passed, non-zero otherwise.

.. code::

    $ ./testrunner.pl
    [  OK  ] Cyrus::ACL.reconstruct
    [  OK  ] Cyrus::ACL.move
    [  OK  ] Cyrus::ACL.delete
    ...

There are several test report formats to choose from, by invoking testrunner.pl
with the -f 'format' option.

``-f pretty``
    Human readable output to the terminal, showing the ok/failed/error status
    and name for each test, as well as the error reports from any not-ok tests.
    This gets noisy in the case of failures!  It's mostly useful when debugging
    single tests, especially in conjunction with -vvv.

``-f prettier`` (the default)
    As for pretty, but without the noise when problems occur.  This is most
    useful when running many (or all) tests at once.  A list of failed tests
    is written to $rootdir/failed, and the full error reports for any failed
    tests are written to $rootdir/reports, so you can still access these details
    if you find yourself needing them after the fact.

``-f xml``
    This writes reports in jUnit format.  The reports will be xml files in a
    subdirectory "reports" of the current directory at the time testrunner.pl
    was invoked.  Note that this is NOT the same "reports" file as used by
    -f prettier.  This format is apparently useful for integration with various
    CI systems, though it's not used by our Github CI.

``-f tap``
    TAP is a common format which originated with Perl and is now widely used,
    see http://en.wikipedia.org/wiki/Test_Anything_Protocol for more
    information.  This seems to prints a single character for each test, or
    something.  I'm not sure what it's useful for, since if a test fails you
    don't know which one or why.

You can run just a subset of tests by giving arguments to testrunner.pl.
Tests to run are most commonly specified as:

* a test suite without the leading Cassandane::Cyrus

    .. code::

        $ ./testrunner.pl Quota

* a single test in a single test suite

    .. code::

        $ ./testrunner.pl Quota.quotarename

Multiple test suites or tests can be specified as well:

    .. code::

        $ ./testrunner.pl Admin Quota.quotarename

Arguments can be negated by using a leading exclamation mark (!) or tilde (~)
character.  Note that you may need to escape the ! from the shell, so ~ is
generally preferable:

.. code::

    $ ./testrunner.pl ~Quota

will run all the tests from all the suites except the Quota suite.
Arguments accumulate from left to right, so e.g.

.. code::

    $ ./testrunner.pl Quota ~Quota.quotarename

will run all the tests in the Quota suite except the quotarename test.

The -v (or --verbose) option to testrunner.pl causes both Cassandane and
several Cyrus programs run by Cassandane to emit a lot of information to
stderr.  You can specify this option multiple times for increased verbosity,
and the single-character version can be stacked, like -vvv.

The --valgrind option to testrunner.pl runs all the Cyrus executables using
Valgrind.  This is of course much slower but is recommended because it finds
many subtle bugs.  The Valgrind logs are saved in the files
$rootdir/$instance/vglogs/$name.$pid.  Cassandane will examine these logs after
each test finishes, and will fail the test if there are any errors (including
memory leaks) reported.

The --cleanup option causes Cassandane to do two things.  Firstly, it
immediately cleans up any files left over in $rootdir.  Secondly, it cleans up
any such files after each test, unless the test fails.  This should be helpful
when the filesystem in use does not have much room, such as when running on a
tmpfs filesystem.  You'll probably find this useful, so enable
cassandane.cleanup in your cassandane.ini rather than typing it all the time.
Then use --no-cleanup to override it when you don't want that.

testrunner.pl also accepts a bunch of other options that are not documented
here.  Consult the script itself for the full and most up-to-date set.

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
    Encapsulates an instance of Cyrus, with it's own directory
    structure, configuration files, master process, and one or more
    services such as imapd.

    To create a default Instance:

    .. code::

        my $instance = Cassandane::Instance->new();

    To create an Instance with a non-default parameter in the
    configuration file:

    .. code::

        my $config = Cassandane::Config->default()->clone();
        $config->set(conversations => 'on');
        my $instance = Cassandane::Instance->new(config => $config);

    By default the Instance has no services, but just runs the master
    daemon.  This is rarely a useful setup.  To add a service, in this case
    the imapd daemon:

    .. code::

        $instance->add_service(name => 'imap');

    Starting the Instance creates the directory structure and
    configuration files, then starts the master process and waits for
    all the defined services to be running (as reported by netstat).

    .. code::

        $instance->start();

    Stopping the instance kills all master process and all services
    as gracefully as possible, and waits for them to die.

    .. code::

        $instance->stop();

    Interactions with services are handled via one of the classed
    derived from the abstract Cassandane::MessageStore class.  To create
    a store for a paerticular service in an Instance:

    .. code::

        $store = $instance->get_service('imap')->create_store();

    For the imapd service in particular, Cassandane::IMAPMessageStore
    wraps a Mail::IMAPTalk object which can be retrieved thus:

    .. code::

        my $imaptalk = $store->get_client();

Cassandane::Config
    Encapsulates the configuration information present in an imapd.conf
    format configuration file.  Config objects are useful for passing
    to the Cassandane::Instance constructor to set up Cyrus instances
    with particular configuration options.

    The Config module keeps a global Config object.  This object should
    not be modified directly but should be cloned (see below).  To get
    the default object:

    .. code::

        my $config = Cassandane::Config->default();

    Configs use a lightweight copy-on-write cloning mechanism.  The
    clone() method can be used to create a new Config object based on a
    parent Config object.  The child remembers it's parent.

    .. code::

        my $child_config = $parent_config->clone();

    The set() and get() methods can be used to set and get key-value
    pairs from a Config object.  The set() method always works on the
    object itself, but get() will walk back up the ancestry chain until
    it finds a matching key.

    .. code::

        $config->set(conversations => 'on');
        $config->set(foo => '1', bar => '2');

        my $foo = $config->get('foo');

    The typical use for a Config object is:

    .. code::

        my $config = Cassandane::Config->default()->clone();
        $config->set(conversations => 'on');
        my $instance = Cassandane::Instance->new(config => $config);

Cassandane::Message
    Encapsulates an RFC822 message, plus a set of non-RFC822 attributes
    expressed as key-value pairs.   Message objects are returned from
    MessageStore->read_message() and Generator->generate().

    To create a new default Message object

    .. code::

        my $msg = Cassandane::Message->new();

    To create a Message object read from a file handle

    .. code::

        my $fh = ...
        my $msg = Cassandane::Message->new(fh => $fh);

    To get all the RFC822 headers of a given name, as a reference
    to an array of strings:

    .. code::

        my $values = $msg->get_headers('Received');

    To get an RFC822 header and enforce that there is only a single
    header of that name, use

    .. code::

        my $value = $msg->get_header('From');

    To set an RFC822 header, replacing any previous headers of
    the same name:

    .. code::

        $msg->set_headers('From', 'Foo Bar <foo@bar.org>');

    To set multiple RFC822 headers with the same name, replacing
    any previous headers of that name:

    .. code::

        my @values = ('baz', 'quux');
        $msg->set_headers('Received', @values);

    To add an RFC822 header:

    .. code::

        $msg->add_header('Subject', 'Hello World');

    To set the RFC822 body (as one big string)

    .. code::

        $msg->set_body('....one enormous string...');

    To get a non-RFC822 attribute (this may have be placed on the message
    as a side effect of it's creation e.g. during an IMAP FETCH command):

    .. code::

        my $cid = $msg->get_attribute('cid);

Cassandane::Generator
    Creates new Message objects with a number of useful default values
    based on random words.  Has a constructor and a single function

    .. code::

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

::

    sub test_my_new_feature
        :min_version_3_0
    {
         # [...]
    }

And you might continue to test some hypothetical feature that's been
discontinued on master but still exists in the stable branch with
something like:

::

    sub test_my_obsolete_feature
        :max_version_2_5
    {
        # [...]
    }

Cassandane::Instance offers ``get_version()``.  It's able to detect versions as
far back as 2.5.0.  So if you need to do some version-based conditionalisation
within a test function (or within infrastructure), you can use something like:

::

    my ($major, $minor, $revision, $extra) = Cassandane::Instance->get_version()

Cassandane::Test::Skip implements the skip handling.
