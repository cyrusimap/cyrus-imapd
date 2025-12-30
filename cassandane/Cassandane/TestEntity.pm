package Cassandane::TestEntity;
# Nothing should load this!

=head1 NAME

Cassandane::TestEntity - the test entity system, for making test data easily

=head1 OVERVIEW

The "test entity" system is a couple of things that work together to make it
easy to set up the test data you need to test Cyrus.  Those things are:

L<Cassandane::Instance>, which represents an instance of Cyrus.  From an
instance, you can create instances of...

L<Cassandane::TestUser>, which makes it easy to get protocol clients for a
given user -- but also lets you create test data with the various test entity
factories.

The entity factories are objects that perform the role
L<Cassandane::TestEntity::Role::Factory>.  You can generally get them by
calling a plural-noun-named method on a TestUser.  For example, to get the
factory for the Mailbox type, you can call C<< $user->mailboxes >>.

A factory is there to help you find, retrieve, and create instances.  For
example, given a mailbox id (like C<PN1->) you can call C<< ->get($id) >> on
the factory to get back the instance object.  (More on those below.)  Factories
always provide C<get>, and also C<create>.  The create method will create a new
instance.  Under the hood, it calls the C<Whatever/set> JMAP method to create
an object, providing defaults for any properties where it's required.

Factories often provide more methods, like C<inbox> on the mailboxes factory to
get a mailbox instance object for the user's Inbox.

Instances are objects that perform the role
L<Cassandane::TestEntity::Role::Instance>.  Each one represents a single object
in a JMAP datatype, like an email or a calendar.  They always have an C<id>
method, and often many other accessors for common properties.  You can call
those methods to read or update their properties, or you can call the C<update>
method.  Updates become C<Whatever/set> calls.

Instances often have more useful behavior for datatype-specific actions.  For
example, you can call C<new_email> on a mailbox instance to create an email in
that mailbox.  These will be documented in the module for that datatype, which
will always be named in the form Cassandane::TestEntity::DataType::Whatever.

=cut

1;
