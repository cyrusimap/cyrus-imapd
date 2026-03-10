# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::MessageStoreFactory;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::MessageStoreFactory;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

# Test no args at all - default is mbox to stdout/stdin
sub test_no_args
{
    my ($self) = @_;
    my $ms = Cassandane::MessageStoreFactory->create();
    $self->assert(ref $ms eq 'Cassandane::MboxMessageStore');
    $self->assert( !defined $ms->{filename});
}

# Test guessing type from single attribute, one of 'filename'
# 'directory' or 'host'.
sub test_single_attr
{
    my ($self) = @_;
    my $ms = Cassandane::MessageStoreFactory->create(filename => 'foo');
    $self->assert(ref $ms eq 'Cassandane::MboxMessageStore');
    $self->assert($ms->{filename} eq 'foo');

    $ms = Cassandane::MessageStoreFactory->create(directory => 'foo');
    $self->assert(ref $ms eq 'Cassandane::MaildirMessageStore');
    $self->assert($ms->{directory} eq 'foo');
}

# Test creating from a URI
sub test_uri
{
    my ($self) = @_;
    my $ms = Cassandane::MessageStoreFactory->create(uri => 'mbox:///foo/bar');
    $self->assert(ref $ms eq 'Cassandane::MboxMessageStore');
    $self->assert($ms->{filename} eq '/foo/bar');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'file:///foo/bar');
    $self->assert(ref $ms eq 'Cassandane::MboxMessageStore');
    $self->assert($ms->{filename} eq '/foo/bar');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'maildir:///foo/bar');
    $self->assert(ref $ms eq 'Cassandane::MaildirMessageStore');
    $self->assert($ms->{directory} eq '/foo/bar');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://victoria:secret@foo.com:29143/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert($ms->{username} eq 'victoria');
    $self->assert($ms->{password} eq 'secret');
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 29143);
    $self->assert($ms->{folder} eq 'inbox.foo');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://victoria@foo.com:29143/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert($ms->{username} eq 'victoria');
    $self->assert(!defined $ms->{password});
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 29143);
    $self->assert($ms->{folder} eq 'inbox.foo');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com:29143/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert(!defined $ms->{username});
    $self->assert(!defined $ms->{password});
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 29143);
    $self->assert($ms->{folder} eq 'inbox.foo');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert(!defined $ms->{username});
    $self->assert(!defined $ms->{password});
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 143);
    $self->assert($ms->{folder} eq 'inbox.foo');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com/');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert(!defined $ms->{username});
    $self->assert(!defined $ms->{password});
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 143);
    $self->assert($ms->{folder} eq 'INBOX');
}

# Test creation with the 'path' and 'type' attribute - default
# arguments for genmail3.pl
sub test_path
{
    my ($self) = @_;

    my $ms = Cassandane::MessageStoreFactory->create(path => 'foo');
    $self->assert(ref $ms eq 'Cassandane::MboxMessageStore');
    $self->assert($ms->{filename} eq 'foo');

    $ms = Cassandane::MessageStoreFactory->create(type => 'mbox', path => 'foo');
    $self->assert(ref $ms eq 'Cassandane::MboxMessageStore');
    $self->assert($ms->{filename} eq 'foo');

    $ms = Cassandane::MessageStoreFactory->create(type => 'maildir', path => 'foo');
    $self->assert(ref $ms eq 'Cassandane::MaildirMessageStore');
    $self->assert($ms->{directory} eq 'foo');
}

1;
