#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Test::MessageStoreFactory;
use strict;
use warnings;

use lib '.';
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

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://victoria:secret@foo.com:9143/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert($ms->{username} eq 'victoria');
    $self->assert($ms->{password} eq 'secret');
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 9143);
    $self->assert($ms->{folder} eq 'inbox.foo');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://victoria@foo.com:9143/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert($ms->{username} eq 'victoria');
    $self->assert(!defined $ms->{password});
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 9143);
    $self->assert($ms->{folder} eq 'inbox.foo');

    $ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com:9143/inbox.foo');
    $self->assert(ref $ms eq 'Cassandane::IMAPMessageStore');
    $self->assert(!defined $ms->{username});
    $self->assert(!defined $ms->{password});
    $self->assert($ms->{host} eq 'foo.com');
    $self->assert($ms->{port} == 9143);
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
