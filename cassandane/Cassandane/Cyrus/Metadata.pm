#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
package Cassandane::Cyrus::Metadata;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{instance} = Cassandane::Instance->new();
    $self->{instance}->add_service('imap');

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    my $svc = $self->{instance}->get_service('imap');
    $self->{store} = $svc->create_store();
    $self->{adminstore} = $svc->create_store(username => 'admin');
}

sub tear_down
{
    my ($self) = @_;

    $self->{store}->disconnect()
	if defined $self->{store};
    $self->{store} = undef;
    $self->{adminstore}->disconnect()
	if defined $self->{adminstore};
    $self->{adminstore} = undef;
    $self->{instance}->stop();
}

#
# Test the cyrus annotations
#
sub test_shared
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog "reading read_only Cyrus annotations";
    my $res = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/shared');

    # size should be zero
    $self->assert_not_null($res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/size"});
    $self->assert_num_equals(0, $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/size"});

    # parition should be default
    $self->assert_str_equals('default', $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/partition"});

    # individual item fetch:
    my $part = $imaptalk->getmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/partition");
    $self->assert_str_equals('default', $part->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/partition"});

    # duplicate deliver should be false
    $self->assert_str_equals('false', $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/duplicatedeliver"});

    # set duplicate deliver (as admin)
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setmetadata('user.cassandane', "/shared/vendor/cmu/cyrus-imapd/duplicatedeliver", 'true');

    # and make sure the change sticks
    my $dup = $imaptalk->getmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/duplicatedeliver");
    $self->assert_str_equals('true', $dup->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/duplicatedeliver"});
}

sub test_private
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog "testing private metadata operations";

    # nothing present
    my $res = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/private');
    $self->assert_num_equals(0, scalar keys %$res);

    $imaptalk->setmetadata('INBOX', "/private/comment", "This is a comment");
    my $com = $imaptalk->getmetadata('INBOX', "/private/comment");
    $self->assert_str_equals("This is a comment", $com->{INBOX}{"/private/comment"});

    # remove it again
    $imaptalk->setmetadata('INBOX', "/private/comment", undef);

    my $meta = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/private');
    $self->assert_num_equals(0, scalar keys %$meta);
}

1;
