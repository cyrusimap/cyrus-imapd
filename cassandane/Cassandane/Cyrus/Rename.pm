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
package Cassandane::Cyrus::Rename;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;
use Data::Dumper;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    my $conf = Cassandane::Config->default()->clone();

    $conf->set(
	'partition-p2' => '@basedir@/data-p2',
    );

    $self->{instance} = Cassandane::Instance->new(config => $conf);
    $self->{instance}->add_service('imap');

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    $self->{store} = $self->{instance}->get_service('imap')->create_store();
    $self->{adminstore} = $self->{instance}->get_service('imap')->create_store(username => 'admin');
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
# Test LSUB behaviour
#
sub test_rename_asuser
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.user-src") || die;
    $self->{store}->{folder} = "INBOX.user-src";  # gah, API
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();
    $imaptalk->select("INBOX.user-src") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->rename("INBOX.user-src", "INBOX.user-dst") || die;
    $imaptalk->select("INBOX.user-dst") || die;
    my @postdata = $imaptalk->search("FLAG" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postdata);
}

#
# Test LSUB behaviour
#
sub test_rename_user
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->rename('user.cassandane', 'user.cassandane'); # should have an error;
    $self->assert($admintalk->get_last_error());

    $admintalk->rename('user.cassandane', 'user.cassandane', 'p2') || die; # partition move
}

1;
