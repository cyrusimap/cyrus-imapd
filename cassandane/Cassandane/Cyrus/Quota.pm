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
package Cassandane::Cyrus::Quota;
use base qw(Test::Unit::TestCase);
use IO::File;
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

    $self->{instance} = Cassandane::Instance->new();
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

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(storage 100000)") || die "Failed $@";
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

sub make_message
{
    my ($self, $store, $subject, @attrs) = @_;

    $store->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, @attrs);
    $store->write_message($msg);
    $store->write_end();

    return $msg;
}

#
# Test renames
#
sub test_quotarename
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_num_equals(0, $res[1]);

    for (1..10) {
	$self->make_message($self->{store}, "Message $_", extra_lines => 5000);
    }

    @res = $admintalk->getquota("user.cassandane");

    my $base_usage = $res[1];
    $self->assert_num_not_equals(0, $base_usage, "10 messages should use some quota: " . Dumper(\@res));

    $imaptalk->create("INBOX.sub") || die;
    $imaptalk->select($self->{store}->{folder}) || die;
    $imaptalk->copy("1:5", "INBOX.sub") || die;
    $imaptalk->select("INBOX.sub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);

    my $more_usage = $res[1];
    $self->assert_num_not_equals($base_usage, $more_usage, "another 15 messages should use more quota ($base_usage, $more_usage)");

    $imaptalk->rename("INBOX.sub", "INBOX.othersub") || die;
    $imaptalk->select("INBOX.othersub") || die;

    # usage should be the same after a rename
    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals($more_usage, $res[1], "Usage should be unchanged after a rename ($more_usage, $res[1])");

    $imaptalk->delete("INBOX.othersub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals($base_usage, $res[1], "Usage should drop back after a delete ($base_usage, $res[1])");
}

sub test_quota_f {
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.quotafuser");
    $admintalk->setacl("user.quotafuser", "admin", 'lrswipkxtecda');
    $self->{adminstore}->set_folder("user.quotafuser");
    for (1..3) {
	$self->make_message($self->{adminstore}, "QuotaFUser $_", extra_lines => 17000);
    }
    for (1..10) {
	$self->make_message($self->{store}, "Cassandane $_", extra_lines => 5000);
    }

    $admintalk->create("user.zlateuser");
    $admintalk->setacl("user.zlateuser", "admin", 'lrswipkxtecda');
    $self->{adminstore}->set_folder("user.zlateuser");
    for (1..7) {
	$self->make_message($self->{adminstore}, "Lateuser $_", extra_lines => 1200);
    }
    $admintalk->setquota("user.zlateuser", "(storage 750000)") || die "Failed $@";

    my @origcasres = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @origcasres);

    my @origzres = $admintalk->getquota("user.zlateuser");
    $self->assert_num_equals(3, scalar @origzres);

    # create a bogus quota file
    mkdir("$self->{instance}{basedir}/conf/quota");
    mkdir("$self->{instance}{basedir}/conf/quota/q");
    my $fh = IO::File->new(">$self->{instance}{basedir}/conf/quota/q/user.quotafuser") || die "Failed to open quota file";
    print $fh "0\n100000\n";
    close($fh);
    $self->{instance}->_fix_ownership("$self->{instance}{basedir}/conf/quota");

    # find and add the quota
    $self->{instance}->run_utility('quota', '-f');

    my @res = $admintalk->getquota("user.quotafuser");
    $self->assert_num_equals(3, scalar @res);
    my @casres = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @casres);
    my @zres = $admintalk->getquota("user.zlateuser");
    $self->assert_num_equals(3, scalar @zres);

    # re-run the quota utility
    $self->{instance}->run_utility('quota', '-f');

    my @res2 = $admintalk->getquota("user.quotafuser");
    $self->assert_num_equals(3, scalar @res2);
    my @casres2 = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @casres2);
    my @zres2 = $admintalk->getquota("user.zlateuser");
    $self->assert_num_equals(3, scalar @zres2);

    # usage should be unchanged
    $self->assert($res[1] == $res2[1] && 
		  $casres[1] == $casres2[1] &&
		  $casres[1] == $origcasres[1], 
		  $zres[1] == $zres2[1] &&
		  $zres[1] == $origzres[1], 
		  "Quota mismatch: quotafuser (1: $res[1], 2: $res2[1]) " .
		  "cassandane (0:$origcasres[1], 1:$casres[1], 2:$casres2[1]) " .
		  "zlateuser (0:$origzres[1], 1:$zres[1], 2:$zres2[1])");
}

1;
