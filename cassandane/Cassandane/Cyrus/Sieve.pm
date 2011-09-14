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
package Cassandane::Cyrus::Sieve;
use base qw(Cassandane::Cyrus::TestCase);
use IO::File;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ deliver => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_deliver
{
    my ($self) = @_;

    my $sieved = "$self->{instance}{basedir}/conf/sieve/c/cassandane";
    system('mkdir', '-p', $sieved);

    open(FH, ">$sieved/testsieve.script");
    print FH <<EOF;
require ["fileinto"];
fileinto "INBOX.target";
EOF
    close(FH);
    $self->{instance}->run_command({ cyrus => 1 }, "sievec", "$sieved/testsieve.script" => "$sieved/testsieve.bc");
    system('ln', '-s', "testsieve.bc" => "$sieved/defaultbc");

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.target");

    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);
}

1;
