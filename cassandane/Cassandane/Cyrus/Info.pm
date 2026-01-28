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

package Cassandane::Cyrus::Info;
use strict;
use warnings;
use Cwd qw(realpath);
use Data::Dumper;
use Date::Format qw(time2str);
use Time::HiRes qw(usleep);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
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

Cassandane::Cyrus::TestCase::magic(ConfigJunk => sub {
    shift->config_set(trust_fund => 'street art');
});

sub _set_and_get_fields {
    my ($self, $set_fields, $get_fields, $cmd) = @_;

    $self->config_set(%$set_fields);

    $self->_start_instances();

    $cmd //= 'conf';

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info($cmd)) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $cyr_info_conf{$name} = join q{ }, sort @values;
        }
        else {
            $cyr_info_conf{$name} = $value;
        }
    }

    for my $field (keys %$get_fields) {
        my $expect = join q{ }, sort split /\s+/, $get_fields->{$field};
        $self->assert_str_equals($expect, $cyr_info_conf{$field});
    }
}

use Cassandane::Tiny::Loader 'tiny-tests/Info';

1;
