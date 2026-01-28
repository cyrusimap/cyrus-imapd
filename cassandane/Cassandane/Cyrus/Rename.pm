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

package Cassandane::Cyrus::Rename;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

Cassandane::Cyrus::TestCase::magic(MetaPartition => sub {
    shift->config_set(
        'metapartition-default' => '@basedir@/meta',
        'metapartition_files' => 'header index'
    );
});

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

sub get_partition
{
    my ($talk, $folder) = @_;

    my $key = '/shared/vendor/cmu/cyrus-imapd/partition';
    my $md = $talk->getmetadata($folder, $key);

    return undef if $talk->get_last_completion_response() ne 'ok';
    return $md->{$folder}->{$key};
}

sub _match_intermediates
{
    my ($self, %expect) = @_;
    my @lines = $self->{instance}->getsyslog();
    #'Aug 23 12:34:20 bat 0234200101/ctl_cyrusdb[14527]: mboxlist: creating intermediate with children: user.cassandane.a (ec10f137-1bee-443e-8cb2-c6c893463b0a)',
    #'Aug 23 12:34:20 bat 0234200101/ctl_cyrusdb[14527]: mboxlist: deleting intermediate with no children: user.cassandane.hanging (b13ba9d4-9d40-4474-911f-77346a73d747)',
    for (@lines) {
        if (m/mboxlist: creating intermediate with children: (.*?)($| \()/) {
            my $mbox = $1;
            $self->assert(exists $expect{$mbox}, "didn't expect touch of $mbox");
            my $val = delete $expect{$mbox};
            $self->assert(!$val, "create when expected delete of $mbox");
        }
        if (m/mboxlist: deleting intermediate with no children: (.*?)($| \()/) {
            my $mbox = $1;
            $self->assert(exists $expect{$mbox}, "didn't expect touch of $mbox");
            my $val = delete $expect{$mbox};
            $self->assert(!!$val, "delete when expected create of $mbox");
        }
    }
    use Data::Dumper;
    $self->assert_num_equals(0, scalar keys %expect, "EXPECTED TO SEE " . Dumper(\%expect, \@lines));
}

sub _dbset
{
    my ($self, $key, $value) = @_;
    my $format = $self->{instance}->{config}->get('mboxlist_db');
    $self->assert_str_equals('ok', $self->{instance}->run_dbcommand_cb(
        sub { die "got a response!" },
        "$self->{instance}->{basedir}/conf/mailboxes.db",
        $format,
        defined($value)
          ? ['SET', $key => $value]
          : ['DELETE', $key],
    ));
}

use Cassandane::Tiny::Loader 'tiny-tests/Rename';

1;
