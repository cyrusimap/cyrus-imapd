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
use Data::Dumper;

use lib '.';
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

sub test_conf
{
    my ($self) = @_;

    my %imapd_conf;
    my $filename = $self->{instance}->_imapd_conf();
    open my $fh, '<', $filename
        or die "Cannot open $filename for reading: $!";
    while (my $line = <$fh>) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $imapd_conf{$name} = join q{ }, sort @values;
        }
        else {
            $imapd_conf{$name} = $value;
        }
    }
    close $fh;

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info('conf')) {
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

    $self->assert_deep_equals(\%imapd_conf, \%cyr_info_conf);
}

sub test_conf_all
{
    my ($self) = @_;

    my %imapd_conf;
    my $filename = $self->{instance}->_imapd_conf();
    open my $fh, '<', $filename
        or die "Cannot open $filename for reading: $!";
    while (my $line = <$fh>) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $imapd_conf{$name} = join q{ }, sort @values;
        }
        else {
            $imapd_conf{$name} = $value;
        }
    }
    close $fh;

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info('conf-all')) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;

        # conf-all outputs ALL configured values (including defaults)
        # but we can only really test for the ones we know we put there
        next if not exists $imapd_conf{$name};

        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $cyr_info_conf{$name} = join q{ }, sort @values;
        }
        else {
            $cyr_info_conf{$name} = $value;
        }
    }

    $self->assert_deep_equals(\%imapd_conf, \%cyr_info_conf);
}

sub test_conf_default
{
    my ($self) = @_;

    # conf-default spits out all the defaults.  can't do much to
    # check the actual contents, short of duplicating lib/imapoptions
    # in here, but we can at least make sure it runs without crashing
    # and its output looks reasonably sane

    foreach my $line ($self->{instance}->run_cyr_info('conf-default')) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;

        $self->assert_not_null($name);
        $self->assert_not_null($value);

        if (Cassandane::Config::is_bitfield($name)) {
            foreach my $v (split /\s+/, $value) {
                $self->assert_not_null(Cassandane::Config::is_bitfield_bit($name, $v));
            }
        }
    }
}

sub test_lint
{
    my ($self) = @_;

    xlog $self, "test 'cyr_info conf-lint' in the simplest case";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    $self->assert_deep_equals([], \@output);
}

Cassandane::Cyrus::TestCase::magic(ConfigJunk => sub {
    shift->config_set(trust_fund => 'street art');
});

sub test_lint_junk
    :ConfigJunk
{
    my ($self) = @_;

    xlog $self, "test 'cyr_info conf-lint' with junk in the config";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    $self->assert_deep_equals(["trust_fund: street art\n"], \@output);
}

sub test_lint_channels
    :min_version_3_2 :NoStartInstances
{
    my ($self) = @_;

    $self->config_set(
        'sync_log_channels' => 'banana',
        'banana_sync_host' => 'banana.internal',
        'banana_sync_trust_fund' => 'street art',
        'banana_tcp_keepalive' => 'yes',
        'banana_sasl_mech_list' => 'PLAIN',
    );

    $self->_start_instances();

    xlog $self, "test 'cyr_info conf-lint' with channel-specific sync config";

    my @output = $self->{instance}->run_cyr_info('conf-lint');

    $self->assert_deep_equals(
        [ sort(
            "banana_sync_trust_fund: street art\n",
            "banana_tcp_keepalive: yes\n",
            "banana_sasl_mech_list: PLAIN\n",
        ) ],
        [ sort @output ]
    );
}

sub test_lint_partitions
    :min_version_3_0 :NoStartInstances
{
    my ($self) = @_;

    $self->config_set(
        # metapartition-, archivepartition- and searchpartition- must
        # correspond with an extant partition-
        #
        # backuppartition- is independent
        'partition-good' => '/tmp/pgood',
        'metapartition-good' => '/tmp/mgood',
        'archivepartition-good' => '/tmp/agood',
        'foosearchpartition-good' => '/tmp/sgood',
        'backuppartition-good' => '/tmp/bgood',

        'metapartition-bad' => '/tmp/mbad',
        'archivepartition-bad' => '/tmp/abad',
        'foosearchpartition-bad' => '/tmp/sbad',

        # not actually bad
        'backuppartition-bad' => '/tmp/bbad',
    );

    $self->_start_instances();

    xlog $self, "test 'cyr_info conf-lint' with partitions configured";

    my @output = $self->{instance}->run_cyr_info('conf-lint');

    $self->assert_deep_equals(
        [ sort(
            "archivepartition-bad: /tmp/abad\n",
            "foosearchpartition-bad: /tmp/sbad\n",
            "metapartition-bad: /tmp/mbad\n",
        ) ],
        [ sort @output ]
    );
}

sub test_lint_services
    :want_service_http :needs_component_httpd :NoStartInstances
{
    my ($self) = @_;

    $self->config_set(
        'http_sasl_mech_list' => 'PLAIN',
        'http_sasl_trust_fund' => 'street art',
        'http_tcp_keepalive' => 'yes',
        'http_trust_fund' => 'street art',
    );

    $self->_start_instances();

    xlog $self, "test 'cyr_info conf-lint' with service-specific config";

    my @output = $self->{instance}->run_cyr_info('conf-lint');
    @output = grep { !m/_db: / } @output;  # skip database types

    $self->assert_deep_equals(
        [ sort(
            "http_trust_fund: street art\n",
            # XXX we don't verify sasl keys, so this isn't reported
            #"http_sasl_trust_fund: street art\n",
        ) ],
        [ sort @output ]
    );
}

1;
