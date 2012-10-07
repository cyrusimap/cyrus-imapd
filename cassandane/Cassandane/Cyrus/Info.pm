#!/usr/bin/perl
#
#  Copyright (c) 2011-2012 Opera Software Australia Pty. Ltd.  All rights
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
package Cassandane::Cyrus::Info;
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

sub run_cyr_info
{
    my ($self, @args) = @_;

    my $filename = $self->{instance}->{basedir} . "/cyr_info.out";

    $self->{instance}->run_command({
	    cyrus => 1,
	    redirects => { stdout => $filename },
	},
	'cyr_info',
	# we get -C for free
	'-M', $self->{instance}->_master_conf(),
	@args
    );

    open RESULTS, '<', $filename
	or die "Cannot open $filename for reading: $!";
    my @res = readline(RESULTS);
    close RESULTS;

    return @res;
}

sub test_info_conf
{
    my ($self) = @_;

    xlog "test 'cyr_info conf' in the simplest case";

    # Slurp the imapd.conf
    my $filename = $self->{instance}->_imapd_conf();
    open CONF, '<', $filename
	or die "Cannot open $filename for reading: $!";
    my @imapd_conf = readline(CONF);
    close CONF;

    @imapd_conf = sort {
	    substr($a, 0, index($a, ':'))
	    cmp
	    substr($b, 0, index($b, ':'))
	} @imapd_conf;

    my @output = $self->run_cyr_info('conf');

    @output = sort {
	    substr($a, 0, index($a, ':'))
	    cmp
	    substr($b, 0, index($b, ':'))
	} @output;

    $self->assert_deep_equals(\@imapd_conf, \@output);
}

sub test_info_lint
{
    my ($self) = @_;

    xlog "test 'cyr_info lint' in the simplest case";

    my @output = $self->run_cyr_info('lint');
    $self->assert_deep_equals([], \@output);
}

Cassandane::Cyrus::TestCase::magic(ConfigJunk => sub {
    shift->config_set(trust_fund => 'street art');
});

sub test_info_lint_junk
    :ConfigJunk
{
    my ($self) = @_;

    xlog "test 'cyr_info lint' with junk in the config";

    my @output = $self->run_cyr_info('lint');
    $self->assert_deep_equals(["trust_fund: street art\n"], \@output);
}


1;
