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

# Tweak the include path to find the Cyrus install directory.
use lib ("$ENV{CASSANDANE_CYRUS_PREFIX}/share/perl",
	 "$ENV{CASSANDANE_CYRUS_PREFIX}/lib/perl");
# And again to find Cassandane modules
use lib ("$ENV{CASSANDANE_PREFIX}");

use strict;
use warnings;
package Cassandane::AnnotatorDaemon;
# use base qw(Cyrus::Annotator::Daemon);
use Cyrus::Annotator::Daemon;
our @ISA = qw(Cyrus::Annotator::Daemon);
use Cassandane::Util::Log;

my %valid_shared = ( shared => SHARED, private => PRIVATE );

my %commands =
(
    add_annotation => sub
    {
	my ($self, $entry, $shared, $value) = @_;
	die "Wrong number of args for add_annotation" unless (@_ == 4);
	$shared = $valid_shared{lc($shared)}
	    or die "Bad argument 2 for add_annotation";
	xlog "add_annotation(\"$entry\", " . $shared . ", \"$value\")";
	$self->add_annotation($entry, $shared, $value);
    },
    remove_annotation => sub
    {
	my ($self, $entry, $shared) = @_;
	die "Wrong number of args for remove_annotation" unless (@_ == 3);
	$shared = $valid_shared{lc($shared)}
	    or die "Bad argument 2 for remove_annotation";
	xlog "remove_annotation(\"$entry\", " . $shared . ")";
	$self->remove_annotation($entry, $shared);
    },
    set_flag => sub
    {
	my ($self, $flag) = @_;
	die "Wrong number of args for set_flag" unless (@_ == 2);
	xlog "set_flag($flag)";
	$self->set_flag($flag);
    },
    clear_flag => sub
    {
	my ($self, $flag) = @_;
	die "Wrong number of args for clear_flag" unless (@_ == 2);
	xlog "clear_flag($flag)";
	$self->clear_flag($flag);
    },
);

sub annotate_message
{
    my ($self, $args) = @_;

    xlog "annotate_message called";

    # Parse the body of the message as a series of test commands
    seek $args->{FH}, $args->{BODY}->{Offset}, 0
	or die "Cannot seek in message: $!";

    while (my $line = readline $args->{FH})
    {
	chomp $line;
	my @a = split /\s+/, $line;
	my $cmd = $commands{$a[0]}
	    or die "Unknown command $a[0]";
	shift(@a);
	$cmd->($self, @a);
    }
}

# suck ARGV dry to prevent Net::Daemon getting its hands on it
@ARGV = ();

xlog "annotator starting";
Cassandane::AnnotatorDaemon->run(
	background => 0,
	pid_file => "$ENV{CASSANDANE_BASEDIR}/conf/socket/annotator.pid",
	port => "$ENV{CASSANDANE_BASEDIR}/conf/socket/annotator.sock|SOCK_STREAM|unix",
    );
