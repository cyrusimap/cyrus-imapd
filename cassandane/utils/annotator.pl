#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::AnnotatorDaemon;
use strict;
use warnings;
use base qw(Cyrus::Annotator::Daemon);
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX;

use lib '.';
use Cassandane::Util::Log;

set_verbose(1) if $ENV{CASSANDANE_VERBOSE};

# Hack to work around Net::Server being too dumb to unblock the signals
# it handles, notably SIGQUIT.  This was breaking the Jenkins build,
# because Jenkins starts child processes with SIGQUIT blocked and
# Cassandane::Instance expects to be able to use SIGQUIT to gracefully
# shut down processes.
sigprocmask(SIG_UNBLOCK, POSIX::SigSet->new( &POSIX::SIGQUIT ))
    or die "Cannot unblock SIGQUIT: $!";

my %commands =
(
    set_shared_annotation => sub
    {
        my ($message, $entry, $value) = @_;
        die "Wrong number of args for set_shared_annotation" unless (@_ == 3);
        xlog "set_shared_annotation(\"$entry\", \"$value\")";
        $message->set_shared_annotation($entry, $value);
    },
    set_private_annotation => sub
    {
        my ($message, $entry, $value) = @_;
        die "Wrong number of args for set_private_annotation" unless (@_ == 3);
        xlog "set_private_annotation(\"$entry\", \"$value\")";
        $message->set_private_annotation($entry, $value);
    },
    clear_shared_annotation => sub
    {
        my ($message, $entry) = @_;
        die "Wrong number of args for clear_shared_annotation" unless (@_ == 2);
        xlog "clear_shared_annotation(\"$entry\")";
        $message->clear_shared_annotation($entry);
    },
    clear_private_annotation => sub
    {
        my ($message, $entry) = @_;
        die "Wrong number of args for clear_private_annotation" unless (@_ == 2);
        xlog "clear_private_annotation(\"$entry\")";
        $message->clear_private_annotation($entry);
    },
    set_flag => sub
    {
        my ($message, $flag) = @_;
        die "Wrong number of args for set_flag" unless (@_ == 2);
        xlog "set_flag($flag)";
        $message->set_flag($flag);
    },
    clear_flag => sub
    {
        my ($message, $flag) = @_;
        die "Wrong number of args for clear_flag" unless (@_ == 2);
        xlog "clear_flag($flag)";
        $message->clear_flag($flag);
    },

    # These are here so that syntactically valid Sieve scripts can be appended,
    # and go through the test annotator daemon, and not crash it before hitting
    # instructions inside the comments.  Weird, right? -- rjbs, 2025-01-29
    '/*' => sub {},
    '*/' => sub {},
);

sub annotate_message
{
    my ($self, $message) = @_;

    xlog "annotate_message called";

    # Parse the body of the message as a series of test commands
    my $fh = $message->fh();
    seek $fh, $message->bodystructure()->{Offset}, 0
        or die "Cannot seek in message: $!";

    while (my $line = readline $fh)
    {
        chomp $line;
        my @a = split /\s+/, $line;
        my $cmd = $commands{$a[0]}
            or die "Unknown command $a[0]";
        shift(@a);
        $cmd->($message, @a);
    }
}

my $pidfile = "$ENV{CASSANDANE_BASEDIR}/conf/socket/annotator.pid";
my $port = "$ENV{CASSANDANE_BASEDIR}/conf/socket/annotator.sock|unix";
GetOptions(
    'pidfile|P=s' => \$pidfile,
    'port|p=s' => \$port,
) || die "Bad arguments";

# suck ARGV dry to prevent Net::Daemon getting its hands on it
@ARGV = ();

xlog "annotator $$ starting";
Cassandane::AnnotatorDaemon->run(
        pid_file => $pidfile,
        port => $port
    );
xlog "annotator $$ exiting";
