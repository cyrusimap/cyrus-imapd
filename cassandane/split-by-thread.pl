#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;
use DateTime;

use lib '.';
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: split-by-thread.pl [ -f format [maildir] | -u uri]";
}

my %params;
while (my $a = shift)
{
    if ($a eq '-f')
    {
        usage() if defined $params{uri};
        $params{type} = shift;
    }
    elsif ($a eq '-u')
    {
        usage() if defined $params{type};
        $params{uri} = shift;
    }
    elsif ($a eq '-v')
    {
        $params{verbose} = 1;
    }
    elsif ($a =~ m/^-/)
    {
        usage();
    }
    else
    {
        usage() if defined $params{path};
        $params{path} = $a;
    }
}

sub extract_refs
{
    my ($msg) = @_;
    my $str = $msg->get_header('references');
    return if !defined $str;
    my @refs;

    for (;;)
    {
        my ($msgid, $rem) = ($str =~ m/[\s,]*(<[^\s<>]+@[^\s<>]+>)(.*)/);
        last if !defined $msgid;
        push(@refs, $msgid);
        last if !defined $rem || !length $rem;
        $str = $rem;
    }

    return @refs;
}

my $store = Cassandane::MessageStoreFactory->create(%params);

my %threads_by_msgid;
my @threads;
my $next_thread_id = 1;
my $max_msgs = 1000;

sub thread_new
{
    my $t =
        {
            id => $next_thread_id++,
            messages => [],
        };
    push(@threads, $t);
    return $t;
}

sub thread_add_message
{
    my ($thread, $msg) = @_;

    push(@{$thread->{messages}}, $msg);
    $threads_by_msgid{$msg->get_header('message-id')} = $thread;
}

$store->read_begin();
while (my $msg = $store->read_message())
{
    my $msgid = $msg->get_header('message-id');
    die "duplicate msgid $msgid"
        if defined $threads_by_msgid{$msgid};

    my @refs;
    eval
    {
        @refs = extract_refs($msg);
    };
    if ($@)
    {
        print STDERR "Can't get references: $@";
        next;
    }

    my $thread;
    foreach my $ref (@refs)
    {
        my $t = $threads_by_msgid{$ref};
        if (defined $t &&
            defined $thread &&
            $t->{id} != $thread->{id})
        {
            print STDERR "Thread clash! $t->{id} vs $thread->{id}\n";
            next;
        }
        $thread = $t;
    }

    $thread = thread_new()
        if !defined $thread;
    thread_add_message($thread, $msg);

    last if (--$max_msgs == 0);
}
$store->read_end();

foreach my $t (@threads)
{
    next if scalar(@{$t->{messages}}) < 8;

    my $store = Cassandane::MessageStoreFactory->create(
                    type => 'mbox',
                    path => sprintf("x/thread%04u", $t->{id}));
    $store->write_begin();
    foreach my $msg (@{$t->{messages}})
    {
        $store->write_message($msg);
    }
    $store->write_end();
}
