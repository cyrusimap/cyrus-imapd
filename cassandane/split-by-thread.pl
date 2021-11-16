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
#       Opera Software Australia Pty. Ltd.
#       Level 50, 120 Collins St
#       Melbourne 3000
#       Victoria
#       Australia
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
