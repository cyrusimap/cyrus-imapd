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

package Cassandane::Cyrus::Thread;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
}

sub test_unrelated
{
    my ($self) = @_;

    xlog $self, "test THREAD with no inter-message references";
    xlog $self, "and all different subjects";
    my $talk = $self->{store}->get_client();
    my $res;

    xlog $self, "append some messages";
    my %exp;
    my $N = 20;
    for (1..$N)
    {
        my $msg = $self->make_message("Message $_");
        $exp{$_} = $msg;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp);

    xlog $self, "The REFERENCES algorithm gives each message in a singleton thread";
    $res = $talk->thread('REFERENCES', 'US-ASCII', 'ALL');
    $self->assert_deep_equals([ map { [ $_ ] } (1..$N) ], $res);

    xlog $self, "The ORDEREDSUBJECT algorithm gives each message in a singleton thread";
    $res = $talk->thread('ORDEREDSUBJECT', 'US-ASCII', 'ALL');
    $self->assert_deep_equals([ map { [ $_ ] } (1..$N) ], $res);

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp);
}

sub test_subjects
{
    my ($self) = @_;

    xlog $self, "test THREAD with no inter-message references";
    xlog $self, "but apparently similar subjects";
    my $talk = $self->{store}->get_client();
    my $res;

    xlog $self, "append some messages";
    my %exp;
    my %exp_by_sub;
    my $N = 20;
    my @subjects = ( 'quinoa', 'selvedge', 'messenger bag' );
    for (1..$N)
    {
        my $sub = $subjects[($_ - 1) % scalar(@subjects)];
        $exp_by_sub{$sub} ||= [];
        my $msg = $self->make_message(("Re: " x scalar(@{$exp_by_sub{$sub}})) . $sub);
        push(@{$exp_by_sub{$sub}}, $msg);
        $exp{$_} = $msg;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp);

    my @expthreads;
    foreach my $sub (@subjects)
    {
        my @thread = ( map { $_->uid } @{$exp_by_sub{$sub}} );
        my $parent = shift(@thread);
        push(@expthreads, [ $parent, map { [ $_ ] } @thread ] );
    }

    xlog $self, "The REFERENCES algorithm gives one thread per subject, even";
    xlog $self, "though the References headers are completely missing";
    $res = $talk->thread('REFERENCES', 'US-ASCII', 'ALL');
    $self->assert_deep_equals(\@expthreads, $res);

    xlog $self, "The ORDEREDSUBJECT algorithm gives one thread per subject";
    $res = $talk->thread('ORDEREDSUBJECT', 'US-ASCII', 'ALL');
    $self->assert_deep_equals(\@expthreads, $res);

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp);
}

sub test_references_chain
{
    my ($self) = @_;

    xlog $self, "test THREAD with a linear chain of inter-message references";
    xlog $self, "and apparently similar subjects";
    my $talk = $self->{store}->get_client();
    my $res;

    xlog $self, "append some messages";
    my %exp;
    my %exp_by_sub;
    my $N = 20;
    my @subjects = ( 'cosby sweater', 'brooklyn', 'portland' );
    for (1..$N)
    {
        my $sub = $subjects[($_ - 1) % scalar(@subjects)];
        $exp_by_sub{$sub} ||= [];
        my $msg;
        if (scalar @{$exp_by_sub{$sub}})
        {
            my $parent = $exp_by_sub{$sub}->[-1];
            $msg = $self->make_message("Re: " . $parent->subject,
                                       references => [ $parent ]);
        }
        else
        {
            $msg = $self->make_message($sub);
        }
        push(@{$exp_by_sub{$sub}}, $msg);
        $exp{$_} = $msg;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp);

    my @expthreads;

    xlog $self, "The REFERENCES algorithm gives the true thread structure which is deep";
    foreach my $sub (@subjects)
    {
        push(@expthreads, [ map { $_->uid } @{$exp_by_sub{$sub}} ]);
    }
    $res = $talk->thread('REFERENCES', 'US-ASCII', 'ALL');
    $self->assert_deep_equals(\@expthreads, $res);

# From RFC5256
#          The top level or "root" in ORDEREDSUBJECT threading contains
#          the first message of every thread.  All messages in the root
#          are siblings of each other.  The second message of a thread is
#          the child of the first message, and subsequent messages of the
#          thread are siblings of the second message and hence children of
#          the message at the root.  Hence, there are no grandchildren in
#          ORDEREDSUBJECT threading.
    xlog $self, "The ORDEREDSUBJECT algorithm gives a false more flat view of the structure";
    @expthreads = ();
    foreach my $sub (@subjects)
    {
        my @thread = ( map { $_->uid } @{$exp_by_sub{$sub}} );
        my $parent = shift(@thread);
        push(@expthreads, [ $parent, map { [ $_ ] } @thread ] );
    }
    $res = $talk->thread('ORDEREDSUBJECT', 'US-ASCII', 'ALL');
    $self->assert_deep_equals(\@expthreads, $res);

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp);
}

sub test_references_star
{
    my ($self) = @_;

    xlog $self, "test THREAD with a star configuration of inter-message references";
    xlog $self, "and apparently similar subjects";
    my $talk = $self->{store}->get_client();
    my $res;

    xlog $self, "append some messages";
    my %exp;
    my %exp_by_sub;
    my $N = 20;
    my @subjects = ( 'cosby sweater', 'brooklyn', 'portland' );
    foreach my $uid (1..$N)
    {
        my $sub = $subjects[($uid - 1) % scalar(@subjects)];
        $exp_by_sub{$sub} ||= [];
        my $msg;
        if (scalar @{$exp_by_sub{$sub}})
        {
            my $parent = $exp_by_sub{$sub}->[0];
            $msg = $self->make_message("Re: " . $parent->subject,
                                       references => [ $parent ]);
        }
        else
        {
            $msg = $self->make_message($sub);
        }
        push(@{$exp_by_sub{$sub}}, $msg);
        $exp{$uid} = $msg;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp, keyed_on => 'uid');

    my @expthreads;
    foreach my $sub (@subjects)
    {
        my @thread = ( map { $_->uid } @{$exp_by_sub{$sub}} );
        my $parent = shift(@thread);
        push(@expthreads, [ $parent, map { [ $_ ] } @thread ] );
    }

    xlog $self, "The REFERENCES algorithm gives the true thread structure which is flat";
    $res = $talk->thread('REFERENCES', 'US-ASCII', 'ALL');
    $self->assert_deep_equals(\@expthreads, $res);

    xlog $self, "The ORDEREDSUBJECT algorithm gives the same flat view";
    $res = $talk->thread('ORDEREDSUBJECT', 'US-ASCII', 'ALL');
    $self->assert_deep_equals(\@expthreads, $res);

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp, keyed_on => 'uid');
}

sub test_references_missing_parent
{
    my ($self) = @_;

    xlog $self, "test THREAD with two messages which share a common parent";
    xlog $self, "which is not seen on the server";
    my $talk = $self->{store}->get_client();
    my $res;
    my %exp;

    xlog $self, "Message A is never seen by the server";
    my $msgA = $self->{gen}->generate(subject => "put a bird on it");

    xlog $self, "Generate message B, which References message A";
    my $msgB = $self->make_message("Re: " . $msgA->subject,
                                   uid => 1,
                                   references => [ $msgA ]);
    $exp{1} = $msgB;

    xlog $self, "Generate message C, which References message A";
    my $msgC = $self->make_message("Re: " . $msgA->subject,
                                   uid => 2,
                                   references => [ $msgA ]);
    $exp{2} = $msgC;

    xlog $self, "check the messages got there";
    $self->check_messages(\%exp, keyed_on => 'uid');

    xlog $self, "The REFERENCES algorithm gives the true thread";
    xlog $self, "structure which is flat with a missing common parent";
    $res = $talk->thread('REFERENCES', 'US-ASCII', 'ALL');
    $self->assert_deep_equals([[[1],[2]]], $res);

    xlog $self, "The ORDEREDSUBJECT algorithm gives a false more flat view of the structure";
    $res = $talk->thread('ORDEREDSUBJECT', 'US-ASCII', 'ALL');
    $self->assert_deep_equals([[1, 2]], $res);

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp, keyed_on => 'uid');
}


sub test_references_loop
{
    my ($self) = @_;

    xlog $self, "test THREAD with a loop configuration of inter-message references";
    xlog $self, "and a missing common parent (Bug 3784)";
    my $talk = $self->{store}->get_client();
    my $res;
    my %exp;

    xlog $self, "Generate message B, which References itself and some other messages";
    my $msgB = $self->{gen}->generate(subject => "Re: put a bird on it", uid => 1);
    $msgB->set_headers('Message-Id', '<477CBE0D020000330001972A@gwia1.boku.ac.at>');
    $msgB->set_headers('References',
                        '<477CB3AF0200001E00003B58@gwia1.boku.ac.at>' . "\n" .
                        '<477CBA030200003300019722@gwia1.boku.ac.at>' . "\n" .
                        '<477CBD530200003300019726@gwia1.boku.ac.at>' . "\n" .
                        '<477CBE0D020000330001972A@gwia1.boku.ac.at>');
    $msgB->set_headers('In-Reply-To', '<477CBE0D020000330001972A@gwia1.boku.ac.at>');
    $self->_save_message($msgB);
    $exp{1} = $msgB;

    xlog $self, "Generate message C, which References itself and some other messages";
    my $msgC = $self->{gen}->generate(subject => "Re: put a bird on it", uid => 2);
    $msgC->set_headers('Message-Id', '<478B52E10200003300019E06@gwia1.boku.ac.at>');
    $msgC->set_headers('References',
                        '<477CB3AF0200001E00003B58@gwia1.boku.ac.at>' . "\n" .
                        '<478B2D7F0200003300019DA2@gwia1.boku.ac.at>' . "\n" .
                        '<478B2E9F0200003300019DA5@gwia1.boku.ac.at>' . "\n" .
                        '<478B2F0E0200003300019DA8@gwia1.boku.ac.at>' . "\n" .
                        '<478B32C40200003300019DB1@gwia1.boku.ac.at>' . "\n" .
                        '<478B38C40200003300019DBD@gwia1.boku.ac.at>' . "\n" .
                        '<478B52E10200003300019E06@gwia1.boku.ac.at>');
    $msgC->set_headers('In-Reply-To',  '<478B52E10200003300019E06@gwia1.boku.ac.at>');
    $self->_save_message($msgC);
    $exp{2} = $msgC;

    xlog $self, "check the messages got there";
    $self->check_messages(\%exp, keyed_on => 'uid');

    xlog $self, "The REFERENCES algorithm gives the true thread";
    xlog $self, "structure which is flat";
    $res = $talk->thread('REFERENCES', 'US-ASCII', 'ALL');
    $self->assert_deep_equals([[[1], [2]]], $res);

    xlog $self, "The ORDEREDSUBJECT algorithm gives a false more flat view of the structure";
    $res = $talk->thread('ORDEREDSUBJECT', 'US-ASCII', 'ALL');
    $self->assert_deep_equals([[1, 2]], $res);

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp, keyed_on => 'uid');
}

1;
