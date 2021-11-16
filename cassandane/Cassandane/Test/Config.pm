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

package Cassandane::Test::Config;
use strict;
use warnings;
use Data::Dumper;
use File::Temp qw(tempfile);

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Config;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_default
{
    my ($self) = @_;

    my $c = Cassandane::Config->default();
    $self->assert(defined $c);
    $self->assert(!defined $c->get('hello'));

    my $c2 = Cassandane::Config->default();
    $self->assert(defined $c2);
    $self->assert($c2 eq $c);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));

    $c->set(hello => 'world');
    $self->assert($c->get('hello') eq 'world');
    $self->assert($c2->get('hello') eq 'world');

    $c->set(hello => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));
}

sub test_clone
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c->get('foo'));

    my $c2 = $c->clone();
    $self->assert($c2 ne $c);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));

    $c2->set(hello => 'world');
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));

    $c->set(foo => 'bar');
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert($c->get('foo') eq 'bar');
    $self->assert($c2->get('foo') eq 'bar');

    $c2->set(foo => 'baz');
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert($c->get('foo') eq 'bar');
    $self->assert($c2->get('foo') eq 'baz');

    $c2->set(foo => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert($c->get('foo') eq 'bar');
    $self->assert(!defined $c2->get('foo'));

    $c->set(foo => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));

    $c2->set(hello => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));
}

sub _generate_and_read
{
    my ($self, $c) = @_;

    # Write the file
    my ($fh, $filename) = tempfile()
        or die "Cannot open temporary file: $!";
    $c->generate($filename);

    # read it back again to check
    my %nv;
    while (<$fh>)
    {
        chomp;
        my ($n, $v) = m/^([^:\s]+):\s*(.+)*$/;
        $self->assert(defined $v);
        $nv{$n} = $v;
    }

    close $fh;
    unlink $filename;

    return \%nv;
}

sub test_generate
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $c->set(foo => 'bar');
    $c->set(quux => 'foonly');
    $c->set('httpmodules', 'caldav jmap');
    $c->set('event_groups', [qw(quota)]);

    my $c2 = $c->clone();
    $c2->set(hello => 'world');
    $c2->set(foo => 'baz');
    $c2->set('event_groups', [qw(flags quota)]);

    my $nv = $self->_generate_and_read($c2);

    $self->assert_num_equals(5, scalar(keys(%$nv)));
    $self->assert_str_equals('baz', $nv->{foo});
    $self->assert_str_equals('world', $nv->{hello});
    $self->assert_str_equals('foonly', $nv->{quux});
    $self->assert_str_equals('caldav jmap', $nv->{httpmodules});
    $self->assert_str_equals('flags quota', $nv->{event_groups});
}

sub test_variables
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $c->set(foo => 'b@grade@r');
    $c->set(quux => 'fo@grade@nly');
    my $c2 = $c->clone();
    $c2->set(hello => 'w@grade@rld');
    $c2->set(foo => 'baz');

    # missing @grade@ variable throws an exception
    my $nv;
    eval
    {
        $nv = $self->_generate_and_read($c2);
    };
    $self->assert(defined $@ && $@ =~ m/Variable grade not defined/i);

    # @grade@ on the parent affects all variable expansions
    $c->set_variables('grade' => 'B');
    $nv = $self->_generate_and_read($c2);
    $self->assert_num_equals(3, scalar(keys(%$nv)));
    $self->assert_str_equals('baz', $nv->{foo});
    $self->assert_str_equals('wBrld', $nv->{hello});
    $self->assert_str_equals('foBnly', $nv->{quux});

    # @grade@ on the child overrides @grade@ on the parent
    $c2->set_variables('grade' => 'A');
    $nv = $self->_generate_and_read($c2);
    $self->assert_num_equals(scalar(keys(%$nv)), 3);
    $self->assert_str_equals('baz', $nv->{foo});
    $self->assert_str_equals('wArld', $nv->{hello});
    $self->assert_str_equals('foAnly', $nv->{quux});
}

sub test_bitfields
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();

    # can set bitfields as space separated strings
    $c->set('httpmodules' => 'caldav jmap');
    # get in scalar context returns space separated string
    $self->assert_str_equals('caldav jmap', scalar $c->get('httpmodules'));
    # get in list context returns list
    $self->assert_deep_equals([qw(caldav jmap)], [$c->get('httpmodules')]);

    # can clear a whole bitfield
    $c->clear_all_bits('httpmodules');
    $self->assert_null($c->get('httpmodules'));

    # can set bitfields as array reference
    $c->set('httpmodules' => [qw(caldav jmap)]);
    # get in scalar context returns space separated string
    $self->assert_str_equals('caldav jmap', scalar $c->get('httpmodules'));
    # get in list context returns list
    $self->assert_deep_equals([qw(caldav jmap)], [$c->get('httpmodules')]);

    # can clear one bit
    $c->clear_bits('httpmodules', 'caldav');
    $self->assert_str_equals('jmap', $c->get('httpmodules'));

    # can set one bit
    $c->set_bits('httpmodules', 'prometheus');
    $self->assert_str_equals('jmap prometheus', scalar $c->get('httpmodules'));

    # can get one bit
    $self->assert($c->get_bit('httpmodules', 'prometheus'));
    $self->assert($c->get_bit('httpmodules', 'jmap'));
    # valid bits that aren't set are false
    $self->assert(not $c->get_bit('httpmodules', 'caldav'));
    $self->assert(not $c->get_bit('httpmodules', 'freebusy'));

    # can set a few bits
    $c->set_bits('httpmodules', 'caldav', 'carddav');
    $self->assert_str_equals('caldav carddav jmap prometheus',
                             scalar $c->get('httpmodules'));
    $c->set_bits('httpmodules', 'ischedule rss');
    $self->assert_str_equals('caldav carddav ischedule jmap prometheus rss',
                             scalar $c->get('httpmodules'));
    $c->set_bits('httpmodules', 'cgi_webdav');
    $self->assert_str_equals('caldav carddav cgi ischedule jmap prometheus rss webdav',
                             scalar $c->get('httpmodules'));

    # can clear a few bits
    $c->clear_bits('httpmodules', 'caldav', 'carddav');
    $self->assert_str_equals('cgi ischedule jmap prometheus rss webdav',
                             scalar $c->get('httpmodules'));
    $c->clear_bits('httpmodules', 'ischedule rss');
    $self->assert_str_equals('cgi jmap prometheus webdav',
                             scalar $c->get('httpmodules'));
    $c->clear_bits('httpmodules', 'cgi_webdav');
    $self->assert_str_equals('jmap prometheus',
                             scalar $c->get('httpmodules'));


    # setting with set() should replace previous bit set
    $c->set('httpmodules' => [qw(admin tzdist)]);
    $self->assert(not $c->get_bit('httpmodules', 'prometheus'));
    $self->assert(not $c->get_bit('httpmodules', 'jmap'));
    $self->assert($c->get_bit('httpmodules', 'admin'));
    $self->assert($c->get_bit('httpmodules', 'tzdist'));
    $self->assert_str_equals('admin tzdist', scalar $c->get('httpmodules'));

    # cannot set bits on non-bitfield options
    eval {
        $c->set_bits('conversations', 'irrelevant');
    };
    my $e = $@;
    $self->assert_matches(qr{conversations is not a bitfield option}, $e);

    # cannot set invalid bits on bitfield options
    eval {
        $c->set_bits('httpmodules', 'bogus');
    };
    $e = $@;
    $self->assert_matches(qr{bogus is not a httpmodules value}, $e);

    # cannot mix and match bits from other bitfields
    eval {
        $c->set_bits('httpmodules', 'VEVENT');
    };
    $e = $@;
    $self->assert_matches(qr{VEVENT is not a httpmodules value}, $e);

    # should be able to set valid bitfields in constructor
    my $c2 = Cassandane::Config->new('foo' => 'bar',
                                     'httpmodules' => 'caldav jmap',
                                     'event_groups' => [qw(message quota)]);
    $self->assert_not_null($c2);

    # expectations should still hold for bitfields set via constructor
    $self->assert_str_equals('bar', $c2->get('foo'));
    $self->assert_str_equals('caldav jmap', scalar $c2->get('httpmodules'));
    $self->assert_deep_equals([qw(caldav jmap)], [$c2->get('httpmodules')]);
    $self->assert_str_equals('message quota', scalar $c2->get('event_groups'));
    $self->assert_deep_equals([qw(message quota)], [$c2->get('event_groups')]);
}

sub test_clone_bitfields
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $self->assert_null($c->get('httpmodules'));
    $self->assert_null($c->get('event_groups'));

    my $c2 = $c->clone();
    $self->assert($c2 ne $c);
    $self->assert_null($c->get('httpmodules'));
    $self->assert_null($c2->get('httpmodules'));
    $self->assert_null($c->get('event_groups'));
    $self->assert_null($c2->get('event_groups'));

    # set bit in clone doesn't affect parent
    $c2->set_bits('httpmodules', 'caldav');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('caldav', scalar $c2->get('httpmodules'));
    $self->assert_null($c->get('event_groups'));
    $self->assert_null($c2->get('event_groups'));

    # set bit in parent is inherited by child
    $c->set_bits('event_groups', 'access', 'mailbox');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('caldav', scalar $c2->get('httpmodules'));
    $self->assert_str_equals('access mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('access mailbox', scalar $c2->get('event_groups'));

    # set bit in child supplements parent
    $c2->set_bits('event_groups', 'quota');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('caldav', scalar $c2->get('httpmodules'));
    $self->assert_str_equals('access mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('access mailbox quota', scalar $c2->get('event_groups'));

    # clear bit in child overrides parent
    $c2->clear_bits('event_groups', 'mailbox');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('caldav', scalar $c2->get('httpmodules'));
    $self->assert_str_equals('access mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('access quota', scalar $c2->get('event_groups'));

    # clear bit in parent updates inheriting child
    $c->clear_bits('event_groups', 'access');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('caldav', scalar $c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('quota', scalar $c2->get('event_groups'));

    # clear bit in child updates child
    $c2->clear_bits('event_groups', 'quota');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('caldav', scalar $c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_null($c2->get('event_groups'));

    # set explicit list in parent updates child
    $c->set('httpmodules', 'jmap prometheus carddav');
    $self->assert_str_equals('carddav jmap prometheus',
                             scalar $c->get('httpmodules'));
    $self->assert_str_equals('caldav carddav jmap prometheus',
                             scalar $c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_null($c2->get('event_groups'));

    # clear all in child overrides parent
    $c2->clear_all_bits('httpmodules');
    $self->assert_str_equals('carddav jmap prometheus',
                             scalar $c->get('httpmodules'));
    $self->assert_null($c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_null($c2->get('event_groups'));

    # discard clone and recreate, clone should be the same as parent again
    undef $c2;
    $c2 = $c->clone();
    $self->assert_not_equals($c, $c2);
    $self->assert_equals(scalar $c->get('httpmodules'),
                         scalar $c2->get('httpmodules'));
    $self->assert_equals(scalar $c->get('event_groups'),
                         scalar $c2->get('event_groups'));

    # bit set in both parent and child is only listed once
    $c2->set_bits('httpmodules', 'jmap');
    $self->assert_str_equals('carddav jmap prometheus',
                             scalar $c->get('httpmodules'));
    $self->assert_str_equals('carddav jmap prometheus',
                             scalar $c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('mailbox', scalar $c2->get('event_groups'));

    # clearing bit in parent doesn't affect child who has it explicitly set
    $c->clear_bits('httpmodules', 'jmap');
    $self->assert_str_equals('carddav prometheus',
                             scalar $c->get('httpmodules'));
    $self->assert_str_equals('carddav jmap prometheus',
                             scalar $c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('mailbox', scalar $c2->get('event_groups'));

    # clearing all in parent doesn't affect child's explicit bits
    $c->clear_all_bits('httpmodules');
    $self->assert_null($c->get('httpmodules'));
    $self->assert_str_equals('jmap', scalar $c2->get('httpmodules'));
    $self->assert_str_equals('mailbox', scalar $c->get('event_groups'));
    $self->assert_str_equals('mailbox', scalar $c2->get('event_groups'));
}

1;
