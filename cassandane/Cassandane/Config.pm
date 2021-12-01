#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Config;
use strict;
use warnings;

use lib '.';
use Cassandane::Cassini;
use Cassandane::Util::Log;

my $default;

# XXX Manually entered from lib/imapoptions in cyrus-imapd repo.
# XXX Once these repositories are merged, we'll be able to automate keeping
# XXX this synchronised...
my %bitfields = (
    'calendar_component_set' => 'VEVENT VTODO VJOURNAL VFREEBUSY VAVAILABILITY VPOLL',
    'event_extra_params' => 'bodyStructure clientAddress diskUsed flagNames messageContent messageSize messages modseq service timestamp uidnext vnd.cmu.midset vnd.cmu.unseenMessages vnd.cmu.envelope vnd.cmu.sessionId vnd.cmu.mailboxACL vnd.cmu.mbtype vnd.cmu.davFilename vnd.cmu.davUid vnd.fastmail.clientId vnd.fastmail.sessionId vnd.fastmail.convExists vnd.fastmail.convUnseen vnd.fastmail.cid vnd.fastmail.counters vnd.fastmail.jmapEmail vnd.fastmail.jmapStates vnd.cmu.emailid vnd.cmu.threadid',
    'event_groups' => 'message quota flags access mailbox subscription calendar applepushservice',
    'httpmodules' => 'admin caldav carddav cgi domainkey freebusy ischedule jmap prometheus rss tzdist webdav',
    'metapartition_files' => 'header index cache expunge squat annotations lock dav archivecache',
    'newsaddheaders' => 'to replyto',
    'sieve_extensions' => 'fileinto reject vacation vacation-seconds notify include envelope environment body relational regex subaddress copy date index imap4flags imapflags mailbox mboxmetadata servermetadata variables editheader extlists duplicate ihave fcc special-use redirect-dsn redirect-deliverby mailboxid vnd.cyrus.log x-cyrus-log vnd.cyrus.jmapquery x-cyrus-jmapquery snooze vnd.cyrus.snooze x-cyrus-snooze vnd.cyrus.imip',
);
my $bitfields_fixed = 0;

sub new
{
    my $class = shift;

    if (!$bitfields_fixed) {
        while (my ($key, $allvalues) = each %bitfields) {
            $bitfields{$key} = {};
            foreach my $v (split /\s/, $allvalues) {
                $bitfields{$key}->{$v} = 1;
            }
        }
        $bitfields_fixed = 1;
    }

    my $self = {
        parent => undef,
        variables => {},
        params => {},
    };

    bless $self, $class;

    # any arguments are initial params, process them properly
    $self->set(@_);

    return $self;
}

sub default
{
    if (!defined($default)) {
        $default = Cassandane::Config->new(
            admins => 'admin mailproxy mupduser repluser',
            rfc3028_strict => 'no',
            configdirectory => '@basedir@/conf',
            syslog_prefix => '@name@',
            sievedir => '@basedir@/conf/sieve',
            defaultpartition => 'default',
            defaultdomain => 'defdomain',
            'partition-default' => '@basedir@/data',
            sasl_mech_list => 'PLAIN LOGIN',
            allowplaintext => 'yes',
            # config options used at FastMail - may as well be testing our stuff
            expunge_mode => 'delayed',
            delete_mode => 'delayed',
            # for debugging - see cassandane.ini.example
            debug_command => '@prefix@/utils/gdbtramp %s %d',
            # everyone should be running this
            improved_mboxlist_sort => 'yes',
            # default changed, we want to be explicit about it
            unixhierarchysep => 'no',
            # let's hear all about it
            auditlog => 'yes',
            chatty => 'yes',
            debug => 'yes',
            httpprettytelemetry => 'yes',
        );
        my $defs = Cassandane::Cassini->instance()->get_section('config');
        $default->set(%$defs);
    }

    return $default;
}

sub clone
{
    my ($self) = @_;

    my $child = Cassandane::Config->new();
    $child->{parent} = $self;
    return $child;
}

sub _explode_bit_string
{
    my ($s) = @_;
    return split /[_ ]/, $s;
}

sub set
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
        if (exists $bitfields{$n}) {
            # it's a bitfield, set exactly what's given (clearing others)
            if (ref $v eq 'ARRAY') {
                $self->clear_all_bits($n);
                $self->set_bits($n, @{$v});
            }
            elsif (ref $v eq q{}) {
                $self->clear_all_bits($n);
                $self->set_bits($n, _explode_bit_string($v));
            }
            else {
                die "don't know what to do with value '$v'";
            }
        }
        else {
            $self->{params}->{$n} = $v;
        }
    }
}

sub set_bits
{
    my ($self, $name, @bits) = @_;

    die "$name is not a bitfield option" if not exists $bitfields{$name};

    # explode space- or underscore-delimited list as only bit
    if (scalar @bits == 1 && $bits[0] =~ m/[_ ]/) {
        @bits = _explode_bit_string($bits[0]);
    }

    foreach my $bit (@bits) {
        die "$bit is not a $name value"
            if not exists $bitfields{$name}->{$bit};

        $self->{params}->{$name}->{$bit} = 1;
    }
}

sub clear_bits
{
    my ($self, $name, @bits) = @_;

    die "$name is not a bitfield option" if not exists $bitfields{$name};

    # explode space- or underscore-delimited list as only bit
    if (scalar @bits == 1 && $bits[0] =~ m/[_ ]/) {
        @bits = _explode_bit_string($bits[0]);
    }

    foreach my $bit (@bits) {
        die "$bit is not a $name value"
            if not exists $bitfields{$name}->{$bit};

        $self->{params}->{$name}->{$bit} = 0;
    }
}

sub clear_all_bits
{
    my ($self, $name) = @_;

    die "$name is not a bitfield option" if not exists $bitfields{$name};

    $self->{params}->{$name}->{$_} = 0 for keys %{$bitfields{$name}};
}

sub get
{
    my ($self, $n) = @_;
    if (exists $bitfields{$n}) {
        my %bits;
        while (defined $self) {
            if (exists $self->{params}->{$n}) {
                while (my ($bit, $val) = each %{$self->{params}->{$n}}) {
                    $bits{$bit} //= $val;
                }
            }
            $self = $self->{parent};
        }
        my @v = grep { $bits{$_} } sort keys %bits;
        return wantarray ? @v : join q{ }, @v;
    }
    else {
        while (defined $self)
        {
            return $self->{params}->{$n}
                if exists $self->{params}->{$n};
            $self = $self->{parent};
        }
    }
    return undef;
}

sub get_bit
{
    my ($self, $name, $bit) = @_;

    die "$name is not a bitfield option" if not exists $bitfields{$name};
    die "$bit is not a $name value" if not exists $bitfields{$name}->{$bit};

    while (defined $self) {
        return $self->{params}->{$name}->{$bit}
            if exists $self->{params}->{$name}->{$bit};
        $self = $self->{parent};
    }
    return undef;
}

sub get_bool
{
    my ($self, $n, $def) = @_;

    die "bitfield $n cannot be boolean" if exists $bitfields{$n};

    $def = 'no' if !defined $def;
    my $v = $self->get($n);
    $v = $def if !defined $v;

    return 1 if ($v =~ m/^yes$/i);
    return 1 if ($v =~ m/^true$/i);
    return 1 if ($v =~ m/^on$/i);
    return 1 if ($v =~ m/^1$/);

    return 0 if ($v =~ m/^no$/i);
    return 0 if ($v =~ m/^false$/i);
    return 0 if ($v =~ m/^off$/i);
    return 0 if ($v =~ m/^0$/);

    die "Bad boolean \"$v\"";
}

sub set_variables
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
        $self->{variables}->{$n} = $v;
    }
}

sub _get_variable
{
    my ($self, $n) = @_;
    $n =~ s/@//g;
    while (defined $self)
    {
        return $self->{variables}->{$n}
            if exists $self->{variables}->{$n};
        $self = $self->{parent};
    }
    die "Variable $n not defined";
}

sub substitute
{
    my ($self, $s) = @_;

    return unless defined $s;
    my $r = '';
    while (defined $s)
    {
        my ($pre, $ref, $post) = ($s =~ m/(.*)(@[a-z]+@)(.*)/);
        if (defined $ref)
        {
            $r .= $pre . $self->_get_variable($ref);
            $s = $post;
        }
        else
        {
            $r .= $s;
            last;
        }
    }
    return $r;
}

sub _flatten
{
    my ($self) = @_;
    my %nv;
    for (my $conf = $self ; defined $conf ; $conf = $conf->{parent})
    {
        foreach my $n (keys %{$conf->{params}})
        {
            if (exists $bitfields{$n}) {
                # no variable substitution on bitfields
                while (my ($bit, $val) = each %{$conf->{params}->{$n}}) {
                    $nv{$n}->{$bit} //= $val;
                }
            }
            else {
                $nv{$n} = $self->substitute($conf->{params}->{$n})
                    unless exists $nv{$n};
            }
        }
    }
    return \%nv;
}

sub generate
{
    my ($self, $filename) = @_;
    my $nv = $self->_flatten();

    open CONF,'>',$filename
        or die "Cannot open $filename for writing: $!";
    while (my ($n, $v) = each %$nv)
    {
        next unless defined $v;
        if (exists $bitfields{$n}) {
            my @bits = grep { $nv->{$n}->{$_} } sort keys %{$nv->{$n}};
            print CONF "$n: " . join(q{ }, @bits) . "\n";
        }
        else {
            print CONF "$n: $v\n";
        }
    }
    close CONF;
}

1;
