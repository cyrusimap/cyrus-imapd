# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Config;
use strict;
use warnings;

use Cassandane::Cassini;
use Cassandane::Config::Bitfields;
use Cassandane::Util::Log;

my $default;

sub new
{
    my $class = shift;

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
            master_pid_file => '@basedir@/run/master.pid',
            master_ready_file => '@basedir@/master.ready',
            defaultpartition => 'default',
            defaultdomain => 'defdomain',
            'partition-default' => '@basedir@/data',
            sasl_mech_list => 'PLAIN LOGIN',
            allowplaintext => 'yes',
            # for debugging - see cassandane.ini.example
            debug_command => '@prefix@/utils/gdbtramp %s %d',
            # default changed, we want to be explicit about it
            unixhierarchysep => 'no',
            # let's hear all about it
            auditlog => 'yes',
            chatty => 'yes',
            debug => 'yes',
            httpprettytelemetry => 'yes',

            # smtpclient_open should fail by default!
            #
            # If your test fails and writes something like
            #     smtpclient_open: can't connect to host: bogus:0/noauth
            # in syslog, then Cyrus is calling smtpclient_open(), and you
            # will need to arrange for fakesmtpd to be listening.  To do
            # this add :want_smtpdaemon to the test attributes, or enable
            # smtpdaemon in the suite constructor.
            smtp_backend => 'host',
            smtp_host => 'bogus:0',
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
    return split / /, $s;
}

sub set
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
        if (is_bitfield($n)) {
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

sub set_if_undef
{
    my ($self, %nv) = @_;

    while (my ($n, $v) = each %nv) {
        if (is_bitfield($n)) {
            # XXX bitfield behaviour?
            die "can't set_if_undef with bitfield '$n'";
        }
        elsif (not defined $self->get($n)) {
            $self->{params}->{$n} = $v;
        }
        else {
            # nothing to do
        }
    }
}

sub set_bits
{
    my ($self, $name, @bits) = @_;

    die "$name is not a bitfield option" if not is_bitfield($name);

    # explode space-delimited list as only bit
    if (scalar @bits == 1 && $bits[0] =~ m/ /) {
        @bits = _explode_bit_string($bits[0]);
    }

    foreach my $bit (@bits) {
        die "$bit is not a $name value"
            if not is_bitfield_bit($name, $bit);

        $self->{params}->{$name}->{$bit} = 1;
    }
}

sub clear_bits
{
    my ($self, $name, @bits) = @_;

    die "$name is not a bitfield option" if not is_bitfield($name);

    # explode space-delimited list as only bit
    if (scalar @bits == 1 && $bits[0] =~ m/ /) {
        @bits = _explode_bit_string($bits[0]);
    }

    foreach my $bit (@bits) {
        die "$bit is not a $name value"
            if not is_bitfield_bit($name, $bit);

        $self->{params}->{$name}->{$bit} = 0;
    }
}

sub clear_all_bits
{
    my ($self, $name) = @_;

    die "$name is not a bitfield option" if not is_bitfield($name);

    $self->{params}->{$name}->{$_} = 0 for get_bitfield_bits($name);
}

sub get
{
    my ($self, $n) = @_;
    if (is_bitfield($n)) {
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

    die "$bit is not a $name value" if not is_bitfield_bit($name, $bit);

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

    die "bitfield $n cannot be boolean" if is_bitfield($n);

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
            if (is_bitfield($n)) {
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
        if (is_bitfield($n)) {
            my @bits = grep { $nv->{$n}->{$_} } sort keys %{$nv->{$n}};
            print CONF "$n: " . join(q{ }, @bits) . "\n";
        }
        else {
            print CONF "$n: $v\n";
        }
    }
    close CONF;
}

sub is_bitfield
{
    my ($name) = @_;

    return defined $Cassandane::Config::Bitfields::bitfields{$name};
}

sub is_bitfield_bit
{
    my ($name, $value) = @_;

    die "$name is not a bitfield option"
        if not exists $Cassandane::Config::Bitfields::bitfields{$name};

    return defined $Cassandane::Config::Bitfields::bitfields{$name}->{$value};
}

sub get_bitfield_bits
{
    my ($name) = @_;

    die "$name is not a bitfield option"
        if not exists $Cassandane::Config::Bitfields::bitfields{$name};

    return sort keys %{$Cassandane::Config::Bitfields::bitfields{$name}};
}

1;
