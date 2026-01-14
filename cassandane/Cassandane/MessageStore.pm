# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::MessageStore;
use strict;
use warnings;
use overload qw("") => \&as_string;

use Cassandane::Util::Log;

sub new
{
    my ($class, %params) = @_;
    my $self = {
        verbose => delete $params{verbose} || 0,
    };
    die "Unknown parameters: " . join(' ', keys %params)
        if scalar %params;
    return bless $self, $class;
}

sub connect
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub disconnect
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub write_begin
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub write_message
{
    my ($self, $msg, %opts) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub write_end
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub read_begin
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub read_message
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub read_end
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub get_client
{
    my ($self) = @_;
    die "Unimplemented in base class " . __PACKAGE__;
}

sub as_string
{
    my ($self) = @_;
    return "unknown";
}

1;
