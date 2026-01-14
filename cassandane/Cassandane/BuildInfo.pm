# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::BuildInfo;
use strict;
use warnings;
use JSON;

use Cassandane::Cassini;
use Cassandane::Util::Log;

sub new {
    my ($class, $installation) = @_;
    my $self = {};

    $installation ||= 'default';

    my $cassini = Cassandane::Cassini->instance();

    my $destdir = $cassini->val("cyrus $installation", 'destdir', '');
    my $prefix = $cassini->val("cyrus $installation", 'prefix', '/usr/cyrus');

    $self->{data} = _read_buildinfo($destdir, $prefix);

    return bless $self, $class;
}

sub _read_buildinfo
{
    my ($destdir, $prefix) = @_;

    my $cyr_buildinfo;
    foreach my $bindir (qw(sbin cyrus/bin)) {
        my $p = "$destdir$prefix/$bindir/cyr_buildinfo";
        if (-x $p) {
            $cyr_buildinfo = $p;
            last;
        }
    }

    if (not defined $cyr_buildinfo) {
        xlog "Couldn't find cyr_buildinfo: ".
             "don't know what features Cyrus supports";
        return;
    }

    my $jsondata = qx($cyr_buildinfo);
    return if not $jsondata;

    return JSON::decode_json($jsondata);
}

sub get
{
    my ($self, $category, $key) = @_;

    return if not exists $self->{data}->{$category};
    return $self->{data}->{$category} if not defined $key;
    return if not exists $self->{data}->{$category}->{$key};
    return $self->{data}->{$category}->{$key};
}

1;
