# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Log;
use strict;
use warnings;
use File::Basename;
use Scalar::Util qw(blessed);
use Sys::Syslog qw(:standard :macros);

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &xlog &set_verbose &get_verbose
    );

my $verbose = 0;

openlog('cassandane', '', LOG_LOCAL6)
    or die "Cannot openlog";

sub xlog
{
    my $id;
    my $highlight = 0;

    # if the first argument is an object with an id() method,
    # include the id it returns in the log message
    if (ref $_[0] && blessed $_[0] && $_[0]->can('id')) {
        my $obj = shift @_;
        $id = $obj->id();
    }

    # if the first output argument starts with XXX, highlight the
    # whole line when printing to stderr
    if ($_[0] =~ m/^XXX/) {
        $highlight = 1;
    }

    # the current line number is in this frame
    my (undef, undef, $line) = caller();
    # but the current subroutine name is in the parent frame,
    # as the function-the-caller-called
    my (undef, undef, undef, $sub) = caller(1);
    $sub //= basename($0);
    $sub =~ s/^Cassandane:://;
    my $msg = "[$$] =====> $sub\[$line] ";
    $msg .= "($id) " if $id;
    $msg .= join(' ', @_);
    if ($highlight) {
        print STDERR "\033[33m" . $msg . "\033[0m\n";
    }
    else {
        print STDERR "$msg\n";
    }
    syslog(LOG_ERR, "$msg");
}

sub set_verbose
{
    my ($v) = @_;
    $verbose = 0 + $v;
}

sub get_verbose
{
    return $verbose;
}

1;
