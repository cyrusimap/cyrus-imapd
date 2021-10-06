#!/usr/bin/env perl
#
# Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
use Config;

sub normalise {
    my $s = shift;
    $s =~ s/\/+$//;
    return $s;
}

sub quote {
    my $s = shift;
    return "'$s'";
}

sub usage {
    die "Usage: $0 configure_prefix configure_bindir";
}

my $configure_prefix = normalise(shift || usage);
my $configure_bindir = normalise(shift || usage);
my $perl_prefix = normalise($Config{prefix});

# These directories are listed in the reverse of the order that we want
# them searched, assuming that we will emit multiple "use lib"
# directives each of which *prepends* its argument to @INC.
my @dirvars = (
    { dir => 'installvendorlib', prefix => 'vendorprefix' },
    { dir => 'installvendorarch', prefix => 'vendorprefix' },
    { dir => 'installsitelib', prefix => 'siteprefix' },
    { dir => 'installsitearch', prefix => 'siteprefix' },
);

my $boilerplate = << 'EOT'
## Boilerplate added by Cyrus fixsearchpath.pl
my $__cyrus_destdir;
BEGIN {
    $__cyrus_destdir = '';
    if ($0 =~ m/\//) {
        my $d = $0;
EOT
;
$boilerplate .= "       my \$bindir = " . quote($configure_bindir) . ";\n";
$boilerplate .= << 'EOT'
        # remove the filename, $d is now the installed bindir
        $d =~ s/\/[^\/]+$//;
        # check if the path ends in the configured bindir
        my $len = length($d)-length($bindir);
        if (substr($d, $len) eq $bindir) {
            # if so then the installed destdir is what remains
            $__cyrus_destdir = substr($d, 0, $len);
        }
    }
};
EOT
;

foreach my $dv (@dirvars) {
    my $dir = $Config{$dv->{dir}};
    if ($configure_prefix ne $perl_prefix) {
        # Expect to be installed into a non-default location
        # because Cyrus was built with a non-default --prefix
        my $install_prefix = normalise($Config{$dv->{prefix}});
        $dir = $configure_prefix . substr($dir, length($install_prefix))
    }
    $boilerplate .= 'use lib $__cyrus_destdir . ' . quote($dir) .  ";\n";
}
$boilerplate .= "##\n\n";

# Filter stdin to stdout
while (<STDIN>)
{
    if (defined $boilerplate && m/^use\s/) {
        print $boilerplate;
        $boilerplate = undef;
    }
    print $_;
}
