# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
package Cyrus::IMAPOptions::App::Command::docs;
use warnings;
use strict;

use Cyrus::IMAPOptions::App -command;

use Cwd qw(abs_path);
use File::Basename;
use File::Spec::Functions;

sub abstract { 'show imapoptions format documentation' }

sub execute
{
    my ($self, $opt, $args) = @_;

    my @cmd = split /\s+/, $ENV{PAGER} || 'less';
    push @cmd, $self->_find_readme;

    exec { $cmd[0] } @cmd;
}

sub _find_readme
{
    my ($self) = @_;

    my $readme = abs_path(catfile(dirname($self->app->full_arg0),
                                  '../lib/imapoptions/',
                                  'README.md'));

    die "$readme: not found" if not -e $readme;

    return $readme;
}

1;
