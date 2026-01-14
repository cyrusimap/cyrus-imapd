# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Delete;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use File::Basename;

sub new
{
    my ($class, @args) = @_;

    my $buildinfo = Cassandane::BuildInfo->new();

    if ($buildinfo->get('component', 'httpd')) {
        my $config = Cassandane::Config->default()->clone();

        $config->set(conversations => 'yes',
                     httpmodules => 'carddav caldav');

        return $class->SUPER::new({
            config => $config,
            jmap => 1,
            adminstore => 1,
            services => [ 'imap', 'http', 'sieve' ]
        }, @args);
    }
    else {
        return $class->SUPER::new({ adminstore => 1 }, @args);
    }
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub check_folder_ondisk
{
    my ($self, $folder, %params) = @_;

    my $instance = delete $params{instance} || $self->{instance};
    my $deleted = delete $params{deleted} || 0;
    my $exp = delete $params{expected};
    die "Bad params: " . join(' ', keys %params)
        if scalar %params;

    my $display_folder = ($deleted ? "DELETED " : "") . $folder;
    xlog $self, "Checking that $display_folder exists on disk";

    my $dir;
    if ($deleted)
    {
        my @dirs = $instance->folder_to_deleted_directories($folder);
        $self->assert_equals(1, scalar(@dirs),
                             "too many directories for $display_folder");
        $dir = shift @dirs;
    }
    else
    {
        $dir = $instance->folder_to_directory($folder);
    }

    $self->assert_not_null($dir,
                           "directory missing for $display_folder");
    $self->assert( -f "$dir/cyrus.header",
                   "cyrus.header missing for $display_folder");
    $self->assert( -f "$dir/cyrus.index",
                   "cyrus.index missing for $display_folder");

    if (defined $exp)
    {
        map
        {
            my $uid = $_->uid();
            $self->assert( -f "$dir/$uid.",
                           "message $uid missing for $display_folder");
        } values %$exp;
    }
}

sub check_folder_not_ondisk
{
    my ($self, $folder, %params) = @_;

    my $instance = delete $params{instance} || $self->{instance};
    my $deleted = delete $params{deleted} || 0;
    die "Bad params: " . join(' ', keys %params)
        if scalar %params;

    my $display_folder = ($deleted ? "DELETED " : "") . $folder;
    xlog $self, "Checking that $display_folder does not exist on disk";

    if ($deleted)
    {
        my @dirs = $instance->folder_to_deleted_directories($folder);
        $self->assert_equals(0, scalar(@dirs),
                             "directory unexpectedly present for $display_folder");
    }
    else
    {
        my $dir = $instance->folder_to_directory($folder);
        $self->assert_null($dir,
                           "directory unexpectedly present for $display_folder");
    }
}

sub check_syslog
{
    my ($self, $instance) = @_;

    my $remove_empty_pat = qr/Remove of supposedly empty directory/;

    $self->assert_null($instance->_check_syslog($remove_empty_pat));
}

use Cassandane::Tiny::Loader;

1;
