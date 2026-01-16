# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Bug3649;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

sub test_delete_subuser
{
    my ($self) = @_;
    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    xlog $self, "Test Cyrus extension which renames a user to a different partition";

    # create and prepare the user
    $self->{instance}->create_user('admin1');
    $adminstore->set_folder('user.admin1');
    for ('A'..'Z') {
        $self->make_message("Message $_", store => $adminstore);
    }
    $admintalk->unselect();

    $admintalk->delete('user.admin1');
}

1;
