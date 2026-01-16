# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::T116;
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

Cassandane::Cyrus::TestCase::magic(T116 => sub {
    my ($testcase) = @_;
    $testcase->config_set(virtdomains => 'userid');
});

sub test_list_inbox
    :T116
{
    my ($self) = @_;
    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    xlog $self, "Test Cyrus extension which renames a user to a different partition";

    # create and prepare the user
    $admintalk->create('user.test@inbox.com');
    $admintalk->setacl('user.test@inbox.com', 'admin', 'lrswipkxtecda');

    $admintalk->create('user.test@inbox2.com');
    $admintalk->setacl('user.test@inbox2.com', 'admin', 'lrswipkxtecda');

    my @list = $admintalk->list('', '*');
    my @items = sort map { $_->[2] } @list;
    $self->assert_deep_equals(\@items, ['user.cassandane', 'user.test@inbox.com', 'user.test@inbox2.com']);
}

1;
