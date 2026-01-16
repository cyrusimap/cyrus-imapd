# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Replace;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return  $class->SUPER::new({adminstore => 1}, @_);
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

sub test_replace_different_mailbox
    :min_version_3_9
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my %exp;
    $exp{A} = $self->make_message("Message A", store => $self->{store});
    $self->check_messages(\%exp);

    $talk->create("INBOX.foo");
    $talk->select('INBOX');

    %exp = ();
    $exp{B} = $self->{gen}->generate(subject => "Message B", uid => 1);

    $talk->_imap_cmd('REPLACE', 0, '', "1", "INBOX.foo",
                     { Literal => $exp{B}->as_string() });
    $self->check_messages({});

    $self->{store}->set_folder("INBOX.foo");
    $self->check_messages(\%exp);
}

1;
