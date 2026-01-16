# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::List;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

    return $class->SUPER::new({ config => $config, adminstore => 1 }, @args);
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

# tests based on rfc 5258 examples:
# https://tools.ietf.org/html/rfc5258#section-5

# TODO not sure how to set up test data for remote mailboxes...
#sub test_rfc5258_ex04_remote_children
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex05_remote_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex06_remote_return_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex09_childinfo
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex10_multiple_mailbox_patterns_childinfo
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

#sub test_rfc5258_ex11_missing_hierarchy_elements
#{
#    my ($self) = @_;
#    $self->assert(0, 'XXX test not implemented');
#}

# tests based on rfc 6154 examples:
# https://tools.ietf.org/html/rfc6154#section-5

# "An IMAP server that supports this extension MAY include any or all of the
# following attributes in responses to the non-extended IMAP LIST command."
#
# Cyrus does not (at least, not at the moment), so this test is disabled.
sub bogus_test_rfc6154_ex01_list_non_extended
    :UnixHierarchySep :AltNamespace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $self->setup_mailbox_structure($imaptalk, [
        [ 'create' => [qw( ToDo Projects Projects/Foo SentMail MyDrafts Trash) ] ],
    ]);

    $imaptalk->setmetadata("SentMail", "/private/specialuse", "\\Sent");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    $imaptalk->setmetadata("MyDrafts", "/private/specialuse", "\\Drafts");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    $imaptalk->setmetadata("Trash", "/private/specialuse", "\\Trash");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    my $alldata = $imaptalk->list("", "%");

    $self->assert_mailbox_structure($alldata, '/', {
        'INBOX'                 => [qw( \\HasNoChildren )],
        'ToDo'                  => [qw( \\HasNoChildren )],
        'Projects'              => [qw( \\HasChildren )],
        'SentMail'              => [qw( \\Sent \\HasNoChildren )],
        'MyDrafts'              => [qw( \\Drafts \\HasNoChildren )],
        'Trash'                 => [qw( \\Trash \\HasNoChildren )],
    });
}

use Cassandane::Tiny::Loader 'tiny-tests/List';

1;
