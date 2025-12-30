use v5.28.0;
package Cassandane::TestEntity::DataType::Mailbox;

package Cassandane::TestEntity::Factory::Mailbox {
    use Moo;

    use feature 'state';

    sub fill_in_creation_defaults {
        my ($self, $prop) = @_;

        state $i = 1;
        $prop->{name} //= 'Mailbox #' . $i++;

        return;
    }

    sub inbox {
        my ($self) = @_;
        my $dt = $self->datatype;

        my $jmap = $self->user->entity_jmap;
        local $jmap->{CreatedIds}; # do not pollute the client for later use

        my $res = $jmap->request([
            [ "$dt/query", { filter => { role => 'inbox' } }, "a" ],
            [ "$dt/get", {
                '#ids' => {
                    resultOf => 'a',
                    name     => "$dt/query",
                    path     => '/ids'
                },
            } ],
        ]);

        my $get = $res->sentence(1);

        unless ($get->name eq "$dt/get"
            &&  $get->arguments->{list}->@* == 1
        ) {
            Carp::confess("failed to get $dt object for inbox role");
        }

        my $props = $get->arguments->{list}[0];
        my $id    = delete $props->{id};
        $self->instance_class->new({
            id  => $id,
            factory    => $self,
            properties => $props,
        })
    }

    use Cassandane::TestEntity::AutoSetup;

    no Moo;
}

package Cassandane::TestEntity::Instance::Mailbox {
    use Moo;

    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        name parentId role sortOrder
        totalEmails unreadEmails totalThreads unreadThreads
        myRights isSubscribed
    ) ];

    with 'Cassandane::TestEntity::Role::ShareableInstance';

    # This returns an Email::MIME object. It has some problems, but it makes it
    # easy to futz around with in testing where performance isn't really an issue.
    # (It's also what we use in the tests for all the other products, so you don't
    # need to remember what the interface of Mail::MemoryMessage or whatever is.)
    # -- michael, 2019-05-14
    my sub fake_rfc822 {
        my ($arg) = @_;
        $arg //= {};
        die "fake_rfc822 requires a 'to' argument" unless $arg->{to};

        require Email::MessageID;
        require Email::MIME;

        my $body_type = delete $arg->{body_type} // 'text/plain';

        # headers is in addition to default headers which are to, from, subject
        my $to      = $arg->{to};
        my $from    = $arg->{from} // 'Xavier Ample <x.avier.ample@example.com>';
        my $subject = $arg->{subject} // 'Test Message';

        $to = join q{, }, @$to if ref $to eq 'ARRAY';

        my @headers = (
            From => $from,
            To => $to,
            Subject => $subject,
            'Message-Id' => $arg->{message_id} ? $arg->{message_id} : Email::MessageID->new->in_brackets,
            ($arg->{headers} ? $arg->{headers}->@* : ()),
        );

        my $body_str = $arg->{body_str} // 'I am a test message.';

        if ($arg->{parts}) {
            return Email::MIME->create(
                header_str => \@headers,
                parts => [
                    Email::MIME->create(
                        body_str   => $body_str,
                        attributes => {
                            charset      => 'UTF-8',
                            content_type => $body_type,
                            encoding     => $arg->{body_encoding} // 'quoted-printable',
                        },
                    ),
                    $arg->{parts}->@*,
                ],
            );
        }

        if ($arg->{attachments}) {
            return Email::MIME->create(
                header_str => \@headers,
                attributes => {
                    content_type => 'multipart/related',
                },
                parts => [
                    Email::MIME->create(
                        body_str   => $body_str,
                        attributes => {
                            charset      => 'UTF-8',
                            content_type => $body_type,
                            encoding     => $arg->{body_encoding} // 'quoted-printable',
                        },
                    ),
                    $arg->{attachments}->@*,
                ],
            );
        }

        return Email::MIME->create(
            header_str => \@headers,
            attributes => {
                content_type => $body_type,
                charset      => 'UTF-8',
                encoding     => $arg->{body_encoding} // 'quoted-printable',
            },
            body_str   => $body_str,
        );
    }

    sub _import_message {
      my ($self, $email, $keywords) = @_;

      my $jmap  = $self->user->entity_jmap;
      my $bytes = Scalar::Util::blessed($email) ? $email->as_string : $email;
      my $upload  = $jmap->upload({
          blob => \$bytes,
          type => "message/rfc822",
          accountId => $jmap->fallback_account_id,
      });

      my $blob_id = $upload->blob_id;

      my $import_res = $jmap->request([['Email/import', {
          emails => {
              "toCreate" => {
                  blobId => $blob_id,
                  mailboxIds => { $self->id =>  JSON::true() },
                  ($keywords ? (keywords => { map {; $_ => JSON::true() } @$keywords }) : ()),
              },
          }
      }, "MailboxEntityImport"]]);

      Carp::confess("Email/import call failed") unless $import_res->sentence(0)->name eq 'Email/import';

      my $email_id = $import_res->sentence_named('Email/import')
                                ->arguments
                                ->{created}{toCreate}{id};

      unless ($email_id) {
          Carp::confess("Email/import did not import our blob");
      }

      return $email_id;
    }

    sub new_email {
        my ($self, $arg) = @_;
        $arg //= {};

        my $email = fake_rfc822({
            to   => $self->user->username,
            from => 'Xavier Ample <xa@example.com>',
            %$arg,
        });

        my $email_id = $self->_import_message($email);

        return $self->user->emails->get($email_id);
    }

    no Moo;
}

1;
