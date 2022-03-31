#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::JMAPEmailSubmission;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);
use URI;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 jmapsubmission_deleteonsend => 'no',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
    ]);
}


sub getinbox
{
    my ($self, $args) = @_;

    $args = {} unless $args;

    my $jmap = $self->{jmap};

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', $args, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}

sub test_emailsubmission_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
            }
       }
    }, "R1" ] ] );
    my $msgsubid = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($msgsubid);

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);

    xlog $self, "get email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/get', {
        ids => [ $msgsubid ],
    }, "R1" ] ] );
    $self->assert_str_equals($msgsubid, $res->[0][1]->{list}[0]{id});

    xlog $self, "update email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        update => {
            $msgsubid => {
                undoStatus => 'canceled',
            }
       }
    }, "R1" ] ] );
    $self->assert_str_equals('cannotUnsend', $res->[0][1]->{notUpdated}{$msgsubid}{type});

    xlog $self, "destroy email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        destroy => [ $msgsubid ],
    }, "R1" ] ] );
    $self->assert_str_equals($msgsubid, $res->[0][1]->{destroyed}[0]);

    xlog $self, "make sure #jmapsubmission folder isn't visible via IMAP";
    my $talk = $self->{store}->get_client();
    my @list = $talk->list('', '*');
    $self->assert_num_equals(0, scalar grep { $_->[2] eq 'INBOX.#jmapsubmission' } @list);
}

sub test_emailsubmission_set_with_envelope
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $msgsubid = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($msgsubid);

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_set_futurerelease
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submissions";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => "30",
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '2' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => "30",
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $msgsubid1 = $res->[0][1]->{created}{1}{id};
    my $msgsubid2 = $res->[0][1]->{created}{2}{id};
    $self->assert_not_null($msgsubid1);
    $self->assert_not_null($msgsubid2);

    xlog $self, "event were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(2, scalar @$alarmdata);

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => undef }, "R2"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});
    $self->assert_str_equals('pending', $res->[0][1]->{list}[0]->{undoStatus});
    $self->assert_str_equals('pending', $res->[0][1]->{list}[1]->{undoStatus});
    my $state = $res->[0][1]->{state};

    xlog $self, "cancel first email submission";
    $res = $jmap->CallMethods([
        ['EmailSubmission/set', {
            update => { $msgsubid1 => {
                "undoStatus" => "canceled",
            }},
        }, 'R3'],
    ]);

    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    xlog $self, "one event left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => [ $msgsubid1 ] }, "R4"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});
    $self->assert_str_equals('canceled', $res->[0][1]->{list}[0]->{undoStatus});

    xlog $self, "destroy first email submission";
    $res = $jmap->CallMethods([
        ['EmailSubmission/set', {
            destroy => [ $msgsubid1 ]
        }, 'R5'],
    ]);

    $self->assert_not_null($res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{notDestroyed});

    xlog $self, "one event left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => undef }, "R6"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});

    xlog $self, "set up a send block";
    $self->{instance}->set_smtpd({ begin_data => ["451", "4.3.0 [jmapError:forbiddenToSend] try later"] });

    xlog $self, "attempt delivery of the second email";
    my $now = DateTime->now();
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    xlog $self, "still pending";
    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => [ $msgsubid2 ] }, "R7"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});
    $self->assert_str_equals('pending', $res->[0][1]->{list}[0]->{undoStatus});

    xlog $self, "one event left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);

    xlog $self, "clear the send block";
    $self->{instance}->set_smtpd();

    xlog $self, "trigger delivery of second email submission";
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 600 );

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => [ $msgsubid2 ] }, "R7"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});
    $self->assert_str_equals('final', $res->[0][1]->{list}[0]->{undoStatus});

    xlog $self, "no events left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);

    xlog $self, "attempt to cancel second email submission (should fail)";
    $res = $jmap->CallMethods([
        ['EmailSubmission/set', {
            update => { $msgsubid2 => {
                "undoStatus" => "canceled",
            }},
        }, 'R8'],
    ]);

    $self->assert_null($res->[0][1]{updated});
    $self->assert_not_null($res->[0][1]{notUpdated});
}

sub test_emailsubmission_set_bad_futurerelease
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submissions";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => JSON::null
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '2' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => ""
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '3' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => " "
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '4' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => "30a"
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '5' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holduntil" => undef
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '6' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holduntil" => []
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '7' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holduntil" => ""
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $errType = $res->[0][1]->{notCreated}{1}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $errType = $res->[0][1]->{notCreated}{2}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $errType = $res->[0][1]->{notCreated}{3}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $errType = $res->[0][1]->{notCreated}{4}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $errType = $res->[0][1]->{notCreated}{5}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $errType = $res->[0][1]->{notCreated}{6}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $errType = $res->[0][1]->{notCreated}{7}{type};
    $self->assert_str_equals("invalidProperties", $errType);
}

sub test_replication_emailsubmission_set_futurerelease
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submissions";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => "30",
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            },
            '2' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                        parameters => {
                            "holdfor" => "30",
                        }
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $msgsubid1 = $res->[0][1]->{created}{1}{id};
    my $msgsubid2 = $res->[0][1]->{created}{2}{id};
    $self->assert_not_null($msgsubid1);
    $self->assert_not_null($msgsubid2);

    xlog $self, "events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(2, scalar @$alarmdata);

    xlog $self, "events aren't in replica alarmdb yet";
    my $replicadata = $self->{replica}->getalarmdb();
    $self->assert_num_equals(0, scalar @$replicadata);

    $self->run_replication();

    xlog $self, "events are still in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(2, scalar @$alarmdata);

    xlog $self, "events are now in replica alarmdb";
    $replicadata = $self->{replica}->getalarmdb();
    $self->assert_num_equals(2, scalar @$replicadata);

    xlog $self, "cancel first email submission";
    $res = $jmap->CallMethods([
        ['EmailSubmission/set', {
            update => { $msgsubid1 => {
                "undoStatus" => "canceled",
            }},
        }, 'R3'],
    ]);

    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    xlog $self, "one event left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);

    $self->run_replication();

    xlog $self, "one event left in the alarmdb";
    $replicadata = $self->{replica}->getalarmdb();
    $self->assert_num_equals(1, scalar @$replicadata);

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => [ $msgsubid1 ] }, "R4"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});
    $self->assert_str_equals('canceled', $res->[0][1]->{list}[0]->{undoStatus});

    xlog $self, "destroy first email submission";
    $res = $jmap->CallMethods([
        ['EmailSubmission/set', {
            destroy => [ $msgsubid1 ]
        }, 'R5'],
    ]);

    $self->assert_not_null($res->[0][1]{destroyed});
    $self->assert_null($res->[0][1]{notDestroyed});

    xlog $self, "one event left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => undef }, "R6"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});

    xlog $self, "trigger delivery of second email submission";
    my $now = DateTime->now();
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 120 );

    $res = $jmap->CallMethods([['EmailSubmission/get', { ids => [ $msgsubid2 ] }, "R7"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});
    $self->assert_str_equals('final', $res->[0][1]->{list}[0]->{undoStatus});

    xlog $self, "no events left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);

    $self->run_replication();

    xlog $self, "no replica events left in the alarmdb";
    $replicadata = $self->{replica}->getalarmdb();
    $self->assert_num_equals(0, scalar @$replicadata);
}

sub test_emailsubmission_set_creationid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityId = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityId);

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    $res = $jmap->CallMethods([
        ['Mailbox/get', { properties => ['name'], }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{A}->{id};
    my $mboxIdB = $mboxByName{B}->{id};

    xlog $self, "create, send and update email";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'm1' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'hello',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'world',
                        }
                    },
                },
            },
        }, 'R1'],
        [ 'EmailSubmission/set', {
            create => {
                's1' => {
                    identityId => $identityId,
                    emailId  => '#m1',
                }
           },
           onSuccessUpdateEmail => {
               '#s1' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
               },
           },
        }, 'R2' ],
        [ 'Email/get', {
            ids => ['#m1'],
            properties => ['mailboxIds'],
        }, 'R3'],
    ]);
    my $emailId = $res->[0][1]->{created}{m1}{id};
    $self->assert_not_null($emailId);
    my $msgSubId = $res->[1][1]->{created}{s1}{id};
    $self->assert_not_null($msgSubId);
    $self->assert(exists $res->[2][1]{updated}{$emailId});
    $self->assert_num_equals(1, scalar keys %{$res->[3][1]{list}[0]{mailboxIds}});
    $self->assert(exists $res->[3][1]{list}[0]{mailboxIds}{$mboxIdB});

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_cancel_creation
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityId = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityId);

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    $res = $jmap->CallMethods([
        ['Mailbox/get', { properties => ['name'], }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{A}->{id};
    my $mboxIdB = $mboxByName{B}->{id};

    xlog $self, "create, send and update email";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'm1' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'hello',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'world',
                        }
                    },
                },
            },
        }, 'R1'],
        [ 'EmailSubmission/set', {
            create => {
                's1' => {
                    identityId => $identityId,
                    emailId  => '#m1',
                    envelope => {
                        mailFrom => {
                            email => 'foo@local',
                            parameters => {
                                "holdfor" => "30",
                            }
                        },
                        rcptTo => [{
                            email => 'bar@local',
                        }],
                    },
                },
           },
           onSuccessUpdateEmail => {
               '#s1' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
               },
           },
        }, 'R2' ],
        [ 'Email/get', {
            ids => ['#m1'],
            properties => ['mailboxIds'],
        }, 'R3'],
    ]);

    xlog $self, "event gets added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);

    my $emailId = $res->[0][1]->{created}{m1}{id};
    $self->assert_not_null($emailId);
    my $msgSubId = $res->[1][1]->{created}{s1}{id};
    $self->assert_not_null($msgSubId);
    $self->assert(exists $res->[2][1]{updated}{$emailId});
    $self->assert_num_equals(1, scalar keys %{$res->[3][1]{list}[0]{mailboxIds}});
    $self->assert(exists $res->[3][1]{list}[0]{mailboxIds}{$mboxIdB});

    xlog $self, "cancel the send and revert the mailbox";
    $res = $jmap->CallMethods([
        [ 'EmailSubmission/set', {
            update => {
                $msgSubId => {
                    undoStatus => 'canceled',
                }
            },
            onSuccessUpdateEmail => {
                $msgSubId => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                },
            },
        }, 'R2' ],
        [ 'Email/get', {
            ids => [$emailId],
            properties => ['mailboxIds'],
        }, 'R3'],
    ]);

    $self->assert(exists $res->[0][1]{updated}{$msgSubId});
    $self->assert(exists $res->[1][1]{updated}{$emailId});
    $self->assert_num_equals(1, scalar keys %{$res->[2][1]{list}[0]{mailboxIds}});
    $self->assert(exists $res->[2][1]{list}[0]{mailboxIds}{$mboxIdA});

    xlog $self, "event is no longer in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);

    xlog $self, "destroy and destroy the email too";
    $res = $jmap->CallMethods([
        [ 'EmailSubmission/set', {
            destroy => [$msgSubId],
            onSuccessDestroyEmail => [$msgSubId],
        }, 'R2' ],
        [ 'Email/get', {
            ids => [$emailId],
            properties => ['mailboxIds'],
        }, 'R3'],
    ]);

    $self->assert_str_equals($msgSubId, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($emailId, $res->[1][1]{destroyed}[0]);
    $self->assert_str_equals($emailId, $res->[2][1]{notFound}[0]);
}

sub test_emailsubmission_set_smtp_rejection
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwith 11 recipients\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    $self->{instance}->set_smtpd({ begin_data => ["554", "5.3.0 [jmapError:forbiddenToSend] bad egg"] });

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $errType = $res->[0][1]->{notCreated}{1}{type};
    $self->assert_str_equals("forbiddenToSend", $errType);
    $self->assert_str_equals("bad egg", $res->[0][1]->{notCreated}{1}{description});

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_set_too_many_recipients
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwith 11 recipients\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }, {
                        email => 'rcpt3@localhost',
                    }, {
                        email => 'rcpt4@localhost',
                    }, {
                        email => 'rcpt5@localhost',
                    }, {
                        email => 'rcpt6@localhost',
                    }, {
                        email => 'rcpt7@localhost',
                    }, {
                        email => 'rcpt8@localhost',
                    }, {
                        email => 'rcpt9@localhost',
                    }, {
                        email => 'rcpt10@localhost',
                    }, {
                        email => 'rcpt11@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $errType = $res->[0][1]->{notCreated}{1}{type};
    $self->assert_str_equals("tooManyRecipients", $errType);

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_set_fail_some_recipients
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwith 10 recipients\r\n") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }, {
                        email => 'rcpt2@localhost',
                    }, {
                        email => 'rcpt3@fail.to.deliver',
                    }, {
                        email => 'rcpt4@localhost',
                    }, {
                        email => 'rcpt5@fail.to.deliver',
                    }, {
                        email => 'rcpt6@fail.to.deliver',
                    }, {
                        email => 'rcpt7@localhost',
                    }, {
                        email => 'rcpt8@localhost',
                    }, {
                        email => 'rcpt9@fail.to.deliver',
                    }, {
                        email => 'rcpt10@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $errType = $res->[0][1]->{notCreated}{1}{type};
    $self->assert_str_equals("invalidRecipients", $errType);

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_set_message_too_large
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "Generate a email via IMAP";
    my $x = "x";
    $self->make_message("foo", body => "a email\r\nwith 10k+ octet body\r\n" . $x x 10000) or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
                envelope => {
                    mailFrom => {
                        email => 'from@localhost',
                    },
                    rcptTo => [{
                        email => 'rcpt1@localhost',
                    }],
                },
            }
       }
    }, "R1" ] ] );
    my $errType = $res->[0][1]->{notCreated}{1}{type};
    $self->assert_str_equals("tooLarge", $errType);

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_set_issue2285
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Create email";
    $res = $jmap->CallMethods([
    [ 'Email/set', {
        create => {
            'k40' => {
                'bcc' => undef,
                'cc' => undef,
                'attachments' => undef,
                'subject' => 'zlskdjgh',
                'keywords' => {
                    '$Seen' => JSON::true,
                    '$Draft' => JSON::true
                },
                textBody => [{partId => '1'}],
                bodyValues => { '1' => { value => 'lsdkgjh' }},
                'to' => [
                    {
                        'email' => 'foo@bar.com',
                        'name' => ''
                    }
                ],
                'from' => [
                    {
                        'email' => 'fooalias1@robmtest.vm',
                        'name' => 'some name'
                    }
                ],
                'receivedAt' => '2018-03-06T03:49:04Z',
                'mailboxIds' => {
                    $inboxid => JSON::true,
                },
            }
        }
    }, "R1" ],
    [ 'EmailSubmission/set', {
        create => {
            'k41' => {
                identityId => $identityid,
                emailId  => '#k40',
                envelope => undef,
            },
        },
        onSuccessDestroyEmail => [ '#k41' ],
    }, "R2" ] ] );
    $self->assert_str_equals('EmailSubmission/set', $res->[1][0]);
    $self->assert_not_null($res->[1][1]->{created}{'k41'}{id});
    $self->assert_str_equals('R2', $res->[1][2]);
    $self->assert_str_equals('Email/set', $res->[2][0]);
    $self->assert_not_null($res->[2][1]->{destroyed}[0]);
    $self->assert_str_equals('R2', $res->[2][2]);

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "get current email submission state";
    $res = $jmap->CallMethods([['EmailSubmission/get', { }, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog $self, "get email submission updates";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/changes', {
        sinceState => $state,
    }, "R1" ] ] );
    $self->assert_deep_equals([], $res->[0][1]->{created});
    $self->assert_deep_equals([], $res->[0][1]->{updated});
    $self->assert_deep_equals([], $res->[0][1]->{destroyed});

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email") or die;

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission but don't update state";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
            }
       }
    }, "R1" ] ] );
    my $subid = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($subid);

    xlog $self, "get email submission updates";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/changes', {
        sinceState => $state,
    }, "R1" ] ] );
    $self->assert_deep_equals([$subid], $res->[0][1]->{created});
    $self->assert_deep_equals([], $res->[0][1]->{updated});
    $self->assert_deep_equals([], $res->[0][1]->{destroyed});

    xlog $self, "no events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}

sub test_emailsubmission_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "get email submission list (no arguments)";
    my $res = $jmap->CallMethods([['EmailSubmission/query', { }, "R1"]]);
    $self->assert_null($res->[0][1]{filter});
    $self->assert_null($res->[0][1]{sort});
    $self->assert_not_null($res->[0][1]{queryState});
    $self->assert_equals(JSON::false, $res->[0][1]{canCalculateChanges});
    $self->assert_num_equals(0, $res->[0][1]{position});
    $self->assert_num_equals(0, $res->[0][1]{total});
    $self->assert_not_null($res->[0][1]{ids});

    xlog $self, "get email submission list (error arguments)";
    $res = $jmap->CallMethods([['EmailSubmission/query', { filter => 1 }, "R1"]]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
}

sub test_emailsubmission_querychanges
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "get current email submission state";
    my $res = $jmap->CallMethods([['EmailSubmission/query', { }, "R1"]]);
    my $state = $res->[0][1]->{queryState};
    $self->assert_not_null($state);

    xlog $self, "get email submission list updates (empty filter)";
    $res = $jmap->CallMethods([['EmailSubmission/queryChanges', {
        filter => {},
        sinceQueryState => $state,
    }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("cannotCalculateChanges", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);
}

sub test_emailsubmission_onsuccess_invalid_subids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "set email submission with invalid submission ids";
    my $res = $jmap->CallMethods([['EmailSubmission/set', {
        onSuccessUpdateEmail => {
            'foo' => { mailboxIds => { 'INBOX' => JSON::true } } },
        onSuccessDestroyEmail => [ 'bar' ]
    }, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);
}

sub test_emailsubmission_onsuccess_not_using
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get identity id";
    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityid);

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $emailid = $res->[0][1]->{ids}[0];

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $emailid,
            }
        },
        onSuccessDestroyEmail => [ '1' ],
    }, "R1"]], ['urn:ietf:params:jmap:submission']);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("invalidArguments", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);
}

sub test_emailsubmission_scheduled_send
    :min_version_3_7 :needs_component_jmap :needs_component_calalarmd
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Create Drafts, Scheduled, and Sent mailboxes";
    my $res = $jmap->CallMethods([
        [ 'Identity/get', {}, "R0" ],
        [ 'Mailbox/set', {
            create => {
                "1" => {
                    name => "Drafts",
                    role => "drafts"
                },
                "2" => {
                    name => "Scheduled",
                    role => "scheduled"
                },
                "3" => {
                    name => "Sent",
                    role => "sent"
                }
            }
         }, "R1"],
    ]);
    my $identityid = $res->[0][1]->{list}[0]->{id};
    my $draftsid = $res->[1][1]{created}{"1"}{id};
    my $schedid = $res->[1][1]{created}{"2"}{id};
    my $sentid = $res->[1][1]{created}{"3"}{id};


    xlog $self, "Verify Scheduled mailbox rights";
    my $myRights = $res->[1][1]{created}{"2"}{myRights};
    $self->assert_deep_equals({
        mayReadItems => JSON::true,
        mayAddItems => JSON::false,
        mayRemoveItems => JSON::false,
        mayCreateChild => JSON::false,
        mayDelete => JSON::false,
        maySubmit => JSON::false,
        maySetSeen => JSON::true,
        maySetKeywords => JSON::true,
        mayAdmin => JSON::false,
        mayRename => JSON::false
    }, $myRights);


    xlog $self, "Try to create a child of Scheduled mailbox";
    $res = $jmap->CallMethods([
        [ 'Mailbox/set', {
            create => {
                "1" => {
                    name => "foo",
                    parentId => "$schedid"
                }
            }
         }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]->{notCreated}{1});


    xlog $self, "Try to destroy Scheduled mailbox";
    $res = $jmap->CallMethods([
        [ 'Mailbox/set', {
            destroy => [ "$schedid" ]
         }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]->{notDestroyed}{$schedid});


    xlog $self, "Create 2 draft emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'm1' => {
                    mailboxIds => {
                        $draftsid => JSON::true,
                    },
                    keywords => {
                        '$draft' => JSON::true,
                    },
                    from => [{
                        name => '', email => 'cassandane@local'
                    }],
                    to => [{
                        name => '', email => 'foo@local'
                    }],
                    subject => 'foo',
                },
                'm2' => {
                    mailboxIds => {
                        $draftsid => JSON::true,
                    },
                    keywords => {
                        '$draft' => JSON::true,
                    },
                    from => [{
                        name => '', email => 'cassandane@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'bar',
                },
            },
        }, 'R1'],
    ]);
    my $emailid1 = $res->[0][1]->{created}{m1}{id};
    my $emailid2 = $res->[0][1]->{created}{m2}{id};


    xlog $self, "Create 2 email submissions";
    $res = $jmap->CallMethods( [
        [ 'EmailSubmission/set', {
            create => {
                '1' => {
                    identityId => $identityid,
                    emailId  => $emailid1,
                    envelope => {
                        mailFrom => {
                            email => 'from@localhost',
                            parameters => {
                                "holdfor" => "30",
                            }
                        },
                        rcptTo => [
                            {
                                email => 'rcpt1@localhost',
                            }],
                    },
                    onSend => {
                        moveToMailboxId => $sentid,
                        setKeywords => { '$Sent' => $JSON::true },
                    }
                },
                '2' => {
                    identityId => $identityid,
                    emailId  => $emailid2,
                    envelope => {
                        mailFrom => {
                            email => 'from@localhost',
                            parameters => {
                                "holdfor" => "30",
                            }
                        },
                        rcptTo => [
                            {
                                email => 'rcpt2@localhost',
                            }],
                    },
                    onSend => {
                        moveToMailboxId => $sentid,
                        setKeywords => { '$Sent' => $JSON::true },
                    }
                }
            },
            onSuccessUpdateEmail => {
                '#1' => {
                    "mailboxIds/$draftsid" => JSON::null,
                    "mailboxIds/$schedid" => $JSON::true,
                    'keywords/$Draft' =>  JSON::null
                },
                '#2' => {
                    "mailboxIds/$draftsid" => JSON::null,
                    "mailboxIds/$schedid" => $JSON::true,
                    'keywords/$Draft' =>  JSON::null
                }
            }
        }, "R1" ],
        [ "Email/get", {
            ids => ["$emailid1"],
            properties => ["mailboxIds", "keywords"],
        }, "R2"],
    ] );


    xlog $self, "Check create and onSuccessUpdateEmail results";
    my $msgsubid1 = $res->[0][1]->{created}{1}{id};
    my $msgsubid2 = $res->[0][1]->{created}{2}{id};
    $self->assert_str_equals('pending', $res->[0][1]->{created}{1}{undoStatus});

    $self->assert_equals(JSON::null, $res->[1][1]->{updated}{emailid1});

    $self->assert_equals(JSON::true,
                         $res->[2][1]->{list}[0]->{mailboxIds}{$schedid});
    $self->assert_null($res->[2][1]->{list}[0]->{mailboxIds}{$draftsid});


    xlog $self, "Verify 2 events were added to the alarmdb";
    my $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(2, scalar @$alarmdata);


    xlog $self, "Cancel email submission 2";
    $res = $jmap->CallMethods( [
        [ 'EmailSubmission/set', {
            update => {
                $msgsubid2 => {
                    undoStatus => 'canceled',
                }
            },
            onSuccessUpdateEmail => {
                $msgsubid2 => {
                    mailboxIds => {
                        "$draftsid" => JSON::true
                    },
                    keywords => {
                        '$Draft' =>  JSON::true
                    }
                }
            }
         }, "R1" ],
        [ "Email/get", {
            ids => ["$emailid2"],
            properties => ["mailboxIds", "keywords"],
        }, "R2"],
    ] );


    xlog $self, "Check update and onSuccessUpdateEmail results";
    $self->assert_not_null($res->[0][1]->{updated}{$msgsubid2});

    $self->assert_equals(JSON::null, $res->[1][1]->{updated}{emailid2});

    $self->assert_equals(JSON::true,
                         $res->[2][1]->{list}[0]->{keywords}{'$draft'});
    $self->assert_equals(JSON::true,
                         $res->[2][1]->{list}[0]->{mailboxIds}{$draftsid});
    $self->assert_null($res->[2][1]->{list}[0]->{mailboxIds}{$schedid});

    
    xlog $self, "Verify an event was removed from the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(1, scalar @$alarmdata);


    xlog $self, "Trigger delivery of email submission";
    my $now = DateTime->now();
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $now->epoch() + 60 );


    xlog $self, "Check onSend results";
    $res = $jmap->CallMethods( [
        [ 'EmailSubmission/get', {
            ids => [ $msgsubid1 ]
        }, "R1"],
        [ "Email/get", {
            ids => ["$emailid1"],
            properties => ["mailboxIds", "keywords"],
        }, "R2"],
    ] );
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_str_equals('final', $res->[0][1]->{list}[0]->{undoStatus});

    $self->assert_equals(JSON::true,
                         $res->[1][1]->{list}[0]->{mailboxIds}{$sentid});
    $self->assert_null($res->[1][1]->{list}[0]->{mailboxIds}{$schedid});

    $self->assert_equals(JSON::true,
                         $res->[1][1]->{list}[0]->{keywords}{'$sent'});
    $self->assert_equals(JSON::null,
                         $res->[1][1]->{list}[0]->{keywords}{'$draft'});


    xlog $self, "Verify no events left in the alarmdb";
    $alarmdata = $self->{instance}->getalarmdb();
    $self->assert_num_equals(0, scalar @$alarmdata);
}


1;
