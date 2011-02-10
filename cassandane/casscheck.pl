#!/usr/bin/perl

use strict;
use warnings;
use Cassandane::Util::DateTime;
use Cassandane::Address;
use Cassandane::Message;
use Cassandane::MessageStoreFactory;

my $exp;

print "Cassandane internal tests\n";

print "    DateTime\n";
die "Woops, from_iso8601 is broken"
    unless (from_iso8601('20101014T161952Z')->epoch == 1287073192);

die "Woops, from_rfc822 is broken"
    unless (from_rfc822('Fri, 15 Oct 2010 03:19:52 +1100')->epoch == 1287073192);

die "Woops, from_rfc3501 is broken"
    unless (from_rfc3501('15-Oct-2010 03:19:52 +1100')->epoch == 1287073192);

die "Woops, to_iso8601 is broken"
    unless (to_iso8601(DateTime->from_epoch(epoch => 1287073192)) eq '20101014T161952Z');

die "Woops, to_rfc822 is broken"
    unless (to_rfc822(DateTime->from_epoch(epoch => 1287073192)) eq 'Fri, 15 Oct 2010 03:19:52 +1100');

die "Woops, to_rfc3501 is broken"
    unless (to_rfc3501(DateTime->from_epoch(epoch => 1287073192)) eq '15-Oct-2010 03:19:52 +1100');

print "    Address\n";

my $a1 = Cassandane::Address->new();
die "Woops, no-params address has bad name"
    unless !defined $a1->name;
die "Woops, no-params address has bad localpart"
    unless $a1->localpart eq 'unknown-user';
die "Woops, no-params address has bad domain"
    unless $a1->domain eq 'unspecified-domain';
die "Woops, no-params address has bad address"
    unless $a1->address eq 'unknown-user@unspecified-domain';
die "Woops, no-params address has bad as_string"
    unless $a1->as_string eq '<unknown-user@unspecified-domain>';
die "Woops, no-params address has bad as_string (2)"
    unless "" . $a1 eq '<unknown-user@unspecified-domain>';

my $a2 = Cassandane::Address->new(
	name => 'Fred J. Bloggs',
	localpart => 'fbloggs',
	domain => 'fastmail.fm',
	);
die "Woops, all-params address has bad name"
    unless $a2->name eq 'Fred J. Bloggs';
die "Woops, all-params address has bad localpart"
    unless $a2->localpart eq 'fbloggs';
die "Woops, all-params address has bad domain"
    unless $a2->domain eq 'fastmail.fm';
die "Woops, all-params address has bad address"
    unless $a2->address eq 'fbloggs@fastmail.fm';
die "Woops, all-params address has bad as_string"
    unless $a2->as_string eq 'Fred J. Bloggs <fbloggs@fastmail.fm>';
die "Woops, all-params address has bad as_string (2)"
    unless "" . $a2 eq 'Fred J. Bloggs <fbloggs@fastmail.fm>';

printf "    Message\n";
my $m1 = Cassandane::Message->new();
die "Woops, default message has a From: header"
    unless !defined $m1->get_headers('from');
die "Woops, default message has a To: header"
    unless !defined $m1->get_headers('to');
die "Woops, default message has a body"
    unless !defined $m1->get_body;
$exp = <<'EOF';

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test case sensitivity of header names
$m1->add_header('SUBJECT', 'Hello World');
die "Woops, default message has a From: header"
    unless !defined $m1->get_headers('from');
die "Woops, default message has a To: header"
    unless !defined $m1->get_headers('to');
die "Woops, default message has a body"
    unless !defined $m1->get_body;
die "Woops, default message has no SUBJECT: header"
    unless $m1->get_headers('SUBJECT')->[0] eq 'Hello World';
die "Woops, default message has no Subject: header"
    unless $m1->get_headers('Subject')->[0] eq 'Hello World';
die "Woops, default message has no subject: header"
    unless $m1->get_headers('subject')->[0] eq 'Hello World';
die "Woops, default message has no sUbJeCt: header"
    unless $m1->get_headers('sUbJeCt')->[0] eq 'Hello World';
$exp = <<'EOF';
Subject: Hello World

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test implicit stringification of Addresses when passing to headers
$m1->add_header('From', Cassandane::Address->new(
	name => 'Fred J. Bloggs',
	localpart => 'fbloggs',
	domain => 'fastmail.fm'));
die "Woops, default message has a To: header"
    unless !defined $m1->get_headers('to');
die "Woops, default message has a body"
    unless !defined $m1->get_body;
die "Woops, default message has no From: header"
    unless $m1->get_headers('from')->[0] eq 'Fred J. Bloggs <fbloggs@fastmail.fm>';
$exp = <<'EOF';
Subject: Hello World
From: Fred J. Bloggs <fbloggs@fastmail.fm>

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test stringification of a list of Addresses when passing to headers
my @tos = (
    Cassandane::Address->new(
	name => 'Sarah Jane Smith',
	localpart => 'sjsmith',
	domain => 'tard.is'),
    Cassandane::Address->new(
	name => 'Genghis Khan',
	localpart => 'gkhan',
	domain => 'horde.mo'),
    );
$m1->add_header('To', join(', ', @tos));
die "Woops, default message has a body"
    unless !defined $m1->get_body;
die "Woops, default message has no From: header"
    unless $m1->get_headers('from')->[0] eq 'Fred J. Bloggs <fbloggs@fastmail.fm>';
die "Woops, default message has no To: header"
    unless $m1->get_headers('to')->[0] eq 'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>';
$exp = <<'EOF';
Subject: Hello World
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test multiple headers with the same name
$m1->add_header("received", "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100");
$m1->add_header("received", "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100");
$m1->add_header("received", "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100");
die "Woops, default message has no Received: header"
    unless $m1->get_headers('received')->[0] eq "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100";
die "Woops, default message has no Received: header (2)"
    unless $m1->get_headers("received")->[1] eq "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100";
die "Woops, default message has no Received: header (3)"
    unless $m1->get_headers("received")->[2] eq "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100";
$exp = <<'EOF';
Subject: Hello World
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test replacing headers
$m1->set_headers('subject', 'No, scratch that');
$exp = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100
Subject: No, scratch that

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test deleting headers
$m1->remove_headers('received');
$exp = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: No, scratch that

EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test adding a body -- only plain text for now, no MIME
$m1->set_body("This is a message to let you know\r\nthat I'm alive and well\r\n");
$exp = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: No, scratch that

This is a message to let you know
that I'm alive and well
EOF
$exp =~ s/\n/\r\n/g;
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test setting lines.
my $txt = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: Hello World
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);
	Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1])
	by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by
	mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

This is a message to let you know
that I'm alive and well
EOF
my @lines = split(/\n/, $txt);
map { $_ .= "\r\n" } @lines;
$exp = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: Hello World
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

This is a message to let you know
that I'm alive and well
EOF
$exp =~ s/\n/\r\n/g;

$m1->set_lines(@lines);
die "Woops, default message has no From: header"
    unless $m1->get_headers('from')->[0] eq 'Fred J. Bloggs <fbloggs@fastmail.fm>';
die "Woops, default message has no To: header"
    unless $m1->get_headers('to')->[0] eq 'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>';
die "Woops, default message has no Subject: header"
    unless $m1->get_headers('Subject')->[0] eq 'Hello World';
die "Woops, default message has no Received: header"
    unless $m1->get_headers('received')->[0] eq "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100";
die "Woops, default message has no Received: header (2)"
    unless $m1->get_headers("received")->[1] eq "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100";
die "Woops, default message has no Received: header (3)"
    unless $m1->get_headers("received")->[2] eq "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100";
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

$m1 = Cassandane::Message->new(lines => \@lines);
die "Woops, default message has no From: header"
    unless $m1->get_headers('from')->[0] eq 'Fred J. Bloggs <fbloggs@fastmail.fm>';
die "Woops, default message has no To: header"
    unless $m1->get_headers('to')->[0] eq 'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>';
die "Woops, default message has no Subject: header"
    unless $m1->get_headers('Subject')->[0] eq 'Hello World';
die "Woops, default message has no Received: header"
    unless $m1->get_headers('received')->[0] eq "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100";
die "Woops, default message has no Received: header (2)"
    unless $m1->get_headers("received")->[1] eq "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100";
die "Woops, default message has no Received: header (3)"
    unless $m1->get_headers("received")->[2] eq "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100";
die "Woops, default message has bad as_string"
    unless $m1->as_string eq $exp;
die "Woops, default message has bad as_string (2)"
    unless "" . $m1 eq $exp;

# Test message attributes
$m1 = Cassandane::Message->new();
die "Woops, default message has uid attribute\n"
    unless !defined $m1->get_attribute('uid');
die "Woops, default message has UID attribute\n"
    unless !defined $m1->get_attribute('UID');
die "Woops, default message has uId attribute\n"
    unless !defined $m1->get_attribute('uId');
die "Woops, default message has internaldate attribute\n"
    unless !defined $m1->get_attribute('internaldate');

$m1->set_attribute('uid', 123);
die "Woops, message has no uid attribute\n"
    unless $m1->get_attribute('uid') == 123;
die "Woops, message has no UID attribute\n"
    unless $m1->get_attribute('UID') == 123;
die "Woops, message has no uId attribute\n"
    unless $m1->get_attribute('uId') == 123;
die "Woops, message has internaldate attribute\n"
    unless !defined $m1->get_attribute('internaldate');

$m1->set_attribute('uid');
die "Woops, default message has uid attribute\n"
    unless !defined $m1->get_attribute('uid');
die "Woops, default message has UID attribute\n"
    unless !defined $m1->get_attribute('UID');
die "Woops, default message has uId attribute\n"
    unless !defined $m1->get_attribute('uId');
die "Woops, default message has internaldate attribute\n"
    unless !defined $m1->get_attribute('internaldate');

$m1 = Cassandane::Message->new(attrs => { UID => 456 });
die "Woops, message has no uid attribute\n"
    unless $m1->get_attribute('uid') == 456;
die "Woops, message has no UID attribute\n"
    unless $m1->get_attribute('UID') == 456;
die "Woops, message has no uId attribute\n"
    unless $m1->get_attribute('uId') == 456;
die "Woops, message has internaldate attribute\n"
    unless !defined $m1->get_attribute('internaldate');

########################################################################
printf "    MessageStoreFactory\n";

my $ms;

# Test no args at all - default is mbox to stdout/stdin
$ms = Cassandane::MessageStoreFactory->create();
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MboxMessageStore';
die "Woops, wrong filename"
    unless !defined $ms->{filename};

# Test guessing type from single attribute, one of 'filename'
# 'directory' or 'host'.
$ms = Cassandane::MessageStoreFactory->create(filename => 'foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MboxMessageStore';
die "Woops, wrong filename"
    unless $ms->{filename} eq 'foo';

$ms = Cassandane::MessageStoreFactory->create(directory => 'foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MaildirMessageStore';
die "Woops, wrong directory"
    unless $ms->{directory} eq 'foo';

# Test creating from a URI
$ms = Cassandane::MessageStoreFactory->create(uri => 'mbox:///foo/bar');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MboxMessageStore';
die "Woops, wrong filename"
    unless $ms->{filename} eq '/foo/bar';

$ms = Cassandane::MessageStoreFactory->create(uri => 'file:///foo/bar');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MboxMessageStore';
die "Woops, wrong filename"
    unless $ms->{filename} eq '/foo/bar';

$ms = Cassandane::MessageStoreFactory->create(uri => 'maildir:///foo/bar');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MaildirMessageStore';
die "Woops, wrong directory"
    unless $ms->{directory} eq '/foo/bar';

$ms = Cassandane::MessageStoreFactory->create(uri => 'imap://victoria:secret@foo.com:9143/inbox.foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::IMAPMessageStore';
die "Woops, wrong username"
    unless $ms->{username} eq 'victoria';
die "Woops, wrong password"
    unless $ms->{password} eq 'secret';
die "Woops, wrong host"
    unless $ms->{host} eq 'foo.com';
die "Woops, wrong port"
    unless $ms->{port} == 9143;
die "Woops, wrong folder"
    unless $ms->{folder} eq 'inbox.foo';

$ms = Cassandane::MessageStoreFactory->create(uri => 'imap://victoria@foo.com:9143/inbox.foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::IMAPMessageStore';
die "Woops, wrong username"
    unless $ms->{username} eq 'victoria';
die "Woops, wrong password"
    unless !defined $ms->{password};
die "Woops, wrong host"
    unless $ms->{host} eq 'foo.com';
die "Woops, wrong port"
    unless $ms->{port} == 9143;
die "Woops, wrong folder"
    unless $ms->{folder} eq 'inbox.foo';

$ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com:9143/inbox.foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::IMAPMessageStore';
die "Woops, wrong username"
    unless !defined $ms->{username};
die "Woops, wrong password"
    unless !defined $ms->{password};
die "Woops, wrong host"
    unless $ms->{host} eq 'foo.com';
die "Woops, wrong port"
    unless $ms->{port} == 9143;
die "Woops, wrong folder"
    unless $ms->{folder} eq 'inbox.foo';

$ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com/inbox.foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::IMAPMessageStore';
die "Woops, wrong username"
    unless !defined $ms->{username};
die "Woops, wrong password"
    unless !defined $ms->{password};
die "Woops, wrong host"
    unless $ms->{host} eq 'foo.com';
die "Woops, wrong port"
    unless $ms->{port} == 143;
die "Woops, wrong folder"
    unless $ms->{folder} eq 'inbox.foo';

$ms = Cassandane::MessageStoreFactory->create(uri => 'imap://foo.com/');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::IMAPMessageStore';
die "Woops, wrong username"
    unless !defined $ms->{username};
die "Woops, wrong password"
    unless !defined $ms->{password};
die "Woops, wrong host"
    unless $ms->{host} eq 'foo.com';
die "Woops, wrong port"
    unless $ms->{port} == 143;
die "Woops, wrong folder"
    unless $ms->{folder} eq 'INBOX';

# Test creation with the 'path' and 'type' attribute - default
# arguments for genmail3.pl
$ms = Cassandane::MessageStoreFactory->create(path => 'foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MboxMessageStore';
die "Woops, wrong filename"
    unless $ms->{filename} eq 'foo';

$ms = Cassandane::MessageStoreFactory->create(type => 'mbox', path => 'foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MboxMessageStore';
die "Woops, wrong filename"
    unless $ms->{filename} eq 'foo';

$ms = Cassandane::MessageStoreFactory->create(type => 'maildir', path => 'foo');
die "Woops, wrong type"
    unless ref $ms eq 'Cassandane::MaildirMessageStore';
die "Woops, wrong directory"
    unless $ms->{directory} eq 'foo';


########################################################################
print "All tests passed\n";
