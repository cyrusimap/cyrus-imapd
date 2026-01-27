# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::MessageStoreFactory;
use strict;
use warnings;
use Mail::IMAPTalk;
use URI;
use URI::Escape qw(uri_unescape);
use Exporter ();

use Cassandane::MboxMessageStore;
use Cassandane::MaildirMessageStore;
use Cassandane::IMAPMessageStore;
use Cassandane::POP3MessageStore;

our @ISA = qw(Exporter);
our @EXPORT = qw(create);

our %fmethods =
(
    mbox => sub { return Cassandane::MboxMessageStore->new(@_); },
    maildir => sub { return Cassandane::MaildirMessageStore->new(@_); },
    imap => sub { return Cassandane::IMAPMessageStore->new(@_); },
    imaps => sub { return Cassandane::IMAPMessageStore->new(@_, ssl => 1); },
    pop3 => sub { return Cassandane::POP3MessageStore->new(@_); },
);

our %cleanups =
(
    mbox => sub
    {
        my ($params) = @_;
        if (defined $params->{path})
        {
            $params->{filename} = $params->{path};
            delete $params->{path};
        }
    },
    maildir => sub
    {
        my ($params) = @_;
        if (defined $params->{path})
        {
            $params->{directory} = $params->{path};
            delete $params->{path};
        }
    }
);

our %uriparsers =
(
    file => sub
    {
        my ($uri, $params) = @_;
        $params->{filename} = $uri->file();
        return 'mbox';
    },
    mbox => sub
    {
        my ($uri, $params) = @_;
        $params->{filename} = $uri->path();
        return 'mbox';
    },
    maildir => sub
    {
        my ($uri, $params) = @_;
        $params->{directory} = $uri->path();
        return 'maildir';
    },
    imap => sub
    {
        my ($uri, $params) = @_;

        # The URI module doesn't know how to parse imap: URIs.
        # But it does know how to parse pop: URIs, and those
        # are sufficiently close to work for us (as we ignore
        # the special UIDVALIDITY and TYPE stuff anyway).  So
        # hackily recreate the URI object.
        my $u = "" . $uri;
        $u =~ s/^imap:/pop:/;
        $uri = URI->new($u);

        $params->{host} = $uri->host();
        $uri->_port() and $params->{port} = 0 + $uri->_port();
        if ($uri->userinfo())
        {
            my ($u, $p) = split(/:/, $uri->userinfo());
            $params->{username} = uri_unescape($u)
                if defined $u;
            $params->{password} = uri_unescape($p)
                if defined $p;
        }
        $params->{folder} = substr($uri->path(),1)
            if (defined $uri->path() && $uri->path() ne "/");
        return 'imap';
    },
    # XXX need to add a uriparser for imaps urls
    'pop' => sub
    {
        my ($uri, $params) = @_;

        $params->{host} = $uri->host();
        $uri->_port() and $params->{port} = 0 + $uri->_port();
        if ($uri->userinfo())
        {
            my ($u, $p) = split(/:/, $uri->userinfo());
            $params->{username} = uri_unescape($u)
                if defined $u;
            $params->{password} = uri_unescape($p)
                if defined $p;
        }
        $params->{folder} = substr($uri->path(),1)
            if (defined $uri->path() && $uri->path() ne "/");
        return 'pop3';
    },
);

sub create
{
    my $class = shift;
    my %params = @_;
    my $type;

    if (defined $params{uri})
    {
        my $uri = URI->new($params{uri});
        delete $params{uri};

        die "Unsupported URI scheme \"$uri->scheme\""
            unless defined $uriparsers{$uri->scheme()};
        $type = $uriparsers{$uri->scheme()}->($uri, \%params);
    }

    if (!defined $type && defined $params{type})
    {
        $type = $params{type};
        delete $params{type};
    }

    # some heuristics
    if (defined $params{directory})
    {
        $type = 'maildir';
    }
    elsif (defined $params{filename})
    {
        $type = 'mbox';
    }

    $type = 'mbox'
        unless defined $type;

    $cleanups{$type}->(\%params)
        if defined $cleanups{$type};

    die "No such type \"$type\""
        unless defined $fmethods{$type};
    return $fmethods{$type}->(%params);
}

1;
