package Cassandane::JMAPTester;
use Moo;
extends 'JMAP::Tester';

use experimental 'signatures';

use Encode ();
use MIME::Base64 ();

has fallback_account_id => (
    is       => 'ro',
    required => 1,
);

# This emulates JMAPTalk's DefaultUsing
sub DefaultUsing {
    my ($self, $using) = @_;
    $using || return $self->default_using;
    $self->default_using($using);
}

sub AddUsing {
    my ($self, @to_add) = @_;
    my %already_using = map {; $_ => 1 } $self->default_using->@*;

    for my $capa (@to_add) {
        next if $already_using{$capa}++;

        push $self->default_using->@*, $capa;
    }
}

# This emulates JMAPTalk's CallMethods, which returns the plain ol'
# array-of-arrays that is the methodResponses
sub CallMethods {
    my ($self, $sentences, $using, %headers) = @_;

    %headers
        && Carp::confess("Cassandane::JMAPTester does not support custom HTTP headers");

    my $res = $self->request({
        methodCalls => $sentences,
        ($using ? (using => $using) : ()),
    });

    return $res->assert_successful->as_stripped_triples;
}

# This emulates JMAPTalk's Call method, which returns the arguments of the
# successful response to a single method invocation.
sub Call {
    my ($self, $method, $arguments, @rest) = @_;
    $arguments ||= {};
    my $res = $self->CallMethods([[ $method, $arguments, "c1"]], @rest);
    return undef unless ref $res;
    return undef unless ref $res->[0];
    return undef unless $res->[0][0] eq $method;
    return undef unless $res->[0][2] eq 'c1';
    return $res->[0][1];
}

# This emulates JMAPTalk's Upload, called like this:
#   $jmaptalk->Upload(\%optional_headers?, $bytes, $content_type, $accountId)
#
# scalar context, JMAPTalk returns the decoded result data
# list context, JMAPTalk returns (the underlying UA response, the decoded result)
#
# We will start by forbidding custom headers or list context.
sub Upload {
    my $self    = shift;
    my $headers = (ref $_[0] eq 'HASH') ? shift : {};
    my $bytes   = shift;
    my $type    = shift;
    my $accountId = shift // $self->fallback_account_id;

    wantarray
        && Carp::confess("Cassandane::JMAPTester can't emulate JMAPTalk->Upload in list context");

    my $upload = $self->upload({
        type => $type,
        blob => \$bytes,
        accountId => $accountId,
    });

    return $upload->{payload};
}

# This emulate's JMAPTalk's Download, called like this:
#   $jmaptalk->Download( $coderef?, $hashref?, $accountId, $blobId, $name? )
#
# It returns an HTTP::Simple-style HTTP response.
sub Download {
    my $self = shift;
    my $code = ref $_[0] eq 'CODE' ? shift : undef;
    my $hdrs = ref $_[0] eq 'HASH' ? shift : undef;
    my $account_id = shift;
    my $blob_id    = shift;
    my $name       = shift;

    if (length $name) {
        $name = Encode::encode('utf-8', $name, Encode::FB_CROAK);
    }

    $code && Carp::confess("Cassandane::JMAPTester can't emulate JMAPTalk->Download callback");

    my %download_arg;
    if ($hdrs && %$hdrs) {
        my $accept = delete $hdrs->{accept};

        %$hdrs && Carp::confess("Cassandane::JMAPTester's JMAPTalk->Download only supports accept header");

        $download_arg{accept} = $accept;
    }

    my $download = $self->download(
        {
            (defined $account_id ? (accountId => $account_id) : ()),
            (defined $blob_id    ? (blobId    => $blob_id   ) : ()),
            (defined $name       ? (name      => $name      ) : ()),
        },
        \%download_arg,
    );

    my $have_headers = $download->http_response->headers;
    my %tiny_headers;

    # Tests using the emulation layer want to see the headers as they'd have
    # been provided by HTTP::Tiny, which means "either array or one value, name
    # always in lower case".  This just maps HTTP::Header values into
    # HTTP::Tiny-like headers. -- rjbs, 2025-12-11
    $have_headers->scan(sub ($k, $v) {
        $k = lc $k;
        if (exists $tiny_headers{$k}) {
            $tiny_headers{$k} = ref $tiny_headers{$k}
                              ? [ $tiny_headers{$k}->@*, $v ]
                              : [ $tiny_headers{$k}, $v ];
        } else {
            $tiny_headers{$k} = $v;
        }
    });

    my $fake_jmaptalk_download = {
        content => $download->http_response->decoded_content(charset => undef),
        headers => \%tiny_headers,
        status  => $download->http_response->code,
    };

    return $fake_jmaptalk_download;
}

sub set_username_and_password ($self, $username, $password) {
    $self->ua->set_default_header(
        'Authorization',
        q{Basic } .  MIME::Base64::encode_base64(
            join(q{:}, $username, $password),
            q{},
        )
    );
}

sub set_scheme_and_host_and_port ($self, $scheme, $host, $port) {
    $self->api_uri("$scheme://$host:$port/jmap/");
    $self->authentication_uri("$scheme://$host:$port/jmap");
    $self->upload_uri("$scheme://$host:$port/jmap/upload/{accountId}/");

    # The session actually provides a query string of "?accept={type}" but our
    # tests don't reliably provide type, and we can't just use the Accept
    # header they send, because sometimes they send an Accept that's
    # preferential or wildcardy.  So, we'll just not include that parameter
    # here.  This is crap, but it's a transition toward less crap.
    $self->download_uri("$scheme://$host:$port/jmap/download/{accountId}/{blobId}/{name}");

    return;
}

no Moo;
1;
