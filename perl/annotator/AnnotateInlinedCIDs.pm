use warnings;
use strict;


package AnnotateInlinedCIDs;
use Cyrus::Annotator::Daemon;
use JSON;
use URI::Escape;
our @ISA = qw(Cyrus::Annotator::Daemon);

use constant INLINEDCIDSNAME => "/vendor/jmap.io/inlinedcids";

sub MakeInlinedCIDs {
    my ($message) = @_;

    my %CidData;
    my $BS = $message->bodystructure();

    # Keep looking into multipart types
    my @Parts = ($BS);
    do {{ # needed, see perlsyn
      $BS = shift @Parts;

      # Multipart, search all sub-parts
      if ($BS->{'MIME-Type'} eq 'multipart') {
        push @Parts, @{$BS->{'MIME-Subparts'} || []};
        next;

      } elsif ($BS->{'MIME-TxtType'} eq "text/html") {
        # A HTML body, check all cid: URLs in <img> tags
        my $Content = $message->read_part_content($BS);

        # Pick all <img> tags with cid: URLs
        while ( $Content =~ /<img\s+[^>]*src\s*=\s*"cid:(.+?)"[^>]*>/g ) {
            # Format the URL as how it will show up as Content-ID
            my $cid = "<" . uri_unescape($1) . ">";
            $CidData{$cid} = $BS->{'IMAP-Partnum'};
        }

      }
    }} while (@Parts);

    return %CidData ? \%CidData : undef;
}

sub annotate_message {
    my ( $self, $message ) = @_;

    my $InlinedCIDs = MakeInlinedCIDs($message);
    $message->set_shared_annotation(INLINEDCIDSNAME, encode_json($InlinedCIDs))
      if defined $InlinedCIDs;

    return 0;
}

AnnotateInlinedCIDs->run();
