package Net::DAVTalk::XMLParser;

use base 'Exporter';

our @EXPORT = qw(xmlToHash);

use XML::Fast;
use Carp qw(confess);

sub _nsexpand {
  my $data = shift;
  my $ns = shift || {};

  if (ref($data) eq 'HASH') {
    my @keys;
    my %res;
    foreach my $key (keys %$data) {
      if ($key eq '@xmlns') {
        $ns->{''} = $data->{$key};
      }
      elsif ($key eq '#text') {
        $res{'content'} = $data->{$key};
      }
      elsif (substr($key, 0, 7) eq '@xmlns:') {
        my $namespace = substr($key, 7);
        $ns->{$namespace} = $data->{$key};
        # this is what XML::Simple does with existing namespaces
        $res{"{http://www.w3.org/2000/xmlns/}$namespace"} = $data->{$key};
      }
      else {
        push @keys, $key;
      }
    }
    foreach my $key (@keys) {
      my %ns = %$ns; # copy, woot
      my $sub = _nsexpand($data->{$key}, \%ns);
      my $pos = index($key, ':');
      if ($pos > 0) {
        my $namespace = substr($key, 0, $pos);
        my $rest = substr($key, $pos+1);
        my $expanded = $ns{$namespace};
        confess "Unknown namespace $namespace" unless $expanded;
        $key = "{$expanded}$rest";
      }
      elsif ($ns{''}) {
        my $expanded = $ns{''};
        $key = "{$expanded}$key";
      }
      $res{$key} = $sub;
    }
    return \%res;
  }
  elsif (ref($data) eq 'ARRAY') {
    return [ map { _nsexpand($_, $ns) } @$data ];
  }
  else {
    # like XML::Simple's ExpandContent option
    return { content => $data };
  }
}

sub xmlToHash {
  my $text = shift;

  my $Raw = XML::Fast::xml2hash($text, attr => '@');
  # like XML::Simple's NSExpand option
  my $Xml = _nsexpand($Raw);

  # XML::Simple returns the content of the top level key
  # (there should only be one)
  my ($key) = keys %$Xml;

  return $Xml->{$key};
}

1;
