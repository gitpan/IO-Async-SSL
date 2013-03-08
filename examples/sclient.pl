#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use IO::Async::Loop;
use IO::Async::Stream 0.54; # ->new_close_future
use IO::Async::SSL;

my $DUMPCERT;
my $FAMILY;
GetOptions(
   'd|dumpcert' => \$DUMPCERT,
   '4|ipv4'     => sub { $FAMILY = "inet" },
   '6|ipv6'     => sub { $FAMILY = "inet6" },
) or exit 1;

my $HOST = shift @ARGV or die "Need HOST";
my $PORT = shift @ARGV or die "Need PORT";

my $loop = IO::Async::Loop->new;

my ( $socketstream, $stdiostream );
my $peeraddr;

$loop->SSL_connect(
   host    => $HOST,
   service => $PORT,
   family  => $FAMILY,

   on_stream => sub {
      $socketstream = shift;

      my $socket = $socketstream->read_handle;
      $peeraddr = $socket->peerhost . ":" . $socket->peerport;

      print STDERR "Connected to $peeraddr\n";

      if( $DUMPCERT ) {
         print STDERR Net::SSLeay::PEM_get_string_X509($socket->peer_certificate) . "\n";
      }
   },

   on_resolve_error => sub { die "Cannot resolve - $_[0]\n" },
   on_connect_error => sub { die "Cannot connect\n" },
   on_ssl_error     => sub { die "SSL error $_[-1]\n" },
);

$loop->loop_once until defined $socketstream;

$socketstream->configure(
   on_read => sub {
      my ( undef, $buffref, $closed ) = @_;

      # Turn CRLFs into plain \n by stripping \r
      $$buffref =~ s/\r//g;
      $stdiostream->write( $$buffref );
      $$buffref = "";

      return 0;
   },

   on_closed => sub {
      print STDERR "Closed connection to $peeraddr\n";
      $stdiostream->close_when_empty;
   },
);
$loop->add( $socketstream );

$stdiostream = IO::Async::Stream->new(
   read_handle  => \*STDIN,
   write_handle => \*STDOUT,

   on_read => sub {
      my ( undef, $buffref, $closed ) = @_;

      # Turn plain \n into CRLFs
      $$buffref =~ s/\n/\x0d\x0a/g;
      $socketstream->write( $$buffref );
      $$buffref = "";

      return 0;
   },

   on_closed => sub {
      $socketstream->close_when_empty;
   },
);
$loop->add( $stdiostream );

$loop->await( $socketstream->new_close_future, $stdiostream->new_close_future );
