#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use IO::Async::Loop;
use IO::Async::Protocol::Stream;
use IO::Async::Signal;
use IO::Async::Stream 0.54; # ->new_close_future
use IO::Async::SSL;
use IO::Async::SSLStream;

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

$loop->connect(
   host     => $HOST,
   service  => $PORT,
   family   => $FAMILY,
   socktype => 'stream',

   on_stream => sub {
      $socketstream = shift;

      my $socket = $socketstream->read_handle;
      $peeraddr = $socket->peerhost . ":" . $socket->peerport;

      print STDERR "Connected to $peeraddr. Send SIGQUIT (Ctrl-\\) to start SSL upgrade\n";
   },

   on_resolve_error => sub { die "Cannot resolve - $_[0]\n" },
   on_connect_error => sub { die "Cannot connect\n" },
);

$loop->loop_once until defined $socketstream;

my $socketproto = IO::Async::Protocol::Stream->new(
   transport => $socketstream,

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
$loop->add( $socketproto );

$stdiostream = IO::Async::Stream->new(
   read_handle  => \*STDIN,
   write_handle => \*STDOUT,

   on_read => sub {
      my ( undef, $buffref, $closed ) = @_;

      # Turn plain \n into CRLFs
      $$buffref =~ s/\n/\x0d\x0a/g;
      $socketproto->write( $$buffref );
      $$buffref = "";

      return 0;
   },

   on_closed => sub {
      $socketproto->transport->close_when_empty;
   },
);
$loop->add( $stdiostream );

my $signal = IO::Async::Signal->new(
   name => "QUIT",
   on_receipt => sub {
      my ( $self ) = @_;
      $loop->remove( $self );

      $socketproto->SSL_upgrade(
         on_upgraded => sub {
            print STDERR "Now upgraded to SSL\n"; # TODO: get actual name somehow?

            if( $DUMPCERT ) {
               my $socket = $socketproto->transport->read_handle;
               print STDERR Net::SSLeay::PEM_get_string_X509($socket->peer_certificate) . "\n";
            }
         },

         on_error => sub {
            die "Cannot upgrade to SSL - $_[-1]\n";
         },
      );
   },
);
$loop->add( $signal );

$loop->await( $socketproto->transport->new_close_future, $stdiostream->new_close_future );
