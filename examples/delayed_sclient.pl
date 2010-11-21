#!/usr/bin/perl

use strict;
use warnings;

use IO::Async::Loop;
use IO::Async::Protocol::Stream;
use IO::Async::Signal;
use IO::Async::Stream;
use IO::Async::SSL;
use IO::Async::SSLStream;

my $CRLF = "\x0d\x0a"; # because \r\n is not portable

my $HOST = shift @ARGV or die "Need HOST";
my $PORT = shift @ARGV or die "Need PORT";

my $loop = IO::Async::Loop->new;

my ( $socketstream, $stdiostream );
my $peeraddr;

$loop->connect(
   host    => $HOST,
   service => $PORT,

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

my $quit_mergepoint = IO::Async::MergePoint->new(
   needs => [qw[ socket stdio ]],

   on_finished => sub { $loop->loop_stop },
);

my $socketproto = IO::Async::Protocol::Stream->new(
   transport => $socketstream,

   on_read => sub {
      my ( undef, $buffref, $closed ) = @_;

      if( $$buffref =~ s/^(.*)$CRLF// ) {
         $stdiostream->write( $1 . "\n" );
         return 1;
      }

      return 0;
   },

   on_closed => sub {
      print STDERR "Closed connection to $peeraddr\n";
      $quit_mergepoint->done( 'socket' );
      $stdiostream->close_when_empty;
   },
);
$loop->add( $socketproto );

$stdiostream = IO::Async::Stream->new(
   read_handle  => \*STDIN,
   write_handle => \*STDOUT,

   on_read => sub {
      my ( undef, $buffref, $closed ) = @_;

      if( $$buffref =~ s/^(.*)\n// ) {
         $socketproto->write( $1 . $CRLF );
         return 1;
      }

      return 0;
   },

   on_closed => sub {
      $quit_mergepoint->done( 'stdio' );
      $socketproto->close_when_empty;
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
         },

         on_error => sub {
            die "Cannot upgrade to SSL - $_[-1]\n";
         },
      );
   },
);
$loop->add( $signal );

$loop->loop_forever;
