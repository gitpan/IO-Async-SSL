#!/usr/bin/perl

use strict;
use warnings;

use IO::Async::Loop;
use IO::Async::Stream;
use IO::Async::SSL;

my $CRLF = "\x0d\x0a"; # because \r\n is not portable

my $HOST = shift @ARGV or die "Need HOST";
my $PORT = shift @ARGV or die "Need PORT";

my $loop = IO::Async::Loop->new;

my ( $socketstream, $stdiostream );
my $peeraddr;

$loop->SSL_connect(
   host    => $HOST,
   service => $PORT,

   on_stream => sub {
      $socketstream = shift;

      my $socket = $socketstream->read_handle;
      $peeraddr = $socket->peerhost . ":" . $socket->peerport;

      print STDERR "Connected to $peeraddr\n";
   },

   on_resolve_error => sub { die "Cannot resolve - $_[0]\n" },
   on_connect_error => sub { die "Cannot connect\n" },
   on_ssl_error     => sub { die "SSL error $_[-1]\n" },
);

$loop->loop_once until defined $socketstream;

my $quit_mergepoint = IO::Async::MergePoint->new(
   needs => [qw[ socket stdio ]],

   on_finished => sub { $loop->loop_stop },
);

$socketstream->configure(
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
$loop->add( $socketstream );

$stdiostream = IO::Async::Stream->new(
   read_handle  => \*STDIN,
   write_handle => \*STDOUT,

   on_read => sub {
      my ( undef, $buffref, $closed ) = @_;

      if( $$buffref =~ s/^(.*)\n// ) {
         $socketstream->write( $1 . $CRLF );
         return 1;
      }

      return 0;
   },

   on_closed => sub {
      $quit_mergepoint->done( 'stdio' );
      $socketstream->close_when_empty;
   },
);
$loop->add( $stdiostream );

$loop->loop_forever;
