#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use IO::Async::Test;

use IO::Async::OS;
use IO::Async::Loop;
use IO::Async::SSL;
use IO::Async::SSLStream;

use POSIX qw( WEXITSTATUS );

system( "socat -help >/dev/null 2>&1" ) == 0 or
   plan skip_all => "no socat";

my $loop = IO::Async::Loop->new;

testing_loop( $loop );

my ( $my_rd, $ssl_wr, $ssl_rd, $my_wr ) = IO::Async::OS->pipequad
   or die "Cannot pipequad - $!";

my $kid = $loop->spawn_child(
   setup => [
      chdir => "t",
      stdin  => $ssl_rd,
      stdout => $ssl_wr,
   ],
   command => [ "socat", "OPENSSL-LISTEN:4434,cert=server.pem,key=privkey.pem,verify=0", "STDIO" ],
   on_exit => sub {
      my ( $pid, $exitcode ) = @_;

      my $status = WEXITSTATUS( $exitcode );

      $status == 0 or die "socat failed with $status\n";
   },
);

close $ssl_rd;
close $ssl_wr;

END { kill TERM => $kid if defined $kid }

my @socat_lines;
$loop->add( my $socat_stream = IO::Async::Stream->new(
   read_handle => $my_rd,
   write_handle => $my_wr,

   on_read => sub {
      my ( $stream, $buffref, $closed ) = @_;
      push @socat_lines, $1 while $$buffref =~ s/^(.*)\n//;
      return 0;
   },
) );

sleep 1; # This is a hack. Waiting for socat to start

my $sslsock;

$loop->SSL_connect(
   family  => "inet",
   host    => "localhost",
   service => "4434",

   SSL_verify_mode => 0,

   on_connected => sub { $sslsock = shift },

   on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
   on_connect_error => sub { die "Cannot connect\n" },
   on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
);

wait_for { defined $sslsock };

ok( defined $sslsock, "Managed to connect\n" );

my @local_lines;

my $sslstream = IO::Async::SSLStream->new(
   handle => $sslsock,
   on_read => sub {
      my ( $self, $buffref, $closed ) = @_;
      push @local_lines, $1 while $$buffref =~ s/^(.*)\n//;
      return 0;
   },
);

$loop->add( $sslstream );

undef @socat_lines;

$sslstream->write( "Send a line\n" );

wait_for { @socat_lines };

is( $socat_lines[0], "Send a line", 'Line received by openssl' );

$socat_stream->write( "Reply a line\n" );

wait_for { @local_lines };

is( $local_lines[0], "Reply a line", 'Line received by local socket' );

undef @socat_lines;
undef @local_lines;

done_testing;
