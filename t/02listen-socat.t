#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use IO::Async::Test;

use IO::Async::Loop;
use IO::Async::SSL;
use IO::Async::SSLStream;

use POSIX qw( WEXITSTATUS );

system( "socat -help >/dev/null 2>&1" ) == 0 or
   plan skip_all => "no socat";

plan tests => 3;

my $loop = IO::Async::Loop->new;

testing_loop( $loop );

my $listen_sock;
my $sslsock;

$loop->SSL_listen(
   service => "4434",

   SSL_key_file  => "t/privkey.pem",
   SSL_cert_file => "t/server.pem",

   on_listen => sub { $listen_sock = shift },
   on_accept => sub { $sslsock = shift },

   on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
   on_listen_error  => sub { die "Cannot listen - $_[-1]\n" },
   on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
);

wait_for { defined $listen_sock };

my ( $my_rd, $ssl_wr, $ssl_rd, $my_wr ) = $loop->pipequad
   or die "Cannot pipequad - $!";

my $kid = $loop->spawn_child(
   setup => [
      stdin  => $ssl_rd,
      stdout => $ssl_wr,
   ],
   command => [ "socat", "OPENSSL:localhost:4434,verify=0", "STDIO" ],
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

is( $socat_lines[0], "Send a line", 'Line received by socat' );

$socat_stream->write( "Reply a line\n" );

wait_for { @local_lines };

is( $local_lines[0], "Reply a line", 'Line received by local socket' );

undef @socat_lines;
undef @local_lines;
