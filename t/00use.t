#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 2;

use_ok( 'IO::Async::SSL' );
use_ok( 'IO::Async::SSLStream' );
