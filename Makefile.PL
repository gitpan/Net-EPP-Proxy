#!/usr/bin/perl
# $Id: Makefile.PL,v 1.3 2006/04/21 12:04:35 gavin Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'			=> 'Net::EPP::Proxy',
    'VERSION_FROM'		=> 'lib/Net/EPP/Proxy.pm',
    'PREREQ_PM'			=> {
	'Digest::MD5'		=> 0,
	'IO::Multiplex'		=> 0,
	'Net::EPP::Client'	=> '0.05',
	'Net::EPP::Frame'	=> 0,
	'Net::Server'		=> 0,
	'Time::HiRes'		=> 0,
	'XML::LibXML'		=> 0,
    },
);
