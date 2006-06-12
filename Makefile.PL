#!/usr/bin/perl
# $Id: Makefile.PL,v 1.4 2006/06/12 10:18:58 gavin Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'			=> 'Net::EPP::Proxy',
    'VERSION_FROM'		=> 'lib/Net/EPP/Proxy.pm',
    'PREREQ_PM'			=> {
	'Digest::SHA1'		=> 0,
	'IO::Multiplex'		=> 0,
	'Net::EPP::Client'	=> '0.05',
	'Net::EPP::Frame'	=> '0.03',
	'Net::Server'		=> 0,
	'Time::HiRes'		=> 0,
	'XML::LibXML'		=> 0,
    },
);
