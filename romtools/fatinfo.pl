#!perl -w
use strict;
# (C) 2003 XDA Developers
# Author: Willem Jan Hengeveld <itsme@xs4all.nl>
# Web: http://www.xda-developers.com/
#
# $Header$
#
# script to extract deleted files / unused space from a fat filesystem
#  ( for instance the xda2 extended rom upgrade file )
#
$|=1;

use IO::File;

my $fh= new IO::File(shift, "r") or die "open\n";
binmode $fh;

my $bootinfo= readbootinfo($fh);

my @fats;

for (0 .. $bootinfo->{NumberOfFats}-1) {
	$fats[$_]= readfat($fh, $bootinfo->{SectorsPerFAT});
}

print "found ", scalar keys %{$fats[0]}, " files in fat\n";

my $rootdir= readdirectory($fh, $bootinfo->{RootEntries}/16);
printdir($fats[0], $rootdir);

$bootinfo->{cluster2sector}= $bootinfo->{RootEntries}/16 + $bootinfo->{SectorsPerFAT}*$bootinfo->{NumberOfFats} + 1;

$bootinfo->{totalclusters}= int(($bootinfo->{NumberOfSectors}-$bootinfo->{cluster2sector})/$bootinfo->{SectorsPerCluster});

savefiles($fh, $bootinfo, $fats[0], $rootdir);

saveunusedclusters($fh, $bootinfo, $fats[0]);

$fh->close();

exit(0);

sub readbootinfo {
	my ($fh)= @_;

	my $data;
	$fh->read($data, 512) or die "readboot\n";

	my @fields= unpack("A3A8vCvCvvCvvvVVCCCVA11A8a*", $data);

	my @fieldnames= qw(Jump OEMID BytesPerSector SectorsPerCluster ReservedSectors NumberOfFats RootEntries NumberOfSectors MediaDescriptor SectorsPerFAT SectorsPerHead HeadsPerCylinder HiddenSectors BigNumberOfSectors PhysicalDrive CurrentHead Signature SerialNumber VolumeLabel FSID reserved);

	print "field count mismatch($#fields != $#fieldnames)\n" if ($#fields != $#fieldnames);

	my %bootinfo= map { $fieldnames[$_] => $fields[$_] } (0..$#fields);

	printf("%-11s      : %s\n", $fields[1], $fieldnames[1]);
	for (2..$#fieldnames-4) {
		printf("%8x (%5d) : %s\n", $fields[$_], $fields[$_], $fieldnames[$_]);
	}
	printf("%-10s       : %s\n", $fields[-3], $fieldnames[-3]);
	printf("%-10s       : %s\n", $fields[-2], $fieldnames[-2]);

	print(unpack("H*", $fields[-1]), "\n") if ($fields[-1] !~ /^\x00+\x55\xaa$/);

	return \%bootinfo;
}

sub readfat {
	my ($fh, $sects)= @_;

	my $data;
	$fh->read($data, 512*$sects) or die "readfat\n";

	my @clusters= unpack("v*", $data);

	my $maxused;
	my %ref;
	for (0..$#clusters) {
		if ($clusters[$_]>0 && $clusters[$_]<0xfff0) {
			$ref{$clusters[$_]}= 1;

		}
		if ($clusters[$_]) {
			$maxused= $_;
		}
	}

	printf("found %d clusters, max used= %04x\n", scalar @clusters, $maxused);

	my %emptylist;
	my %files;
	for (0..$#clusters) {
		if (!exists $ref{$_} && $clusters[$_]>0) {
			my @list= ();

			for (my $clus= $_ ; $clus>0 && $clus<0xfff0 ; $clus= $clusters[$clus]) {
				push @list, $clus;
			}
			$files{$_}{clusterlist}= \@list;
		}
		elsif ($clusters[$_]==0) {
			$emptylist{$_}= 1;
		}
	}
	$files{emptylist}= \%emptylist;
	$files{ref}= \%ref;
	return \%files;
}
sub parseLFNentry {
	my ($dirdata)= @_;

	my @fields= unpack("Ca10CCCa12va4", $dirdata);
	my $unicodename= $fields[1].$fields[5].$fields[7];

	my $namepart= pack("C*", unpack("v*", $unicodename));

	$namepart =~ s/\x00.*//;

	return { part=>$fields[0]&0x1f, last=>$fields[0]&0x20, namepart=>$namepart };
}

sub parsedirentry {
	my ($dirdata)= @_;

	my @fieldnames= qw(filename attribute reserved time date start filesize);
	my @fields= unpack("A11Ca10vvvV", $dirdata);
	print "dirfield count mismatch($#fields != $#fieldnames)\n" if ($#fields != $#fieldnames);
	my %direntry= map { $fieldnames[$_] => $fields[$_] } (0..$#fields);

	if ($direntry{attribute}==0xf) {
		return parseLFNentry($dirdata);
	}

	return \%direntry;
}
sub readdirectory {
	my ($fh, $sects)= @_;

	my $data;
	$fh->read($data, 512*$sects) or die "readdirectory\n";

	my @entries;
	my @lfn= ();
	for (0..$sects*16-1) {
		my $entrydata= substr($data, 32*$_, 32);

		next if ($entrydata =~ /^\x00+$/);

		my $ent= parsedirentry($entrydata);
		if (exists $ent->{part}) {
			push @lfn, $ent->{namepart};
		}
		else {
			$ent->{lfn}= join("", reverse @lfn);
			push @entries, $ent;

			#printf("%d part lfn: %s\n", scalar @lfn, join(",",@lfn));
			@lfn= ();
		}
	}

	return \@entries;
}

sub printdirentry {
	my ($fat, $ent)= @_;

	printf("%-11s %02x %04x %04x %04x %8d %s  '%s'\n",
		$ent->{filename}, $ent->{attribute}, $ent->{time}, $ent->{date},
		$ent->{start}, $ent->{filesize}, unpack("H*", $ent->{reserved}), $ent->{lfn});
	if (exists $fat->{$ent->{start}}) {
		my $nclusters= scalar @{$fat->{$ent->{start}}{clusterlist}};
		my $expectedclusters= int(($ent->{filesize}+2047)/2048);
		if ($expectedclusters==$nclusters) {
			#printf("   has %d clusters\n", $nclusters);
		}
		else {
			printf("   has %d clusters, expected %d clusters\n", $nclusters, $expectedclusters);
		}
	}
	elsif (exists $fat->{emptylist}{$ent->{start}}) {
		printf("   is in emptylist\n");
	}
}

sub printdir {
	my ($fat, $directory)= @_;

	for (@$directory) {
		printdirentry($fat, $_);
	}
}

sub saveentry {
	my ($fh, $boot, $fat, $ent)= @_;

	my $name= $ent->{lfn} || $ent->{filename};
	my $extra= "";

	if (-e $name) {
		my $i=0;
		do {
			$extra= sprintf("-%03d", $i++);
		} while(-e "$name$extra");

		print("avoided duplicate name for $name$extra\n");
	}
	my $outfh= IO::File->new("$name$extra", "w+");
	binmode($outfh);
	if (exists $fat->{$ent->{start}}) {
		for (@{$fat->{$ent->{start}}{clusterlist}})
		{
			$outfh->write(readcluster($fh, $boot, $_));
			$fat->{ref}{$_}++;
		}
	}
	elsif (exists $fat->{emptylist}{$ent->{start}}) {
		my $nclusters= int(($ent->{filesize}+2047)/2048);
		for (0..$nclusters-1) {
			$outfh->write(readcluster($fh, $boot, $_+$ent->{start}));

			$fat->{ref}{$_}++;
		}
	}
	my $leftoversize= $outfh->tell()-$ent->{filesize};
	printf("truncating last %d bytes\n", $leftoversize);
	if ($leftoversize>0) {
		$outfh->seek($ent->{filesize}, 0);
		my $leftoverdata;
		$outfh->read($leftoverdata, $leftoversize);
		$outfh->truncate($ent->{filesize});

		my $leftfh= IO::File->new("$name$extra-leftover", "w");
		binmode($leftfh);
		$leftfh->write($leftoverdata);
		$leftfh->close();
	}
	$outfh->close();

}
sub savefiles {
	my ($fh, $boot, $fat, $directory)= @_;

	for (@$directory) {
		saveentry($fh, $boot, $fat, $_);
	}
}

sub readsector {
	my ($fh, $nr)= @_;

	$fh->seek(512*$nr, 0);

	my $data;
	$fh->read($data, 512);

	return $data;
}
sub readcluster {
	my ($fh, $boot, $nr)= @_;

	my $startsector= ($nr-2)*4+$boot->{cluster2sector};

	my @data;

	for (0..$bootinfo->{SectorsPerCluster}-1) {
		push @data, readsector($fh, $startsector+$_);
	}

	return join "", @data;
}
sub saveunusedclusters {
	my ($fh, $boot, $fat)= @_;

	for (2 .. $boot->{totalclusters}-1) {
		next if (exists $fat->{ref}{$_});

		my $outfh= IO::File->new(sprintf("cluster-%04x", $_), "w");
		binmode($outfh);
		$outfh->write(readcluster($fh, $boot, $_));
		$outfh->close();
	}
}
