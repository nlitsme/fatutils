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
# shortcomings:
#    - does not yet support subdirectories.
# 

$|=1;

use IO::File;
use Getopt::Long;

my $g_saveFilesTo;
my $g_saveDeletedFiles;
my $g_saveUnusedClusters;
my $g_saveLeftoverSize;
my $g_fatOffset= 0;
my $g_verbose= 0;
my $g_quiet= 0;
my $g_repair= 0;

my @g_repaircmds;

sub usage {
    return <<__EOF__
Usage: perl fatinfo.pl [options]  fatfilesystemimage
   -f DIRECTORY  : save files to DIRECTORY
   -d            : save deleted files
   -c            : save unused clusters
   -l            : save data from unused cluster space
   -o OFFSET     : offset to FAT bootsector
   -v            : be verbose
   -r            : repair incorrect filesize

for example to print info on the xda-ii extended rom image:

    perl fatinfo.pl -o 0x70040 ms_.nbf

__EOF__
}
GetOptions(
    "f=s" => \$g_saveFilesTo,
    "d" => \$g_saveDeletedFiles,
    "c" => \$g_saveUnusedClusters,
    "l" => \$g_saveLeftoverSize,
    "v" => \$g_verbose,
    "q" => \$g_quiet,
    "r" => \$g_repair,
    "o=s" => sub { $g_fatOffset= eval $_[1]; },
) or die usage();

die usage() if (!@ARGV);

my $extromname= shift;
my $fh= new IO::File($extromname, "r") or die "$extromname: $!\n";
binmode $fh;

if (!$g_fatOffset) {
	FindFatOffset($fh);
}
my $bootinfo= ReadBootInfo($fh);

my @fats;

for (0 .. $bootinfo->{NumberOfFats}-1) {
	$fats[$_]= ReadFat($fh, $bootinfo->{SectorsPerFAT});
}

print "found ", scalar keys %{$fats[0]}, " files in fat\n" if (!$g_quiet);

$bootinfo->{rootdirofs}= $fh->tell();

printf("reading rootdir from %08lx\n", $bootinfo->{rootdirofs}) if (!$g_quiet);

my $rootdir= ReadDirectory($fh, $bootinfo->{rootdirofs}, $bootinfo->{RootEntries}/16);

$bootinfo->{cluster2sector}= $bootinfo->{RootEntries}/16 + $bootinfo->{SectorsPerFAT}*$bootinfo->{NumberOfFats} + 1;

$bootinfo->{totalclusters}= int(($bootinfo->{NumberOfSectors}-$bootinfo->{cluster2sector})/$bootinfo->{SectorsPerCluster});

PrintDir($fats[0], $rootdir, $bootinfo);

SaveFiles($fh, $bootinfo, $fats[0], $rootdir) if ($g_saveFilesTo);

SaveUnusedClusters($fh, $bootinfo, $fats[0]) if ($g_saveUnusedClusters);

$fh->close();


if ($g_repair && @g_repaircmds) {
    print "\nto repair your disk run these commands:\n\n";
    print "hexedit $extromname @g_repaircmds\n";
    printf("psdwrite -2 %s -s 0x%x  0x%x\n", $extromname, $bootinfo->{rootdirofs}, $bootinfo->{rootdirofs}); 
}
exit(0);

sub FindFatOffset {
	my ($fh)= @_;

	for (0, 0x40, 0x70000, 0x70040) {
		if (isFatBoot($fh, $_)) {
			$g_fatOffset= $_;
			return;
		}
	}
}
sub isFatBoot {
	my ($fh, $ofs)= @_;
	my $data;
	$fh->seek($ofs, SEEK_SET);
	$fh->read($data, 64);

	return substr($data, 3, 8) eq "MSWIN4.1"
		&& substr($data, 54, 8) eq "FAT16   ";
}

sub ReadBootInfo {
	my ($fh)= @_;

    $fh->seek($g_fatOffset, 0);

    printf("reading bootsector from %08lx\n", $fh->tell()) if (!$g_quiet);

	my $data;
	$fh->read($data, 512) or die "readboot\n";

	my @fields= unpack("A3A8vCvCvvCvvvVVCCCVA11A8a*", $data);

	my @fieldnames= qw(Jump OEMID BytesPerSector SectorsPerCluster ReservedSectors NumberOfFats RootEntries NumberOfSectors MediaDescriptor SectorsPerFAT SectorsPerHead HeadsPerCylinder HiddenSectors BigNumberOfSectors PhysicalDrive CurrentHead Signature SerialNumber VolumeLabel FSID reserved);

	print "field count mismatch($#fields != $#fieldnames)\n" if ($#fields != $#fieldnames);

	my %bootinfo= map { $fieldnames[$_] => $fields[$_] } (0..$#fields);

    if (!$g_quiet) {
        printf("%-11s      : %s\n", $fields[1], $fieldnames[1]);
        for (2..$#fieldnames-4) {
            printf("%8x (%5d) : %s\n", $fields[$_], $fields[$_], $fieldnames[$_]);
        }
        printf("%-10s       : %s\n", $fields[-3], $fieldnames[-3]);
        printf("%-10s       : %s\n", $fields[-2], $fieldnames[-2]);

        print(unpack("H*", $fields[-1]), "\n") if ($fields[-1] !~ /^\x00+\x55\xaa$/);
    }

	return \%bootinfo;
}

# assumes filepointer points after bootsector
sub ReadFat {
	my ($fh, $sects)= @_;

    printf("reading fat from %08lx\n", $fh->tell()) if (!$g_quiet);

	my $data;
	$fh->read($data, 512*$sects) or die "ReadFat\n";

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

	printf("found %d clusters, max used= %04x\n", scalar @clusters, $maxused) if (!$g_quiet);

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
sub ParseLFNEntry {
	my ($dirdata)= @_;

    # 00  bits5-0=partnr  bit6=last   bit7 = erased.
    # 01  namepart1 - 5 unicode chars
    # 0b  0x0f
    # 0c  ?  0x00
    # 0d  ?  checksum of shortname
    # 0e  namepart2 - 6 unicode chars
    # 1a  ?  0x0000
    # 1c  namepart3 - 2 unicode chars

    #print "hex: ", unpack("H*", $dirdata), "\n";
	my @fields= unpack("Ca10CCCa12va4", $dirdata);
	my $unicodename= $fields[1].$fields[5].$fields[7];
    #print join(", ", map {sprintf("%d:%s", $_, unpack("H*",$fields[$_])) } (0..$#fields)), "\n";

	my $namepart= pack("C*", grep { $_<256 } unpack("v*", $unicodename));

	$namepart =~ s/\x00.*//;

    #printf("LFN part %2d  last=%d name=%s\n", $fields[0]&0x3f, $fields[0]&0x40, $namepart );
	return { part=>$fields[0]&0x3f, last=>$fields[0]&0x40, namepart=>$namepart };
}

sub ParseDirEntry {
	my ($dirdata)= @_;

    # 00 filenameext
    # 0b attrib         != 0x0f
    # 0c reserved
    #  0c  first char of erased filename.
    #  0d  10ms createtime.
    #  0e  creation time
    #  10  creation date
    #  12  access date
    #  14  high 16 bits of cluster nr (fat32)
    # 16 time
    # 18 date
    # 1a startcluster
    # 1c filesize

    #print "hex: ", unpack("H*", $dirdata), "\n";

	my @fieldnames= qw(filename attribute reserved time date start filesize);
	my @fields= unpack("A11Ca10vvvV", $dirdata);
	print "dirfield count mismatch($#fields != $#fieldnames)\n" if ($#fields != $#fieldnames);
	my %direntry= map { $fieldnames[$_] => $fields[$_] } (0..$#fields);

	if ($direntry{attribute}==0xf) {
		return ParseLFNEntry($dirdata);
	}
	$direntry{filename} =~ s/^(\S+)\s+(...)$/$1.$2/;

	return \%direntry;
}

# assumes filepointer is at start of rootdir
sub ReadDirectory {
	my ($fh, $startofs, $sects)= @_;

    $fh->seek($startofs, SEEK_SET);

	my $data;
	$fh->read($data, 512*$sects) or die "ReadDirectory\n";

	my @entries;
	my @lfn= ();
	for (0..$sects*16-1) {
		my $entrydata= substr($data, 32*$_, 32);

		next if ($entrydata =~ /^\x00+$/);

		my $ent= ParseDirEntry($entrydata);

        push @{$ent->{diskoffsets}}, $startofs+32*$_;

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

sub CalcNrOfClusters {
    my ($size, $boot)= @_;
    my $clustersize= $boot->{SectorsPerCluster}*$boot->{BytesPerSector};
    return int(($size+$clustersize-1)/$clustersize);
}
sub ModifyFileSize {
    my ($ent, $size)= @_;

    push @g_repaircmds, sprintf("-pd %08lx:%08lx", $ent->{diskoffsets}[0]+0x1c, $size);
}
sub isDirentry {
    my $ent= shift;
    return $ent->{attribute}&0x10;
}
sub PrintDirEntry {
	my ($fat, $ent, $boot)= @_;

	printf("%-11s %02x %04x %04x %04x %8d %s  '%s'\n",
		$ent->{filename}, $ent->{attribute}, $ent->{time}, $ent->{date},
		$ent->{start}, $ent->{filesize}, unpack("H*", $ent->{reserved}), $ent->{lfn}) if (!$g_quiet);
	if (!isDirentry($ent) &&  exists $fat->{$ent->{start}}) {
		my $nclusters= scalar @{$fat->{$ent->{start}}{clusterlist}};
		my $expectedclusters= CalcNrOfClusters($ent->{filesize}, $boot);
		if ($expectedclusters==$nclusters) {
			#printf("   has %d clusters\n", $nclusters);
		}
		else {
			printf("%s   has %d clusters, expected %d clusters\n", $ent->{lfn} || $ent->{filename}, $nclusters, $expectedclusters);

            if ($g_repair) {
                ModifyFileSize($ent, $nclusters*$boot->{SectorsPerCluster}*$boot->{BytesPerSector});
            }
		}
	}
	elsif (exists $fat->{emptylist}{$ent->{start}}) {
		printf("   is in emptylist\n") if ($g_verbose);
	}
}

sub PrintDir {
	my ($fat, $directory, $boot)= @_;

    print "8.3name    attr datetime start    size    reserved           longfilename\n" if (!$g_quiet);
	for (@$directory) {
		PrintDirEntry($fat, $_, $boot) if ($g_saveDeletedFiles || $g_verbose || !isDeletedEntry($_));
	}
}
sub isDeletedEntry {
    my ($ent)= @_;
    return $ent->{filename} =~ /^\xe5/;
}
sub GetUniqueName {
    my ($dir, $name)= @_;

    my $fn= "$dir/$name";
    my $i= 1;
    while (-e $fn) {
        $fn= sprintf("%s/%s-%d", $dir, $name, $i++);
    }

    return $fn;
}
sub SaveEntry {
	my ($fh, $boot, $fat, $ent)= @_;

	my $name= GetUniqueName($g_saveFilesTo, $ent->{lfn} || $ent->{filename});
	my $outfh= IO::File->new($name, "w+") or die "$name: $!";
	binmode($outfh);
	if (exists $fat->{$ent->{start}}) {
		for (@{$fat->{$ent->{start}}{clusterlist}})
		{
			$outfh->write(ReadCluster($fh, $boot, $_));
			$fat->{ref}{$_}++;
		}
	}
	elsif (exists $fat->{emptylist}{$ent->{start}}) {
		my $nclusters= int(($ent->{filesize}+2047)/2048);
		for (0..$nclusters-1) {
			$outfh->write(ReadCluster($fh, $boot, $_+$ent->{start}));

			$fat->{ref}{$_}++;
		}
	}
	my $leftoversize= $outfh->tell()-$ent->{filesize};
	printf("truncating last %d bytes for %s\n", $leftoversize, $name);
	if ($g_saveLeftoverSize && $leftoversize>0) {
		$outfh->seek($ent->{filesize}, 0);
		my $leftoverdata;
		$outfh->read($leftoverdata, $leftoversize);

		my $leftfh= IO::File->new("$$name-leftover", "w") or die "$name-leftover: $!";
		binmode($leftfh);
		$leftfh->write($leftoverdata);
		$leftfh->close();
	}
	$outfh->truncate($ent->{filesize});
	$outfh->close();

}
sub SaveFiles {
	my ($fh, $boot, $fat, $directory)= @_;

	for (@$directory) {
		SaveEntry($fh, $boot, $fat, $_) if ($g_saveDeletedFiles || !isDeletedEntry($_));
	}
}

sub ReadSector {
	my ($fh, $nr)= @_;

	$fh->seek($g_fatOffset+512*$nr, 0);

	my $data;
	$fh->read($data, 512);

	return $data;
}
sub ReadCluster {
	my ($fh, $boot, $nr)= @_;

	my $startsector= ($nr-2)*4+$boot->{cluster2sector};

	my @data;

	for (0..$bootinfo->{SectorsPerCluster}-1) {
		push @data, ReadSector($fh, $startsector+$_);
	}

	return join "", @data;
}
sub SaveUnusedClusters {
	my ($fh, $boot, $fat)= @_;

	for (2 .. $boot->{totalclusters}-1) {
		next if (exists $fat->{ref}{$_});

        my $clusterfn= sprintf("$g_saveFilesTo/cluster-%04x", $_);
		my $outfh= IO::File->new($clusterfn, "w") or die "$clusterfn: $!";
		binmode($outfh);
		$outfh->write(ReadCluster($fh, $boot, $_));
		$outfh->close();
	}
}
