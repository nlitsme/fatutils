fatutils
========

Two tools for reading FAT filesystem images:

 * fatinfo.pl - a rather old tool, written in perl
 * fatdump.py - a newer tool, written in python.

Both have a similar functionality.

I use these so i don't have to actually mount a filesystem image in order to see what is inside.
Note: you can also do this using (7zip)[https://www.7-zip.org/].

fatinfo
=======

    Usage: perl fatinfo.pl [options]  fatfilesystemimage
       -f DIRECTORY  : save files to DIRECTORY
       -d            : save deleted files
       -c            : save unused clusters
       -u            : save unlinked cluster chains
       -l            : save data from unused cluster space
       -o OFFSET     : offset to FAT bootsector
       -v            : be verbose
       -r            : repair incorrect filesize (only rootdir entries)

    for example to print info on the xda-ii extended rom image:

        perl fatinfo.pl -o 0x70040 ms_.nbf

fatdump
=======

    usage: fatdump.py [-h] [--verbose] [--offset OFFSET] [--recurse] [--skiplinks] [--listfiles] [--badblocks BADBLOCKS] [--blocksize BLOCKSIZE] [--cat CAT] [--debug] FILES [FILES ...]

    fatdump

    positional arguments:
      FILES                 Files or URLs

    optional arguments:
      -h, --help            show this help message and exit
      --verbose, -v
      --offset OFFSET, -o OFFSET
      --recurse, -r         recurse into directories, when finding disk images
      --skiplinks, -L       ignore symlinks
      --listfiles, -l       list files
      --badblocks BADBLOCKS
                            bad sector nrs
      --blocksize BLOCKSIZE
                            the blocksize
      --cat CAT, -c CAT     cat a file to stdout
      --debug

AUTHOR
======

Willem Hengeveld <itsme@xs4all.nl>

