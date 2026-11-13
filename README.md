# fatutils

`fatdump.py` inspects FAT filesystem images without mounting them. It supports
FAT12, FAT16 and FAT32 inspection, extraction, consistency analysis and recovery
of unreferenced data.

I use these so I don't have to actually mount a filesystem image in order to see
what is inside. You can also use [7-Zip](https://www.7-zip.org/) to browse images.

## fatdump

### Requirements

Python 3. Local image inspection works with the Python standard library alone.
The following modules are optional:

* `urlstream` is required for URL inputs and must provide seekable access.
* `PartialStream.FileSection`, if installed, replaces the built-in bounded
  image reader.
* `efidump.mbrtypelist`, if installed, adds partition type names to verbose output.

### Quick start

```sh
# List files and directories, including their paths, sizes and start clusters.
python3 fatdump.py --listfiles disk.img

# Extract live files, preserving the directory hierarchy.
python3 fatdump.py --extract --savedir extracted disk.img

# Report filesystem layout, size mismatches and unreferenced FAT chains.
python3 fatdump.py --analyze disk.img

# Include deleted directory entries in the listing.
python3 fatdump.py --listfiles --deleted disk.img

# Show boot sector fields, FAT chains and chain branches.
python3 fatdump.py --verbose disk.img
```

The input image is opened read-only. Extraction writes separate output files;
`--repair` only prints suggestions and never changes the image.

### Selecting a volume

Without `--offset` or `--partition`, fatdump checks for a FAT boot sector at the
start of the input, then checks the four primary MBR partition entries for a
recognizable FAT volume. If none is found, it tries the legacy image offsets
`0x40`, `0x70000` and `0x70040`.

```sh
# Select MBR partition entry 1 (entries are numbered 0 through 3).
python3 fatdump.py --partition 1 --listfiles disk.img

# Inspect a FAT volume embedded at a known byte offset.
python3 fatdump.py --offset 0x70040 --listfiles ms_.nbf
```

Use either `--partition` or a nonzero `--offset`. Partition detection does not
walk extended/logical partitions or GPT tables. For those images, supply the
FAT volume's byte offset explicitly.

### Options

```text
python3 fatdump.py [options] FILES [FILES ...]
```

| Option | Description |
| --- | --- |
| `-h`, `--help` | Show command-line help. |
| `-l`, `--listfiles` | List live files and directories recursively within the FAT volume. |
| `-x`, `--extract` | Extract live files. Also enables analysis. |
| `-a`, `--analyze` | Report volume mapping, file size/chain mismatches and unreferenced chains. |
| `--deleted` | Include deleted directory entries in analysis; combine with `--listfiles` to list them. |
| `--save-deleted` | Attempt recovery of deleted files; includes deleted entries in analysis. |
| `--save-orphans` | Save allocated clusters that are not referenced by live entries, grouped by FAT chain. |
| `--save-clusters` | Save each data cluster not referenced by live entries as a separate file. |
| `--save-free` | Save contiguous runs of clusters whose FAT entry is zero. |
| `--save-slack` | Save bytes beyond a file's logical end in its cluster chain. |
| `--repair` | Print size ranges consistent with FAT chains and, where applicable, suggested `hexedit` commands. |
| `-d DIR`, `--savedir DIR` | Output directory; defaults to the current directory. Does not enable extraction by itself. |
| `-c PATH`, `--cat PATH` | Write a file's contents to standard output. |
| `-o OFFSET`, `--offset OFFSET` | Byte offset of the FAT boot sector. |
| `-p N`, `--partition N` | Select a primary MBR partition entry, numbered from zero. |
| `--badblocks LIST` | Comma-separated logical sector numbers omitted from a condensed image. |
| `--blocksize SIZE` | Sector size used for omitted-sector reconstruction and MBR LBA conversion; defaults to 512. |
| `-r`, `--recurse` | Search host directories recursively for input images. |
| `-L`, `--skiplinks` | Skip symlinks while enumerating input paths. |
| `-v`, `--verbose` | Dump boot sector fields, FAT chains and branch diagnostics. |
| `--debug` | Re-raise caught input-processing exceptions to show a traceback. |

Offsets, block sizes and bad-sector numbers accept decimal or `0x` hexadecimal
notation. Partition numbers are decimal. The FAT volume's own sector and
cluster sizes come from its boot sector; `--blocksize` does not override them.

All recovery switches and `--repair` enable analysis automatically. `--deleted`
also enables analysis. With no action or verbosity option, the image is parsed
but no file listing is printed.

### Reading individual files

```sh
python3 fatdump.py --cat 'Documents/notes.txt' disk.img > notes.txt
```

Paths are relative to the FAT root, use `/` separators and have no leading `/`.
Lookup is case-insensitive and accepts either long names or DOS 8.3 names.
Wildcards are not supported. Contents are limited to the directory entry's
recorded file size and the available cluster chain.

The input banner goes to standard error when `--cat` is used. Automatic volume
selection messages, warnings and other reports can still appear on standard
output. For binary output, use an explicit partition or offset when needed,
avoid combining reporting options with `--cat`, and verify the result.

### Analysis and recovery

Analysis reports the volume base, cluster size, cluster-to-image mapping,
allocation counts and unreferenced chains. It compares each live file's recorded
size with the length of its FAT chain and reports invalid start clusters.
Cluster traversal is bounded by the filesystem geometry and FAT table;
chain loops and repeated directory starts are bounded to avoid endless traversal.

```sh
# Recover live and deleted files, orphan chains, free runs and file slack.
python3 fatdump.py --extract --save-deleted --save-orphans \
    --save-free --save-slack --savedir recovered disk.img

# Save every cluster not referenced by live entries individually.
python3 fatdump.py --save-clusters --savedir clusters-out disk.img

# Review possible file-size corrections without changing the image.
python3 fatdump.py --repair disk.img
```

Output is organized under `--savedir`:

| Location | Contents |
| --- | --- |
| Original relative directory paths | Extracted live files. |
| `deleted/` | Recovered deleted files, with a `deleted-` name prefix. |
| `orphans/orphan-XXXXXXXX` | Unreferenced portions of allocated FAT chains. |
| `clusters/cluster-XXXXXXXX` | Individual clusters not referenced by live entries. |
| `free/free-XXXXXXXX-XXXXXXXX` | Contiguous free-cluster runs, named by inclusive start and end cluster. |
| `slack/` | Data beyond logical file sizes, named with a `-leftover` suffix. |

Cluster numbers in output filenames are hexadecimal. Names and each directory
component are sanitized to ASCII letters, digits, `.`, `,`, `_` and `-`; other
character sequences become `_`. Existing output names receive a numeric suffix
instead of being overwritten. Empty directories and original FAT timestamps
and attributes are not recreated.

Recovery has these limits:

* Deleted entries may retain a long name, but the first character of a deleted
  short name has been lost. Deleted-file contents may already be overwritten.
* Recovery follows whatever FAT links remain. When the first FAT entry has been
  cleared, traversal currently still returns that first cluster; a multi-cluster
  deleted file can therefore be recovered only partially. Do not rely on this
  version to reconstruct a cleared chain or recover fragmented deleted files.
* A short recovery reports the recovered byte count. A plausible name and size
  do not establish that the recovered contents are intact.
* Orphans are defined relative to live files and directories, including the
  FAT32 root directory. Chains can overlap live data; orphan output contains
  only their unreferenced clusters.
* Free runs, orphan chains and individual-cluster dumps contain cluster data
  without a known original file size. Slack includes all chain bytes after the
  recorded end, including surplus clusters. Combining recovery switches can
  save the same bytes in several forms.
* `--repair` cannot infer an exact original file size from a chain alone. It
  prints a consistent size range for mismatched nonempty chains and an
  upper-bound patch suggestion when the recorded size exceeds chain capacity.
  Suggested commands refer to an external `hexedit` tool and are never executed.
* The tool reads one FAT copy: the FAT32 active copy when specified, otherwise
  the first. It does not reconcile FAT copies or perform a complete filesystem
  repair or validation of damaged long-name sequences.

### Images with omitted sectors

`--badblocks` is for a condensed image in which unreadable sectors were omitted
entirely. It inserts zero-filled logical sectors at the listed positions and
maps later reads back to the shorter input file.

```sh
python3 fatdump.py --badblocks 12,0x40,65 --blocksize 512 --analyze condensed.img
```

Sector numbers are zero-based and refer to the whole logical input before any
partition or volume offset is applied. Do not use this option for an image that
already contains zero-filled placeholders for unreadable sectors. Reported
image offsets describe the reconstructed logical image, rather than byte
positions in the condensed physical file. Missing data remains zero-filled.

### Multiple inputs, directories, URLs and standard input

```sh
python3 fatdump.py --listfiles first.img second.img
python3 fatdump.py --recurse --skiplinks --listfiles images/
python3 fatdump.py --listfiles https://example.com/disk.img
cat disk.img | python3 fatdump.py --listfiles -
```

`--recurse` controls discovery of image files in host directories. FAT directory
listing and extraction already traverse subdirectories without it. Directory
search attempts to parse every discovered input; it does not filter by extension.
Use separate output directories when extracting several images if their names
and paths need to remain associated with their source images.

Standard input (`-`) is buffered into a seekable temporary file, staying in
memory up to 16 MiB before spilling to disk. URL inputs require `urlstream`.
URL enumeration currently yields a URL twice, so it may be processed twice.

For named files and URLs, processing errors are printed and processing normally
continues with subsequent inputs. These caught errors do not currently produce
a nonzero exit status. `--debug` stops on a caught error with a traceback;
standard-input processing errors are not handled by that per-input catch.

## History

The project previously included `fatinfo.pl`, an older Perl tool for inspecting
and recovering data from FAT images. It has been removed; `fatdump.py` is the
Python successor.

## Author

Willem Hengeveld <itsme@xs4all.nl>
