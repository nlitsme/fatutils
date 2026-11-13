#!/usr/bin/python3
# updated by chatgpt gpt-5
"""
Author: Willem Hengeveld <itsme@xs4all.nl>

Inspect and recover files and unreferenced space from damaged FAT images.
"""
from __future__ import division, print_function
import struct
import os
import os.path
import re
from binascii import b2a_hex
import datetime
import sys


class FileSection:
    """Seekable, bounded view of an image; offsets are relative to the volume."""
    def __init__(self, fh, start, length):
        self.fh, self.start, self.length, self.pos = fh, start, length, 0

    def seek(self, offset, whence=0):
        pos = (offset if whence == 0 else self.pos + offset if whence == 1
               else self.length + offset if whence == 2 else None)
        if pos is None or pos < 0:
            raise ValueError("invalid section seek")
        self.pos = pos
        return pos

    def tell(self):
        return self.pos

    def read(self, size=-1):
        size = max(0, self.length-self.pos) if size < 0 else max(0, min(size, self.length-self.pos))
        self.fh.seek(self.start+self.pos)
        data = self.fh.read(size)
        self.pos += len(data)
        return data


try:
    from PartialStream import FileSection  # use the author's implementation when installed
except ImportError:
    pass

try:
    from efidump import mbrtypelist
except ImportError:
    mbrtypelist = {}


FAT_PARTITION_TYPES = {1, 4, 6, 11, 12, 14, 17, 20, 27, 28, 30}


def mbr_partitions(fh, blocksize):
    fh.seek(0)
    mbr = fh.read(512)
    if len(mbr) != 512 or mbr[510:] != b'\x55\xaa':
        return []
    return [(i, *struct.unpack_from('<LL', mbr, 446+16*i+8), mbr[446+16*i+4])
            for i in range(4) if mbr[446+16*i+4] and
            struct.unpack_from('<L', mbr, 446+16*i+12)[0]]


def looks_like_fat(data):
    if len(data) < 90:
        return False
    legacy = (data[3:11] == b'MSWIN4.1' and
              (data[54:62] in (b'FAT12   ', b'FAT16   ') or
               data[82:90] == b'FAT32   '))
    bps, spc, reserved, nfats = struct.unpack_from('<HBHB', data, 11)
    return legacy or (data[0] in (0xeb, 0xe9) and
            bps in (512, 1024, 2048, 4096) and spc > 0 and
            spc & (spc-1) == 0 and reserved > 0 and 1 <= nfats <= 4 and
            (data[510:512] == b'\x55\xaa' or
             b'FAT' in (data[54:62], data[82:90])))


def find_volume(fh, args):
    if args.partition is not None and args.offset:
        raise ValueError("--partition and --offset cannot be combined")
    if args.partition is not None or args.offset:
        if args.partition is not None:
            parts = mbr_partitions(fh, args.blocksize or 512)
            for idx, start, count, typ in parts:
                if idx == args.partition:
                    return FileSection(fh, start*(args.blocksize or 512), count*(args.blocksize or 512)), start*(args.blocksize or 512)
            raise ValueError("MBR partition %d does not exist" % args.partition)
        end = fh.seek(0, 2)
        return FileSection(fh, args.offset, end-args.offset), args.offset
    fh.seek(0)
    if looks_like_fat(fh.read(512)):
        return fh, 0
    parts = mbr_partitions(fh, args.blocksize or 512)
    if args.verbose and parts:
        for idx, start, count, typ in parts:
            print('partition %d: type 0x%02x %s, start 0x%x, size 0x%x'
                  % (idx, typ, mbrtypelist.get(typ, ''),
                     start*(args.blocksize or 512), count*(args.blocksize or 512)))
    for idx, start, count, typ in parts:
        if typ not in FAT_PARTITION_TYPES:
            continue
        offset = start*(args.blocksize or 512)
        fh.seek(offset)
        if looks_like_fat(fh.read(512)):
            print("using FAT partition %d at offset 0x%x" % (idx, offset))
            return FileSection(fh, offset, count*(args.blocksize or 512)), offset
    for offset in (0x40, 0x70000, 0x70040):
        fh.seek(offset)
        if looks_like_fat(fh.read(512)):
            print("using FAT boot sector at offset 0x%x" % offset)
            end = fh.seek(0, 2)
            return FileSection(fh, offset, end-offset), offset
    raise ValueError("no FAT boot sector found; specify --offset or --partition")

class Bootsector:
    """
    Parse a FAT filesystem Bootsector.
    """

    def dump(self):
        for k in dir(self):
            if k.startswith('_'): continue
            v = getattr(self, k)
            if type(v) in (str, int, bytes):
                print(f"{k}\t{v}")

    class ClusterReader:
        """
        Object which provides access by cluster number
        """
        def __init__(self, fh, cluster2Offset, clusterSize):
            self.fh = fh
            self.cluster2Offset = cluster2Offset 
            self.clusterSize = clusterSize


        def read(self, nr):
            self.fh.seek(self.cluster2Offset + (nr-2)*self.clusterSize)
            return self.fh.read(self.clusterSize)

    def __init__(self, data):
        """
        constructor: takes a 512 byte array of bootsector data.
        """
        jump, oemname, bytesPerSector, sectorsPerCluster, nrReservedSectors,  \
            nrFATs, rootdirSize, totalSectors16, media, sectorsPerFAT16, sectorsPerTrack, nrHeads, nrHiddenSectors, \
            totalSectors32 = struct.unpack_from("<3s8sHBHBHHBHHHLL", data, 0)
        if bytesPerSector == 0:
            raise Exception("not a FAT boot sector")
        if sectorsPerCluster == 0:
            raise ValueError('invalid sectors per cluster: 0')
        # note: rootdirsize is speced to result in rootdirs which are a multiple of 1k bytes
        if bytesPerSector&(bytesPerSector-1):
            print("WARNING: correcting bytes/sector from 0x%x to 0x200" % bytesPerSector)
            bytesPerSector = 512

        totalSectors = totalSectors16 or totalSectors32
        nrSectorsInRootdir = int(((rootdirSize*32)+bytesPerSector-1) / bytesPerSector)
        self.sectorsPerFAT = sectorsPerFAT16
        self.bytesPerSector = bytesPerSector
        self.sectorsPerCluster = sectorsPerCluster
        self.rootdirSize = rootdirSize
        rootCluster = None
        rootSector = None

        def isFat32():
            # note: officially fat type is determined by nr of clusters:
            #   0..0xFF4 -> fat12
            #   0xFF5..0xFFF4 -> fat16
            #   0xFFF5..0xFFFFFF4 -> fat32
            return nrReservedSectors>1 and rootdirSize==0 and sectorsPerFAT16==0 and totalSectors16==0 and totalSectors32!=0
        self.active_fat = None
        self.totalSectors = totalSectors
        self.nrFATs = nrFATs
        self.reservedSectors = nrReservedSectors
        if isFat32():
            sectorsPerFAT32, extFlags, fsVer, rootCluster, fsInfo, backupBootSectorNr, reserved, drvnum, reserved1, bootSig, volumeID, volumeLabel, filesysType = \
                struct.unpack_from("<LHHLHH12sBBBL11s8s", data, 36)
            if extFlags&0x80:
                self.active_fat = extFlags&15
            self.sectorsPerFAT = sectorsPerFAT32
        else:
            rootSector = nrReservedSectors + nrFATs*self.sectorsPerFAT
            drvNum, reserved1, bootSig, volumeID, volumeLabel, filesysType = \
                struct.unpack_from("<BBBL11s8s", data, 36) 

        volumeLabel = volumeLabel.rstrip(b"\x00\x20").decode('latin1', 'ignore')
        filesysType = filesysType.rstrip(b"\x00\x20").decode('latin1', 'ignore')

        self.clusterTwoSector = nrReservedSectors + nrFATs*self.sectorsPerFAT + nrSectorsInRootdir
        self.totalDataSectors = totalSectors - self.clusterTwoSector
        if self.totalDataSectors < 0:
            raise ValueError('filesystem data starts after its declared end')
        self.totalClusters = int(self.totalDataSectors / sectorsPerCluster)

        self.fats = [ nrReservedSectors + _ * self.sectorsPerFAT for _ in range(nrFATs) ]
        self.rootCluster = rootCluster
        self.rootSector = rootSector
        self.volumeLabel = volumeLabel
        self.mediatype = media

        def officialFatType():
            if self.totalClusters<=0xFF4:
                return "FAT12"
            elif self.totalClusters<=0xFFF4:
                return "FAT16"
            elif self.totalClusters<=0xFFFFFF4:
                return "FAT32"
            else:
                print("nclusters = %d" % self.totalClusters)
                raise Exception("cluster count too large")


        self.fattype = officialFatType()

        if self.fattype != filesysType or (self.fattype=="FAT32")!=isFat32():
            print("fat type expectation mismatch: nrclusters->%s, stored->%s, fields->%s" % (self.fattype, filesysType, "FAT32" if isFat32() else "FAT12/16"))

    def getFATOffset(self):
        """
        Returns byte offset of the active FAT.
        """
        return self.fats[self.active_fat or 0] * self.bytesPerSector

    def getClusterReader(self, fh):
        """
        Creates a cluster reader object.
        """
        return self.ClusterReader(fh, self.clusterTwoSector*self.bytesPerSector, self.sectorsPerCluster*self.bytesPerSector)


class FatReader:
    """
    Decodes the FAT table.
    """
    # badcluster marker: 0x0FF7, 0xFFF7, 0x0FFFFFF7
    # endofchain marker: 0x0FFF, 0xFFFF, 0x0FFFFFFF
    # first cluster contains  mediatype-byte + all one bits
    # second cluster contains EOC mark ( with optionally some volume bits )
    #    0x8000/0x08000000 -> volume is clean: properly shut down
    #    0x4000/0x04000000 -> no hardware errors encountered

    def __init__(self, typ, data):
        """
        Constructor
        """
        # note: the f0/f8  is the mediatype, 0xf0 for floopy, 0xf8 for hdd.
        # fat12: f0 ff ff 03 40 00
        # fat12: f8 ff ff ff 0f 00  when a one-cluster file starts at
        #        cluster 2 (FAT[2] = 0xfff, FAT[3] = 0); bytes 2-3 then
        #        look like FAT16's reserved entries. The fixed FAT12 root
        #        directory does not occupy a data cluster.
        # fat16: f0 ff ff ff ff ff
        # fat32: f8 ff ff 0f ff ff ff 0f f8 ff ff 0f 
        # The BPB cluster count determines the FAT type; these bytes only
        # provide a consistency check and cannot always distinguish 12/16.
        def typeFromData():
            dw0, dw1 = struct.unpack_from("<LL", data)
            if dw0&0xFFFFFF00 == 0x0FFFFF00 and dw1&0x03FFFFFF == 0x03FFFFFF:
                return "FAT32"
            hw0, hw1 = struct.unpack_from("<HH", data)
            if hw0&0xFF00 == 0xFF00 and hw1&0x3FFF == 0x3FFF:
                return "FAT16"
            b0, b1, b2 = struct.unpack_from("BBB", data)
            if b1 == b2 == 0xFF:
                return "FAT12"
            else:
                print(b2a_hex(data[:16]))
                raise Exception("data:unknown fat type")
        detected = typeFromData()
        # A FAT12 table with allocated cluster 2 can match the FAT16 probe.
        # The BPB cluster count, not these reserved entries, chooses decoding.
        if detected != typ and (typ, detected) != ('FAT12', 'FAT16'):
            print(b2a_hex(data[:16]))
            print("fat type from header(%s) is different from that of the fat(%s)" % (typ, detected))

        self.mediatype = data[0]

        self.typ = typ
        if typ == "FAT32":
            self.decodeFat32(data)
        elif typ == "FAT16":
            self.decodeFat16(data)
        elif typ == "FAT12":
            self.decodeFat12(data)
        else:
            raise Exception("unknown fat type")

    def decodeFat32(self, data):
        """
        Decode FAT32, ignoring the reserved top four bits of each entry.
        """
        self.fat = tuple(v & 0x0fffffff for v in struct.unpack("<%dL" % (len(data)//4), data))

    def decodeFat16(self, data):
        """
        decodes the raw FAT bytes into an FAT16 cluster list.
        """
        self.fat = struct.unpack("<%dH" % (len(data)//2), data)

    def decodeFat12(self, data):
        """
        decodes the raw FAT bytes into an FAT32 cluster list.
        """
        b = data
        def first(b0, b1):
            return b0 + (b1&15)*256
        def second(b1, b2):
            return (b1>>4) + b2*16
        self.fat = []
        for i in range(0, len(b)-2, 3):
            self.fat.extend((first(b[i], b[i+1]), second(b[i+1], b[i+2])))
        if len(b) % 3 == 2:
            self.fat.append(first(b[-2], b[-1]))

    def isValidCluster(self, c):
        """
        Check if the value in `c` is an invalid cluster marker.
        """
        if c<2:
            return False
        if self.typ == "FAT12":
            return c<=0xFEF and c<len(self.fat) and c<self.cluster_limit
        elif self.typ == "FAT16":
            return c<=0xFFEF and c<len(self.fat) and c<self.cluster_limit
        elif self.typ == "FAT32":
            return c<=0x0FFFFFEF and c<len(self.fat) and c<self.cluster_limit

    def EOCMarker(self):
        """
        Return the End-of-Chain marker for the current FAT type.
        """
        if self.typ == "FAT12":
            return 0x0FFF
        elif self.typ == "FAT16":
            return 0xFFFF
        elif self.typ == "FAT32":
            return 0xFFFFFFF

    def followChain(self, c):
        """
        Enumerates all clusters in the chain starting at cluster `c`.
        """
        seen = set()
        while self.isValidCluster(c) and c not in seen:
            seen.add(c)
            yield c
            c = self.fat[c]

    def chains(self):
        """Enumerate allocated chains, including branches and loops, once each."""
        used = {c for c in range(2, self.cluster_limit) if self.fat[c]}
        predecessors = {self.fat[c] for c in used if self.isValidCluster(self.fat[c])}
        visited = set()
        for start in sorted(used - predecessors) + sorted(used):
            if start in visited:
                continue
            chain = []
            c = start
            while c in used and c not in visited:
                chain.append(c)
                visited.add(c)
                c = self.fat[c]
            yield chain, c

    def findChains(self):
        """
        Constructs a reverse chain map, then returns all chains ending in an 'EOC' marker.
        """
        rev = {}
        for i, n in enumerate(self.fat):
            if i>1:
                rev.setdefault(n,[]).append(i)
        eoc = self.EOCMarker()
        return rev.get(eoc, [])

    def dump(self):
        """
        Summarize all chains found in this FAT.
        """
        for chain, terminator in self.chains():
            print('chain', chain, '->', hex(terminator))

    def dumpChainBranches(self):
        """
        Find all chains with overlapping clusters.
        """
        rev = {}
        for i, n in enumerate(self.fat):
            if i>1:
                rev.setdefault(n,[]).append(i)

        eoc = self.EOCMarker()
        for k,v in rev.items():
            if self.isValidCluster(k) and len(v)>1:
                print("chain branch found: %d -> %s" % (k, v))


class FatDirectory:
    """
    Represent a single directory.
    """
    class DirEntry:
        def __init__(self, data, ofs):
            def decode_date(dt):
                if dt==0:
                    return datetime.datetime(1980,1,1)
                year, mon, day = (dt>>9), (dt>>5)&15, dt&31
                try:
                    return datetime.datetime(year+1980, mon, day)
                except Exception as e:
                    print("error decoding date %d-%d-%d" % (year+1980, mon, day))
                    return datetime.datetime(1980,1,1)
            def decode_time(tm):
                hour, minute, bisecond = tm>>11, (tm>>5)&63, tm&31
                return datetime.timedelta(hours=hour, minutes=minute, seconds=bisecond*2)
            def decode_usec(us):
                return datetime.timedelta(microseconds=us*1000000)

            self.name, \
            self.attr, \
            self.ntres, \
            subseconds, \
            createTime, \
            createDate, \
            accessDate, \
            clusterH, \
            updateTime, \
            updateDate, \
            clusterL, \
            self.filesize = struct.unpack_from("<11sBBBHHHHHHHL", data, ofs)

            self.isdeleted = self.name[0]==b'\xe5'[0]
            if self.isdeleted:
                self.name = b'?'+self.name[1:]
            if self.name[0]==b'\x05'[0]:
                self.name = b'\xe5' + self.name[1:]

            self.name = self.name.decode('latin1', 'ignore')
            self.offset = ofs

            self.cluster = clusterH*65536+clusterL

            # name[0]==0xE5 -> deleted
            # name[0]==0x00 -> unused
            # name[0]==0x05 -> actual char: 0xe5
            #
            # attr: 1=readonly, 2=hidden, 4=system, 8=volumeid, 16=directory, 32=archive, 15=longname

            # date: dayOfMonth = d&31, monthOfYear = (d>>5)&15, year-1980 = (d>>9)
            # time: seconds = d&31, minutes = (d>>5)&63, hours = (d>>11)

            self.timeCreated = decode_date(createDate) + decode_time(createTime) + decode_usec(subseconds*0.01)
            self.timeUpdated = decode_date(updateDate) + decode_time(updateTime)
            self.dateAccessed = decode_date(accessDate)

        def eightdotthree(self):
            """
            return the 8.3 DOS filename.
            """
            eight = self.name[:8].rstrip()
            three = self.name[8:].rstrip()
            if three:
                return eight+"."+three
            else:
                return eight

        def attributes(self):
            """
            retuns a string representation for the file attributes.
            """
            return "%s%s%s%s%s" % ("-R"[1&self.attr], "-H"[1&self.attr>>1], "-S"[1&self.attr>>2], "-A"[1&self.attr>>5], "L" if 1&self.attr>>3 else "D" if 1&self.attr>>4 else "F")

        def isdir(self):
            return 1&(self.attr>>4)
        def islabel(self):
            return 1&(self.attr>>3)
        def isfile(self):
            return not self.isdir() and not self.islabel()

    class LongNameEntry:
        """
        A Long name entry
        """
        def __init__(self, data, ofs):
            self.order, \
            self.part1, \
            self.attr, \
            self.type, \
            self.chksum, \
            self.part2, \
            self.clusterL, \
            self.part3 = struct.unpack_from("<B10sBBB12sH4s", data, ofs)
            self.name = self.part1+self.part2+self.part3

            self.isdeleted = self.order == 0xE5

            # order.bit6 = lastentry
            # attr must be 15 ( longname )
            # type must be 0
            # clusterL must be 0

    class UnknownEntry:
        """
        An unknown dir entry
        """
        def __init__(self, data, ofs):
            self.data = data[ofs:ofs+32]

    def __init__(self, data):
        """
        Fat directory constructor.
        parses all entries found in `data`.
        """
        self.data = data
        self.entries = None

    def parsed_entries(self):
        if self.entries is None:
            self.entries = [self.parseentry(self.data, ofs)
                            for ofs in range(0, len(self.data)-31, 32)]
        return self.entries

    def parseentry(self, data, ofs):
        """
        decode a single entry.
        """
        if data[ofs] == 0xff or data[ofs+11]&0xc0:
            return None
        if data[ofs+11]==b'\x0f'[0]:
            if data[ofs+12]==b'\x00'[0]:
                return self.LongNameEntry(data, ofs)
            else:
                return self.UnknownEntry(data, ofs)
        elif data[ofs]!=b'\x00'[0]:
            return self.DirEntry(data, ofs)

    def truncate_name(self, name):
        """
        strip trailing bytes from a long name
        """
        iend = name.find(b'\x00\x00\xff\xff')
        if iend>=0:
            return name[:iend]
        if name[-2:] == b'\x00\x00':
            return name[:-2]
        return name

    def enum(self):
        """
        Yield all entries in a directory
        """
        name = None
        for ent in self.parsed_entries():
            if ent is None:
                name = None
            elif isinstance(ent, self.LongNameEntry):
                if ent.isdeleted:
                    if name is None:
                        name = ent.name
                    else:
                        name = ent.name + name
                elif ent.order&0x40:
                    if name is None:
                        name = ent.name
                    else:
                        print("WARNING: unexpected: already collecting name: '%s' + '%s'" % (ent.name, name))
                else:
                    if name is not None:
                        name = ent.name + name
                    else:
                        print("WARNING: did not find end of name: '%s' + '%s'" % (name, ent.name))
            elif isinstance(ent, self.DirEntry):
                if name:
                    ent.longname = self.truncate_name(name).decode('utf-16le', 'replace')
                else:
                    ent.longname = None
                yield ent
                name = None
            else:
                print("WARNING: unknown entry: %s" % b2a_hex(ent.data))
                name = None

class FatFilesystem:
    """
    Parse, and access contents of a fat filesystem.
    """
    def __init__(self, fh):
        fh.seek(0)
        hdrdata = fh.read(512)
        self.boot = Bootsector(hdrdata)

        if self.boot.sectorsPerFAT == 0:
            raise Exception("missing FAT")

        fh.seek(self.boot.getFATOffset())
        fatdata = fh.read(self.boot.sectorsPerFAT * self.boot.bytesPerSector)

        self.fat = FatReader(self.boot.fattype, fatdata)
        self.fat.cluster_limit = min(len(self.fat.fat), self.boot.totalClusters+2)

        if self.fat.typ != self.boot.fattype:
            print(f"boot({self.boot.fattype}) != fat({self.fat.typ}) fattype mismatch")
            

        if self.boot.mediatype != self.fat.mediatype:
            print(f"boot({self.boot.mediatype:02x}) != fat({self.fat.mediatype:02x}) mediatype")

        self.rd = self.boot.getClusterReader(fh)
        self.fh = fh
        self.base_offset = 0
        if self.boot.fattype=="FAT32":
            dirdata = b''.join(self.getchaindata(self.boot.rootCluster))
            self.rootOffset = self.rd.cluster2Offset + (self.boot.rootCluster-2)*self.rd.clusterSize
        else:
            fh.seek(self.boot.rootSector*self.boot.bytesPerSector)
            dirdata = fh.read(self.boot.rootdirSize*32)
            self.rootOffset = self.boot.rootSector*self.boot.bytesPerSector
        self.root = FatDirectory(dirdata)

    def getchaindata(self, cluster):
        for c in self.fat.followChain(cluster):
            yield self.rd.read(c)

    def entries_with_offsets(self, include_deleted=False):
        """Yield path, entry, absolute image offset; keep directory cycles bounded."""
        visited_dirs = set()
        cluster_size = self.rd.clusterSize

        def walk(directory, path, clusters, root=False, deleted=False):
            for ent in directory.enum():
                short = ent.eightdotthree()
                if short in ('.', '..'):
                    continue
                if ent.isdeleted and not include_deleted:
                    continue
                name = ent.longname or short
                if ent.isdeleted:
                    name = 'deleted-' + name.lstrip('?')
                if root and self.boot.fattype != 'FAT32':
                    offset = self.rootOffset + ent.offset
                else:
                    ix, rem = divmod(ent.offset, cluster_size)
                    offset = (self.rd.cluster2Offset + (clusters[ix]-2)*cluster_size + rem
                              if ix < len(clusters) else None)
                yield path, ent, offset, name
                if ent.isdir() and self.fat.isValidCluster(ent.cluster) and ent.cluster not in visited_dirs:
                    visited_dirs.add(ent.cluster)
                    chain = list(self.fat.followChain(ent.cluster))
                    if ent.isdeleted and not chain:
                        chain = [ent.cluster]
                    if chain:
                        data = b''.join(self.rd.read(c) for c in chain)
                        yield from walk(FatDirectory(data), path+[name], chain, deleted=ent.isdeleted)

        rootchain = (list(self.fat.followChain(self.boot.rootCluster))
                     if self.boot.fattype == 'FAT32' else [])
        if rootchain:
            visited_dirs.add(rootchain[0])
        yield from walk(self.root, [], rootchain, root=True)

    def recursedir(self, dir, path=[]):
        """
        recursively yield all non deleted dir entries.
        """
        for p, ent, _, _ in self.entries_with_offsets():
            yield p, ent

    def findentry(self, dir, path):
        """
        recurse directories until path is found.

        note: currently no wildcard matching. i would need to change
        this function to return multiple results.
        And not raise exceptions in some cases.
        """
        cur = path[0].lower()
        for ent in dir.enum():
            if (ent.longname and cur == ent.longname.lower()) or cur == ent.eightdotthree().lower():
                if len(path)==1:
                    return ent
                if ent.attr&0x10:
                    dirdata = b''.join(self.getchaindata(ent.cluster))
                    return self.findentry(FatDirectory(dirdata), path[1:])
                raise Exception("Not a directory")
        raise Exception("file not found")


def listfiles(fs):
    for path, ent in fs.recursedir(fs.root):
        longname = ent.longname or ent.eightdotthree()
        print("%-26s %12d [%08x] %s %s/%s" % (ent.timeCreated, ent.filesize, ent.cluster, ent.attributes(), "/".join(path), longname))

def catfile(fs, fname):
    ent = fs.findentry(fs.root, fname.split("/"))
    n = ent.filesize
    for block in fs.getchaindata(ent.cluster):
        want = min(n, len(block))
        sys.stdout.buffer.write(block[:want])
        n -= want
        if n <= 0:
            break

def makesafe(pathitem):
    pathitem = re.sub(r'[^a-zA-Z0-9.,_-]+', '_', pathitem)
    if pathitem in ('', '.', '..'):
        return '_'
    return pathitem

def extractfiles(fs, savedir):
    if not savedir:
        savedir = "."
    for path, ent in fs.recursedir(fs.root):
        longname = ent.longname or ent.eightdotthree()
        #print("%-26s %12d [%08x] %s %s/%s" % (ent.timeCreated, ent.filesize, ent.cluster, ent.attributes(), "/".join(path), longname))
        if not ent.isfile():
            print("skipping nonfile", longname)
            continue
        savepath = "/".join(makesafe(_) for _ in path)
        savename = makesafe(longname)
        os.makedirs(savedir + "/" + savepath, exist_ok=True)
        fullsavepath = savedir + "/" + savepath + "/" + savename
        if os.path.isfile(fullsavepath):
            print("File already exists: %s" % fullsavepath)
            continue
        n = ent.filesize
        with open(fullsavepath, "wb") as fh:
            for block in fs.getchaindata(ent.cluster):
                want = min(n, len(block))
                fh.write(block[:want])
                n -= want
        print("Saved %s" % fullsavepath)


def save_unique(directory, name, blocks):
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, makesafe(name))
    base, ext = os.path.splitext(target)
    n = 1
    while os.path.lexists(target):
        target = '%s-%d%s' % (base, n, ext)
        n += 1
    with open(target, 'xb') as output:
        for block in blocks:
            output.write(block)
    print('Saved %s' % target)


def analyze(fs, args):
    """Report consistency and optionally carve recoverable image data."""
    fat, boot = fs.fat, fs.boot
    csize = fs.rd.clusterSize
    referenced = set()
    active = set()
    print('sector 0 -> image offset 0x%x; cluster 2 -> sector 0x%x, image offset 0x%x'
          % (fs.base_offset, boot.clusterTwoSector, fs.base_offset+fs.rd.cluster2Offset))
    print('cluster size 0x%x; last data cluster %d -> image offset 0x%x; volume end 0x%x'
          % (csize, fat.cluster_limit-1,
             fs.base_offset+fs.rd.cluster2Offset+(fat.cluster_limit-2)*csize,
             fs.base_offset+boot.totalSectors*boot.bytesPerSector))

    if boot.fattype == 'FAT32':
        active.update(fat.followChain(boot.rootCluster))

    for path, ent, offset, name in fs.entries_with_offsets(args.deleted or args.save_deleted):
        label = '/' + '/'.join(path+[name])
        valid = fat.isValidCluster(ent.cluster)
        chain = list(fat.followChain(ent.cluster)) if valid else []
        if not ent.isdeleted:
            active.update(chain)
        referenced.update(chain)
        if args.listfiles:
            print('%-26s %12d [%08x] %s %s%s' %
                  (ent.timeCreated, ent.filesize, ent.cluster,
                   ent.attributes(), label, ' [deleted]' if ent.isdeleted else ''))
        if ent.isfile():
            needed = (ent.filesize + csize-1)//csize
            if not ent.isdeleted and needed != len(chain):
                print('%s: size %d expects %d clusters; FAT chain has %d'
                      % (label, ent.filesize, needed, len(chain)))
                if args.repair and offset is not None and chain:
                    lower, upper = (len(chain)-1)*csize+1, len(chain)*csize
                    print('  size consistent with chain: %d..%d; entry size field at image offset 0x%x'
                          % (lower, upper, fs.base_offset+offset+28))
                    if needed > len(chain):
                        print('  upper-bound repair: hexedit %s -pd %08x:%08x'
                              % (args.image_name, fs.base_offset+offset+28, upper))
            if ent.filesize and not valid:
                print('%s: unknown start cluster %d' % (label, ent.cluster))
            if (args.extract and not ent.isdeleted) or (ent.isdeleted and args.save_deleted):
                target = args.savedir or '.'
                if ent.isdeleted:
                    target = os.path.join(target, 'deleted')
                target = os.path.join(target, *(makesafe(p) for p in path))
                # The FAT chain of a deleted file is normally cleared. Carve
                # contiguous free clusters only when the whole span is in range.
                if ent.isdeleted and not chain and valid and ent.filesize:
                    span = range(ent.cluster, ent.cluster+needed)
                    if all(fat.isValidCluster(c) and fat.fat[c] == 0 and c not in active
                           for c in span):
                        chain = list(span)
                    else:
                        print('%s: deleted file has no intact chain; skipping uncertain data' % label)
                if not ent.filesize or chain:
                    def file_blocks():
                        remaining = ent.filesize
                        for c in chain:
                            if remaining <= 0:
                                break
                            block = fs.rd.read(c)
                            yield block[:remaining]
                            remaining -= len(block)
                        if remaining > 0:
                            print('%s: recovered %d/%d bytes' %
                                  (label, ent.filesize-remaining, ent.filesize))
                    save_unique(target, name, file_blocks())
            if args.save_slack and chain and ent.filesize < len(chain)*csize:
                slack_start = ent.filesize
                target = os.path.join(args.savedir or '.', 'slack',
                                      *(makesafe(p) for p in path))
                def slack_blocks():
                    for i, c in enumerate(chain):
                        if (i+1)*csize > slack_start:
                            yield fs.rd.read(c)[max(0, slack_start-i*csize):]
                save_unique(target, name+'-leftover', slack_blocks())
        elif ent.isdir() and not ent.isdeleted and not valid:
            print('%s: directory has invalid start cluster %d' % (label, ent.cluster))

    allocated = {c for c in range(2, fat.cluster_limit) if fat.fat[c]}
    free = {c for c in range(2, fat.cluster_limit) if not fat.fat[c]}
    orphans = allocated-active
    if allocated:
        last = max(allocated)
        print('last allocated cluster 0x%x -> image offset 0x%x'
              % (last, fs.base_offset+fs.rd.cluster2Offset+(last-2)*csize))
    print('clusters: %d total, %d allocated, %d free, %d referenced, %d orphaned'
          % (fat.cluster_limit-2, len(allocated), len(free), len(active), len(orphans)))
    printed = set()
    for chain, terminator in fat.chains():
        missing = [c for c in chain if c in orphans]
        if missing:
            printed.update(missing)
            print('unreferenced chain: start 0x%x, %d clusters, %d unreferenced; next 0x%x'
                  % (chain[0], len(chain), len(missing), terminator))
            if args.save_orphans:
                save_unique(os.path.join(args.savedir or '.', 'orphans'),
                            'orphan-%08x' % chain[0], (fs.rd.read(c) for c in missing))
    # A branch into a live file can leave a detached prefix with no EOC.
    if printed != orphans:
        print('additional unreferenced clusters: %d' % len(orphans-printed))
    if args.save_clusters:
        target = os.path.join(args.savedir or '.', 'clusters')
        for c in sorted((allocated | free) - active):
            save_unique(target, 'cluster-%08x' % c, (fs.rd.read(c),))
    if args.save_free:
        target = os.path.join(args.savedir or '.', 'free')
        runs = []
        for c in sorted(free):
            if runs and c != runs[-1]+1:
                save_unique(target, 'free-%08x-%08x' % (runs[0], runs[-1]),
                            (fs.rd.read(n) for n in runs))
                runs = []
            runs.append(c)
        if runs:
            save_unique(target, 'free-%08x-%08x' % (runs[0], runs[-1]),
                        (fs.rd.read(n) for n in runs))


def processfs(args, fs):
    if args.analyze or args.extract or args.deleted or args.save_deleted or args.save_orphans or args.save_clusters or args.save_free or args.save_slack or args.repair:
        analyze(fs, args)
    elif args.listfiles:
        listfiles(fs)
    if args.cat:
        catfile(fs, args.cat)
    #print(fs.fat.findChains())
    if args.verbose:
        fs.boot.dump()
        fs.fat.dump()
        fs.fat.dumpChainBranches()

def DirEnumerator(args, path):
    """
    recursively enumerate files and directories in a path.
    """
    for d in os.scandir(path):
        try:
            if d.name == '.' or d.name == '..':
                pass
            elif d.is_symlink() and args.skiplinks:
                pass
            elif d.is_dir() and args.recurse:
                for f in DirEnumerator(args, d.path):
                    yield f
            else:
                yield d.path
        except Exception as e:
            print("EXCEPTION %s accessing %s/%s" % (e, path, d.name))


def EnumeratePaths(args, paths):
    """
    enumerate all files and dirs in the list of paths.
    optionally recursively.
    """
    for fn in paths:
        try:
            if fn.find("://") in (3,4,5):
                yield fn
            if os.path.islink(fn) and args.skiplinks:
                pass
            elif os.path.isdir(fn) and args.recurse:
                for f in DirEnumerator(args, fn):
                    yield f
            else:
                yield fn
        except Exception as e:
            print("EXCEPTION %s accessing %s" % (e, fn))


def binary_search(a, k):
    """
    Do a binary search in an array of objects ordered by '.key'

    returns the largest index for which:  a[i].key <= k

    like c++: a.upperbound(k)--
    """
    first, last = 0, len(a)
    while first < last:
        mid = (first + last) >> 1
        if k < a[mid].key:
            last = mid
        else:
            first = mid + 1
    return first - 1


class BadblockReader:
    """
    Read an image with missing sectors omitted from the underlying file.
    --badblocks lists their logical sector numbers; each missing sector reads
    as zeroes, and higher logical sectors shift back in the physical file.
    """
    def __init__(self, badblocks, blocksize, fh):
        self.fh = fh
        self.badblocks = sorted(set(badblocks))
        self.blocksize = blocksize

        self.pos = 0

    def read(self, size):
        if size < 0:
            size = self.seek(0, 2)-self.pos
        blocks = []
        while size > 0:
            chunk = self.readsome(size)
            if not chunk:
                break
            blocks.append(chunk)
            size -= len(chunk)
        return b''.join(blocks)
        
    def seek(self, ofs, whence=0):
        if whence == 2:
            end = self.fh.seek(0, 2)+len(self.badblocks)*self.blocksize
            self.pos = end+ofs
        elif whence == 1:
            self.pos += ofs
        elif whence == 0:
            self.pos = ofs
        else:
            raise ValueError('invalid whence')
        if self.pos < 0:
            raise ValueError('negative seek')
        return self.pos

    def tell(self):
        return self.pos

    def readsome(self, size):
        from bisect import bisect_left, bisect_right
        block, inside = divmod(self.pos, self.blocksize)
        pos = bisect_left(self.badblocks, block)
        nextbad = self.badblocks[pos] if pos < len(self.badblocks) else None
        if nextbad == block:
            data = bytes(min(size, self.blocksize-inside))
        else:
            length = size if nextbad is None else min(size, (nextbad-block)*self.blocksize-inside)
            missing_before = bisect_right(self.badblocks, block-1)
            self.fh.seek(self.pos-missing_before*self.blocksize)
            data = self.fh.read(length)
        self.pos += len(data)
        return data

def makereader(args, fh):
    blocksize = args.blocksize or 512
    if args.badblocks:
        bblist = [ int(_.strip(), 0) for _ in args.badblocks.split(",") ]
        fh = BadblockReader(bblist, blocksize, fh)
    return find_volume(fh, args)

class StdinReader:
    def __init__(self, fh):
        self.pos = 0
        self.fh = fh
    def seek(self, ofs, whence=0):
        if whence==0:
            if ofs<self.pos:
                raise Exception("invalid offset")
            if self.pos < ofs:
                self.fh.read(ofs-self.pos)
                self.pos = ofs
        elif whence==1:
            if ofs<0:
                raise Exception("invalid offset")
            self.fh.read(ofs)
            self.pos += ofs
        elif whence==2:
            raise Exception("invalid offset")
        return self.pos
    def read(self, n):
        res = self.fh.read(n)
        if res:
            self.pos += len(res)
        return res
    def tell(self):
        return self.pos

def main():
    def auto_int(x): return int(x,0)
    import argparse

    parser= argparse.ArgumentParser(description='fatdump')
    parser.add_argument('--verbose', '-v', action='count', default = 0)
    parser.add_argument('--offset', '-o', type=auto_int, default = 0)
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories, when finding disk images')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='ignore symlinks')
    parser.add_argument('--listfiles', '-l', action='store_true', help='list files')
    parser.add_argument('--extract', '-x', action='store_true', help='extract live files')
    parser.add_argument('--analyze', '-a', action='store_true', help='report mapping, size mismatches, and unreferenced chains')
    parser.add_argument('--deleted', action='store_true', help='include deleted entries in listings and analysis')
    parser.add_argument('--save-deleted', action='store_true', help='carve deleted files where possible')
    parser.add_argument('--save-orphans', action='store_true', help='save unreferenced FAT chains')
    parser.add_argument('--save-clusters', action='store_true', help='save each cluster not used by a live file')
    parser.add_argument('--save-free', action='store_true', help='save contiguous runs of unallocated clusters')
    parser.add_argument('--save-slack', action='store_true', help='save data past the logical end of files')
    parser.add_argument('--repair', action='store_true', help='print suggested filesize patches; never modify image')
    parser.add_argument('--savedir', '-d', help='where to extract files to')
    parser.add_argument('--badblocks', type=str, help='comma-separated sector numbers missing from a condensed image')
    parser.add_argument('--blocksize', type=auto_int, help='the blocksize')
    parser.add_argument('--cat', '-c', type=str, help='cat a file to stdout')
    parser.add_argument('--partition', '-p', type=int, help='specify mbr partition nr')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('FILES', type=str, nargs='+', help='Files or URLs')
    args= parser.parse_args()

    if args.FILES:
        for fn in EnumeratePaths(args, args.FILES):
            if fn=='-':
                import tempfile
                args.image_name = fn
                with tempfile.SpooledTemporaryFile(max_size=16*1024*1024) as stdinfile:
                    while True:
                        chunk = sys.stdin.buffer.read(1024*1024)
                        if not chunk:
                            break
                        stdinfile.write(chunk)
                    reader, base = makereader(args, stdinfile)
                    fs = FatFilesystem(reader)
                    fs.base_offset = base
                    processfs(args, fs)
            else:

                print("==>", fn, "<==", file=sys.stderr if args.cat else sys.stdout)
                try:
                    args.image_name = fn
                    if fn.find("://") in (3,4,5):
                        import urlstream
                        with urlstream.open(fn) as fh:
                            reader, base = makereader(args, fh)
                            fs = FatFilesystem(reader)
                            fs.base_offset = base
                            processfs(args, fs)
                    else:
                        with open(fn, "rb") as fh:
                            reader, base = makereader(args, fh)
                            fs = FatFilesystem(reader)
                            fs.base_offset = base
                            processfs(args, fs)

                except Exception as e:
                    print("ERROR: %s" % e)
                    if args.debug:
                        raise


if __name__ == '__main__':
    main()
