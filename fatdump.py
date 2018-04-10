"""
Author: Willem Hengeveld <itsme@xs4all.nl>

Tool for listing the contents of a FAT filesystem
"""
from __future__ import division, print_function
import struct
import os
from binascii import b2a_hex
import datetime

class Bootsector:
    """
    Parse a FAT filesystem Bootsector.
    """

    class ClusterReader:
        """
        Object which provides access by cluster number
        """
        def __init__(self, fh, bootOffset, cluster2Offset, clusterSize):
            self.fh = fh
            self.bootOffset = bootOffset
            self.cluster2Offset = cluster2Offset 
            self.clusterSize = clusterSize

            print("cluster reader: off=%x, c2o=%x, cs=%x" % (self.bootOffset, self.cluster2Offset, self.clusterSize))

        def read(self, nr):
            self.fh.seek(self.bootOffset + self.cluster2Offset + (nr-2)*self.clusterSize)
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

        volumeLabel = volumeLabel.rstrip().decode('latin1', 'ignore')
        filesysType = filesysType.rstrip().decode('latin1', 'ignore')

        self.clusterTwoSector = nrReservedSectors + nrFATs*self.sectorsPerFAT + nrSectorsInRootdir
        self.totalDataSectors = totalSectors - self.clusterTwoSector
        self.totalClusters = int(self.totalDataSectors / sectorsPerCluster)

        self.fats = [ nrReservedSectors + _ * self.sectorsPerFAT for _ in range(nrFATs) ]
        self.rootCluster = rootCluster
        self.rootSector = rootSector
        self.volumeLabel = volumeLabel

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

    def getClusterReader(self, fh, bootOffset):
        """
        Creates a cluster reader object.
        """
        return self.ClusterReader(fh, bootOffset, self.clusterTwoSector*self.bytesPerSector, self.sectorsPerCluster*self.bytesPerSector)


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
        # fat12: f0 ff ff 03 40 00
        # fat16: f0 ff ff ff ff ff
        # fat32: f8 ff ff 0f ff ff ff 0f f8 ff ff 0f 
        #  -> the third byte determines the fat type
        def typeFromData():
            dw0, dw1 = struct.unpack_from("<LL", data)
            if dw0&0xFFFFFF00 == 0x0FFFFF00 and dw1&0x03FFFFFF == 0x03FFFFFF:
                return "FAT32"
            hw0, hw1 = struct.unpack_from("<HH", data)
            if hw0&0xFF00 == 0xFF00 and dw1&0x3FFF == 0x3FFF:
                return "FAT16"
            b0, b1, b2 = struct.unpack_from("BBB", data)
            if b1 == b2 == 0xFF:
                return "FAT12"
            else:
                print(b2a_hex(data[:16]))
                raise Exception("data:unknown fat type")
        if typeFromData() != typ:
            print(b2a_hex(data[:16]))
            print("fat type from header(%s) is different from that of the fat(%s)" % (typ, typeFromData()))

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
        decodes the raw FAT bytes into an FAT12 cluster list.
        """
        self.fat = struct.unpack("<%dL" % (len(data)/4), data)

    def decodeFat16(self, data):
        """
        decodes the raw FAT bytes into an FAT16 cluster list.
        """
        self.fat = struct.unpack("<%dH" % (len(data)/2), data)

    def decodeFat12(self, data):
        """
        decodes the raw FAT bytes into an FAT32 cluster list.
        """
        b = struct.unpack("<%dB" % len(data), data)
        def first(b0, b1):
            return b0 + (b1&15)*256
        def second(b1, b2):
            return (b1>>4) + b2*16
        self.fat = [ second(b[_],b[_+1]) if _%3 else first(b[_],b[_+1]) for _ in map(lambda x:int(x*3/2), range(int(len(b)*2/3))) ]

    def isValidCluster(self, c):
        """
        Check if the value in `c` is an invalid cluster marker.
        """
        if c<2:
            return False
        if self.typ == "FAT12":
            return c<=min(0xFF4, len(self.fat))
        elif self.typ == "FAT16":
            return c<=min(0xFFF4, len(self.fat))
        elif self.typ == "FAT32":
            return c<=min(0xFFFFFF4, len(self.fat))

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
        while self.isValidCluster(c):
            yield c
            c = self.fat[c]

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
        done = set()
        def findnotdone():
            c = 2
            while c < len(self.fat):
                if c not in done and self.fat[c]:
                    return c
                c += 1
        def followchain(c):
            chain = []
            while True:
                chain.append(c)
                done.add(c)
                n = self.fat[c]
                if n == self.EOCMarker():
                    break
                if not self.isValidCluster(n):
                    print("invalid cluster %x -> %x" % (c, n))
                    break
                c = n

            return chain

        while True:
            c = findnotdone()
            if c is None:
                break
            ch = followchain(c)

            print("chain", ch)

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
            if k!=0 and k!=eoc and len(v)!=1:
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
        self.entries = [ self.parseentry(data, _) for _ in range(0,len(data),32) ]

    def parseentry(self, data, ofs):
        """
        decode a single entry.
        """
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
        for ent in self.entries:
            if ent is None:
                pass
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
                    ent.longname = self.truncate_name(name).decode('utf-16le', 'ignore')
                else:
                    ent.longname = None
                yield ent
                name = None
            else:
                print("WARNING: unknown entry: %s" % b2a_hex(ent.data))

class FatFilesystem:
    """
    Parse, and access contents of a fat filesystem.
    """
    def __init__(self, args, fh):
        fh.seek(args.offset)
        hdrdata = fh.read(512)
        self.boot = Bootsector(hdrdata)

        fh.seek(args.offset+self.boot.getFATOffset())
        fatdata = fh.read(self.boot.sectorsPerFAT * self.boot.bytesPerSector)
        self.fat = FatReader(self.boot.fattype, fatdata)

        if args.verbose > 1:
            self.fat.dump()

        self.rd = self.boot.getClusterReader(fh, args.offset)
        if self.boot.fattype=="FAT32":
            dirdata = b''.join(self.getchaindata(self.boot.rootCluster))
        else:
            fh.seek(args.offset+self.boot.rootSector*self.boot.bytesPerSector)
            dirdata = fh.read(self.boot.rootdirSize*32)
        self.root = FatDirectory(dirdata)

    def getchaindata(self, cluster):
        for c in self.fat.followChain(cluster):
            yield self.rd.read(c)

    def recursedir(self, dir, path=[]):
        """
        recursively yield all non deleted dir entries.
        """
        for ent in dir.enum():
            if ent.name in ('.          ', '..         '):
                continue
            if ent.isdeleted:
                continue
            yield path, ent
            if ent.attr&0x10:
                longname = ent.longname or ent.eightdotthree()
                dirdata = b''.join(self.getchaindata(ent.cluster))
                for p, e in self.recursedir(FatDirectory(dirdata), path+[longname]):
                     yield p, e

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


class EFIVolume:
    """
    manage EFIPart type volumes
    """
    def __init__(self, args, fh):
        pass

class MBRVolume:
    """
    manage master-boot-record type volumes
    """
    def __init__(self, args, fh):
        pass


def listfiles(fs):
    for path, ent in fs.recursedir(fs.root):
        longname = ent.longname or ent.eightdotthree()
        print("%-26s %12d [%08x] %s %s/%s" % (ent.timeCreated, ent.filesize, ent.cluster, ent.attributes(), "/".join(path), longname))

def catfile(fs, fname):
    ent = fs.findentry(fs.root, fname.split("/"))
    n = ent.filesize
    for block in fs.getchaindata(ent.cluster):
        want = min(n, len(block))
        print(block[:want])
        n -= want

def processfs(args, fs):
    if args.listfiles:
        listfiles(fs)
    if args.cat:
        catfile(fs, args.cat)
    #print(fs.fat.findChains())
    if args.verbose:
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
    # TODO
    """
    Reader which skips over certain blocks.
    """
    def __init__(self, badblocks, blocksize, fh):
        self.fh = fh
        self.badblocks = badblocks
        self.blocksize = blocksize

        self.pos = 0

    def read(self, size):
        data = b''
        while size > 0:
            chunk = self.readsome(size)
            data += chunk
            size -= len(chunk)
        return data
        
    def seek(self, ofs):
        self.pos = ofs

    def readsome(self, size):
        pass

def makereader(args, fh):
    if args.badblocks:
        bblist = [ int(_.strip(), 0) for _ in args.badblocks.split(",") ]
        blocksize = int(args.blocksize, 0)
        return BadblockReader(bblist, blocksize, fh)
    return fh

def main():
    def auto_int(x): return int(x,0)
    import argparse
    parser= argparse.ArgumentParser(description='fatdump')
    parser.add_argument('--verbose', '-v', action='count', default = 0)
    parser.add_argument('--offset', '-o', type=auto_int, default = 0)
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories, when finding disk images')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='ignore symlinks')
    parser.add_argument('--listfiles', '-l', action='store_true', help='list files')
    parser.add_argument('--badblocks', type=str, help='bad sector nrs')
    parser.add_argument('--blocksize', type=str, help='the blocksize')
    parser.add_argument('--cat', '-c', type=str, help='cat a file to stdout')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('FILES', type=str, nargs='+', help='Files or URLs')
    # todo: add partition selector
    # todo: extract files
    # todo: create image
    args= parser.parse_args()

    if args.FILES:
        for fn in EnumeratePaths(args, args.FILES):
            if fn=='-':
                import sys
                fs = FatFilesystem(args, makereader(args, fh))
                processfs(args, fs)
            else:

                print("==>", fn, "<==")
                try:
                    if fn.find("://") in (3,4,5):
                        import urlstream
                        with urlstream.open(fn) as fh:
                            fs = FatFilesystem(args, makereader(args, fh))
                            processfs(args, fs)
                    else:
                        with open(fn, "rb") as fh:
                            fs = FatFilesystem(args, makereader(args, fh))
                            processfs(args, fs)

                except Exception as e:
                    print("ERROR: %s" % e)
                    if args.debug:
                        raise


if __name__ == '__main__':
    main()

