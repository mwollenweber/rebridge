import re

import struct
import envi

"""
A module containing memory utilities and the definition of the
memory access API used by all vtoys trace/emulators/workspaces.
"""

# Memory Map Permission Flags
MM_READ = 0x4
MM_WRITE = 0x2
MM_EXEC = 0x1
MM_SHARED = 0x08

MM_RWX = (MM_READ | MM_WRITE | MM_EXEC)

def reprPerms(mask):
    plist = ['-','-','-','-']
    if mask & MM_SHARED:
        plist[0] = 's'
    if mask & MM_READ:
        plist[1] = 'r'
    if mask & MM_WRITE:
        plist[2] = 'w'
    if mask & MM_EXEC:
        plist[3] = 'x'

    return "".join(plist)

def parsePerms(pstr):
    ret = 0
    if pstr.find('s') != -1: ret |= MM_SHARED
    if pstr.find('r') != -1: ret |= MM_READ
    if pstr.find('w') != -1: ret |= MM_WRITE
    if pstr.find('x') != -1: ret |= MM_EXEC
    return ret

class IMemory:
    """
    This is the interface spec (and a few helper utils)
    for the unified memory object interface.

    NOTE: If your actual underlying memory format is such
    that over-riding anything (like isValidPointer!) can
    be faster than the default implementation, DO IT!
    """

    def __init__(self):
        self.imem_psize = struct.calcsize("P")

    def readMemory(self, va, size):
        """
        Read memory from the specified virtual address for size bytes
        and return it as a python string.

        Example: mem.readMemory(0x41414141, 20) -> "A..."
        """
        raise Exception("must implement readMemory!")

    def writeMemory(self, va, bytes):
        """
        Write the given bytes to the specified virtual address.

        Example: mem.writeMemory(0x41414141, "VISI")
        """
        raise Exception("must implement writeMemory!")

    def protectMemory(self, va, size, perms):
        """
        Change the protections for the given memory map. On most platforms
        the va/size *must* exactly match an existing memory map.
        """
        raise Exception("must implement protectMemory!")

    def probeMemory(self, va, size, permstr):
        """
        Check to be sure that the given virtual address and size
        is contained within one memory map, and check that the
        perms ("rwxs") are contained within the permission bits
        for the memory map.

        Example probeMemory(0x41414141, 20, "w")
        (check if the memory for 20 bytes at 0x41414141 is writable)
        """
        perm = parsePerms(permstr)
        map = self.getMemoryMap(va)
        if map == None:
            return False
        mapva, mapsize, mapperm, mapfile = map
        mapend = mapva+mapsize
        if va+size >= mapend:
            return False
        if mapperm & perm != perm:
            return False
        return True

    def allocateMemory(self, size, perms=MM_RWX, suggestaddr=0):
        raise Exception("must implement allocateMemory!")

    def addMemoryMap(self, mapva, perms, fname, bytes):
        raise Exception("must implement addMemoryMap!")

    def getMemoryMaps(self):
        raise Exception("must implement getMemoryMaps!")

    # Mostly helpers from here down...
    def readMemoryFormat(self, va, fmt):
        # Somehow, pointers are "signed" when they
        # get chopped up by python's struct package
        if self.imem_psize == 4:
            fmt = fmt.replace("P","L")
        elif self.imem_psize == 8:
            fmt = fmt.replace("P","Q")

        size = struct.calcsize(fmt)
        bytes = self.readMemory(va, size)
        return struct.unpack(fmt, bytes)

    def getSegmentInfo(self, id):
        return (0,0xffffffff)

    def readMemValue(self, addr, size):
        bytes = self.readMemory(addr, size)
        if bytes == None:
            return None
        #FIXME change this (and all uses of it) to passing in format...
        if len(bytes) != size:
            raise Exception("Read Gave Wrong Length At 0x%.8x (va: 0x%.8x wanted %d got %d)" % (self.getProgramCounter(),addr, size, len(bytes)))
        if size == 1:
            return struct.unpack("B", bytes)[0]
        elif size == 2:
            return struct.unpack("<H", bytes)[0]
        elif size == 4:
            return struct.unpack("<L", bytes)[0]
        elif size == 8:
            return struct.unpack("<Q", bytes)[0]


    def writeMemoryFormat(self, va, fmt, *args):
        bytes = struct.pack(fmt, *args)
        self.writeMemory(va, bytes)

    def getMemoryMap(self, va):
        """
        Return a tuple of mapva,size,perms,filename for the memory
        map which contains the specified address (or None).
        """
        for mapva,size,perms,mname in self.getMemoryMaps():
            if va >= mapva and va < (mapva+size):
                return (mapva,size,perms,mname)
        return None

    def isValidPointer(self, va):
        try:
            if self.getMemoryMap(va) == None:
                return False
            return True
        except Exception, e:
            return False

    def searchMemory(self, needle, regex=False):
        """
        A quick cheater way to searchMemoryRange() for each
        of the current memory maps.
        """
        results = []
        for va,size,perm,fname in self.getMemoryMaps():
            if not perm & MM_READ:
                continue
            try:
                results.extend(self.searchMemoryRange(needle, va, size, regex=regex))
            except:
                pass # Some platforms dont let debuggers read non-readable mem

        return results

    def searchMemoryRange(self, needle, address, size, regex=False):
        """
        Search the specified memory range (address -> size)
        for the string needle.   Return a list of addresses
        where the match occurs.
        """
        results = []
        memory = self.readMemory(address, size)
        if regex:
            for match in re.finditer(needle, memory):
                off = match.start()
                results.append(address+off)
        else:
            offset = 0
            while offset < size:
                loc = memory.find(needle, offset)
                if loc == -1: # No more to be found ;)
                    break
                results.append(address+loc)
                offset = loc+len(needle) # Skip one past our matcher

        return results

class MemoryObject(IMemory):
    def __init__(self, maps=None, pagesize=4096):
        """
        Take a set of memory maps (va, perms, bytes) and put them in
        a sparse space finder. You may specify your own page-size to optimize
        the search for an architecture.
        """
        IMemory.__init__(self)
        self._mem_pagesize = pagesize
        self._mem_mask = (0-pagesize) & 0xffffffffffffffff
        self._mem_maps = []
        self._mem_maplookup = {}
        self._mem_bytelookup = {}
        if maps != None:
            for va,perms,fname,bytes in maps:
                self.addMemoryMap(va, perms, fname, bytes)

    #FIXME MemoryObject: def allocateMemory(self, size, perms=MM_RWX, suggestaddr=0):

    def addMemoryMap(self, va, perms, fname, bytes):
        x = [va, perms, fname, bytes] # Asign to a list cause we need to write to it
        maptup = (va, len(bytes), perms, fname)
        bytelist = [va, perms, bytes]
        base = va & self._mem_mask
        maxva = va + len(bytes)
        while base < maxva:
            t = self._mem_maplookup.get(base)
            if t != None:
                raise envi.MapOverlapException(maptup, t)
            self._mem_maplookup[base] = maptup
            self._mem_bytelookup[base] = bytelist
            base += self._mem_pagesize
        self._mem_maps.append((va, len(bytes), perms, fname))

    def getMemoryMap(self, va):
        """
        Get the va,perms,bytes list for this map
        """
        return self._mem_maplookup.get(va & self._mem_mask)

    def getMemoryMaps(self):
        return list(self._mem_maps)

    #FIXME rename this... it's aweful
    #FIXME make extendable maps for things like the stack
    def checkMemory(self, va, perms=0):
        map = self._mem_maplookup.get(va & self._mem_mask)
        if map == None:
            return False
        if (perms & map[1]) != perms:
            return False
        return True

    def readMemory(self, va, size):
        map = self._mem_bytelookup.get(va & self._mem_mask)
        if map == None:
            raise envi.SegmentationViolation(va)
        mapva, mperm, mapbytes = map
        if not mperm & MM_READ:
            raise envi.SegmentationViolation(va)
        offset = va - mapva
        return mapbytes[offset:offset+size]

    def writeMemory(self, va, bytes):
        map = self._mem_bytelookup.get(va & self._mem_mask)
        if map == None:
            raise envi.SegmentationViolation(va)
        mva, mperm, mbytes = map
        if not mperm & MM_WRITE:
            raise envi.SegmentationViolation(va)
        offset = va - mva
        map[2] = mbytes[:offset] + bytes + mbytes[offset+len(bytes):]

class MemoryTracker:
    """
    A utility that will track memory access and let everything be valid
    memory for reading and writing.
    """
    def __init__(self):
        self.bytes = {}
        self.reads = []
        self.writes = []

    def readMemory(self, va, size):
        #FIXME make this unique so it can be tracked
        #FIXME make this return anything he's written already
        self.reads.append((va, size))
        return "A"*size

    def writeMemory(self, va, bytes):
        self.writes.append((va, bytes))
        self.bytes[va] = bytes
        
class FakeMemory:
    def checkMemory(self, va, perms=0):
        return True
    def readMemory(self, va, size):
        return "A"*size
    def writeMemory(self, va, bytes):
        pass

class MemoryFile:
    '''
    A file like object to wrap around a memory object.
    '''
    def __init__(self, memobj, baseaddr):
        self.baseaddr = baseaddr
        self.offset = baseaddr
        self.memobj = memobj

    def seek(self, offset):
        self.offset = self.baseaddr + offset

    def read(self, size):
        ret = self.memobj.readMemory(self.offset, size)
        self.offset += size
        return ret
        
    def write(self, bytes):
        self.memobj.writeMemory(self.offset, bytes)
        self.offset += len(bytes)
