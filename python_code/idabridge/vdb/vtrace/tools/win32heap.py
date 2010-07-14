
# Heap Flags
HEAP_NO_SERIALIZE               = 0x00000001
HEAP_GROWABLE                   = 0x00000002
HEAP_GENERATE_EXCEPTIONS        = 0x00000004
HEAP_ZERO_MEMORY                = 0x00000008
HEAP_REALLOC_IN_PLACE_ONLY      = 0x00000010
HEAP_TAIL_CHECKING_ENABLED      = 0x00000020
HEAP_FREE_CHECKING_ENABLED      = 0x00000040
HEAP_DISABLE_COALESCE_ON_FREE   = 0x00000080
HEAP_CREATE_ALIGN_16            = 0x00010000
HEAP_CREATE_ENABLE_TRACING      = 0x00020000
HEAP_CREATE_ENABLE_EXECUTE      = 0x00040000

heap_flag_names = {
HEAP_NO_SERIALIZE:"HEAP_NO_SERIALIZE",
HEAP_GROWABLE:"HEAP_GROWABLE",
HEAP_GENERATE_EXCEPTIONS:"HEAP_GENERATE_EXCEPTIONS",
HEAP_ZERO_MEMORY:"HEAP_ZERO_MEMORY",
HEAP_REALLOC_IN_PLACE_ONLY:"HEAP_REALLOC_IN_PLACE_ONLY",
HEAP_TAIL_CHECKING_ENABLED:"HEAP_TAIL_CHECKING_ENABLED",
HEAP_FREE_CHECKING_ENABLED:"HEAP_FREE_CHECKING_ENABLED",
HEAP_DISABLE_COALESCE_ON_FREE:"HEAP_DISABLE_COALESCE_ON_FREE",
HEAP_CREATE_ALIGN_16:"HEAP_CREATE_ALIGN_16",
HEAP_CREATE_ENABLE_TRACING:"HEAP_CREATE_ENABLE_TRACING",
HEAP_CREATE_ENABLE_EXECUTE:"HEAP_CREATE_ENABLE_EXECUTE",
}

# Heap Chunk Flags
HEAP_ENTRY_BUSY             = 0x01
HEAP_ENTRY_EXTRA_PRESENT    = 0x02
HEAP_ENTRY_FILL_PATTERN     = 0x04
HEAP_ENTRY_VIRTUAL_ALLOC    = 0x08
HEAP_ENTRY_LAST_ENTRY       = 0x10
HEAP_ENTRY_SETTABLE_FLAG1   = 0x20
HEAP_ENTRY_SETTABLE_FLAG2   = 0x40
HEAP_ENTRY_SETTABLE_FLAG3   = 0x80



def reprHeapFlags(flags):
    ret = []
    if flags & HEAP_ENTRY_BUSY:
        ret.append("BUSY")
    if flags & HEAP_ENTRY_FILL_PATTERN:
        ret.append("FILL")
    if flags & HEAP_ENTRY_LAST_ENTRY:
        ret.append("LAST")
    if len(ret):
        return "|".join(ret)
    return "NONE"

class HeapCorruptionException(Exception):
    def __init__(self, heap, segment, prevchunk, badchunk):
        prevaddr = 0
        badaddr = 0
        if prevchunk != None:
            prevaddr = prevchunk.address
        if badchunk != None:
            badaddr = badchunk.address
        Exception.__init__(self, "Prev Chunk: 0x%.8x Bad Chunk: 0x%.8x" % (prevaddr, badaddr))
        self.heap = heap
        self.segment = segment
        self.prevchunk = prevchunk
        self.badchunk = badchunk

class FreeListCorruption(Exception):
    def __init__(self, heap, index, prevchunk, badchunk):
        prevaddr = 0
        badaddr = 0
        if prevchunk != None:
            prevaddr = prevchunk.address
        if badchunk != None:
            badaddr = badchunk.address
        Exception.__init__(self, "Index: %d Prev Chunk: 0x%.8x Bad Chunk: 0x%.8x" % (index, prevaddr, badaddr))
        self.heap = heap
        self.index = index
        self.prevchunk = prevchunk
        self.badchunk = badchunk

class ChunkNotFound(Exception):
    pass

def getHeapSegChunk(trace, address):
    """
    Find and return the heap, segment, and chunk for the given addres
    (or exception).
    """
    for heap in getHeaps(trace):
        for seg in heap.getSegments():
            base,size,perms,fname = trace.getMemoryMap(seg.address)
            if address < base or address > base+size:
                continue
            for chunk in seg.getChunks():
                a = chunk.address
                b = chunk.address + len(chunk)
                if (address >= a and address < b):
                    return heap,seg,chunk

    raise ChunkNotFound("No Chunk Found for 0x%.8x" % address)

def getHeaps(trace):
    """
    Get the win32 heaps (returns a list of Win32Heap objects)
    """
    ret = []
    pebaddr = trace.getMeta("PEB")
    peb = trace.getStruct("win32.PEB", pebaddr)
    heapcount = int(peb.NumberOfHeaps)
    # FIXME not 64bit ok
    hlist = trace.readMemoryFormat(long(peb.ProcessHeaps), "<"+("L"*heapcount))
    for haddr in hlist:
        ret.append(Win32Heap(trace, haddr))
    return ret

class Win32Heap:

    def __init__(self, trace, address):
        self.address = address
        self.trace = trace
        self.heap = trace.getStruct("win32.HEAP", address)
        self.seglist = None

    def hasLookAside(self):
        """
        Does this heap have a lookaside?
        """
        if not self.heap.Flags & HEAP_GROWABLE:
            return False
        if self.heap.Flags & HEAP_NO_SERIALIZE:
            return False
        return True

    def getSegments(self):
        """
        Return a list of Win32Segment objects.
        """
        if self.seglist == None:
            self.seglist = []
            for i in range(long(self.heap.LastSegmentIndex)+1):
                sa = self.heap.Segments[i]
                self.seglist.append(Win32Segment(self.trace, self, long(sa)))
        return self.seglist

    def getLookAsideLists(self):
        """
        Return a list of the lookaside list for this heap
        """
        if not self.hasLookAside():
            raise Exception("Heap at 0x%.8x has no lookaside!" % (self.address))
        laside = self.address + 0x688
        ret = []
        for i in range(128):
            slot = laside + (i * 0x30)
            bucket = []
            base = self.trace.readMemoryFormat(slot, "<L")[0]
            while base != 0:
                chunk = Win32Chunk(self.trace, base-8)
                bucket.append(chunk)
                base,blink = chunk.getFlinkBlink()
            ret.append(bucket)
        return ret

    def getFreeLists(self):
        """
        Return a list of the free lists in this heap.
        (Not including look-aside)
        """
        ret = []
        foff = self.heap.vsGetOffset("FreeLists")
        for i in range(128):
            le = self.heap.FreeLists[i]
            bucket = []
            base = self.address + foff + (i*8)

            addr = le.Flink

            while addr != base:

                # If we die here, the guy before us was dorked.
                try:
                    chunk = Win32Chunk(self.trace, addr-8)
                except Exception, e:
                    chunk = bucket[-1]
                    pchunk = None
                    if len(bucket) >= 2:
                        pchunk = bucket[-2]
                    raise FreeListCorruption(self, i, pchunk, chunk)

                # Check our back pointer
                flink,blink = chunk.getFlinkBlink()
                if len(bucket):
                    pchunk = bucket[-1]
                    if blink != pchunk.getDataAddress():
                        raise FreeListCorruption(self, i, pchunk, chunk)

                addr = flink
                bucket.append(chunk)

            ret.append(bucket)
        return ret

    def getFlagNames(self):
        ret = []
        for k,v in heap_flag_names.items():
            if self.heap.Flags & k:
                ret.append(v)
        return ret

    def __repr__(self):
        fnames = "|".join(self.getFlagNames())
        return "heap: 0x%.8x flags:%s" % (self.address, fnames)

class Win32Segment:
    def __init__(self, trace, heap, address):
        self.trace = trace
        self.heap = heap
        self.address = address
        self.seg = trace.getStruct("win32.HEAP_SEGMENT", address)
        #FIXME segments can specify chunk Size granularity
        self.chunks = None

    def getChunks(self):
        if self.chunks == None:
            self.chunks = []
            addr = self.address
            lastchunk = None
            while True:
                chunk = Win32Chunk(self.trace, addr)
                self.chunks.append(chunk)
                if lastchunk != None:
                    if lastchunk.chunk.Size != chunk.chunk.PrevSize:
                        raise HeapCorruptionException(self.heap, self, lastchunk, chunk)
                if chunk.isLast():
                    break
                lastchunk = chunk
                addr += len(chunk)
        return self.chunks

    def getLastChunk(self):
        va = self.seg.LastEntryInSegment
        return Win32Chunk(self.trace, va)

class Win32Chunk:
    def __init__(self, trace, address):
        self.trace = trace
        self.address = address
        self.chunk = trace.getStruct("win32.HEAP_ENTRY", address)

    def __repr__(self):
        return "HeapChunk: 0x%.8x (%d) %s" % (self.address, len(self),self.reprFlags())

    def __len__(self):
        return int(self.chunk.Size) * 8

    def isLast(self):
        return bool(int(self.chunk.Flags) & HEAP_ENTRY_LAST_ENTRY)

    def isBusy(self):
        return bool(int(self.chunk.Flags) & HEAP_ENTRY_BUSY)

    def getDataAddress(self):
        return self.address + len(self.chunk)

    def getDataSize(self):
        return len(self) - len(self.chunk)

    def getDataBytes(self, maxsize=None):
        size = self.getDataSize()
        if maxsize != None:
            size = min(size, maxsize)
        return self.trace.readMemory(self.getDataAddress(), size)

    def getFlinkBlink(self):
        return self.trace.readMemoryFormat(self.getDataAddress(), "<LL")

    def reprFlags(self):
        return reprHeapFlags(int(self.chunk.Flags))

