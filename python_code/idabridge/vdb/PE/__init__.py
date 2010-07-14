
import struct
import vstruct
import vstruct.defs.pe as vs_pe

import ordlookup

IMAGE_FILE_MACHINE_I386  = 0x014c
IMAGE_FILE_MACHINE_IA64  = 0x0200
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_DIRECTORY_ENTRY_EXPORT          =0   # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT          =1   # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE        =2   # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION       =3   # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY        =4   # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC       =5   # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG           =6   # Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT       =7   # (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    =7   # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR       =8   # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS             =9   # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    =10   # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   =11   # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT            =12   # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   =13   # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR =14   # COM Runtime descriptor

IMAGE_DEBUG_TYPE_UNKNOWN          =0
IMAGE_DEBUG_TYPE_COFF             =1
IMAGE_DEBUG_TYPE_CODEVIEW         =2
IMAGE_DEBUG_TYPE_FPO              =3
IMAGE_DEBUG_TYPE_MISC             =4
IMAGE_DEBUG_TYPE_EXCEPTION        =5
IMAGE_DEBUG_TYPE_FIXUP            =6
IMAGE_DEBUG_TYPE_OMAP_TO_SRC      =7
IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    =8
IMAGE_DEBUG_TYPE_BORLAND          =9
IMAGE_DEBUG_TYPE_RESERVED10       =10
IMAGE_DEBUG_TYPE_CLSID            =11

IMAGE_SCN_CNT_CODE                  = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080
IMAGE_SCN_LNK_OTHER                 = 0x00000100
IMAGE_SCN_LNK_INFO                  = 0x00000200
IMAGE_SCN_LNK_REMOVE                = 0x00000800
IMAGE_SCN_LNK_COMDAT                = 0x00001000
IMAGE_SCN_MEM_FARDATA               = 0x00008000
IMAGE_SCN_MEM_PURGEABLE             = 0x00020000
IMAGE_SCN_MEM_16BIT                 = 0x00020000
IMAGE_SCN_MEM_LOCKED                = 0x00040000
IMAGE_SCN_MEM_PRELOAD               = 0x00080000
IMAGE_SCN_ALIGN_1BYTES              = 0x00100000
IMAGE_SCN_ALIGN_2BYTES              = 0x00200000
IMAGE_SCN_ALIGN_4BYTES              = 0x00300000
IMAGE_SCN_ALIGN_8BYTES              = 0x00400000
IMAGE_SCN_ALIGN_16BYTES             = 0x00500000
IMAGE_SCN_ALIGN_32BYTES             = 0x00600000
IMAGE_SCN_ALIGN_64BYTES             = 0x00700000
IMAGE_SCN_ALIGN_128BYTES            = 0x00800000
IMAGE_SCN_ALIGN_256BYTES            = 0x00900000
IMAGE_SCN_ALIGN_512BYTES            = 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES           = 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES           = 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES           = 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES           = 0x00E00000
IMAGE_SCN_ALIGN_MASK                = 0x00F00000
IMAGE_SCN_LNK_NRELOC_OVFL           = 0x01000000
IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED            = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED             = 0x08000000
IMAGE_SCN_MEM_SHARED                = 0x10000000
IMAGE_SCN_MEM_EXECUTE               = 0x20000000
IMAGE_SCN_MEM_READ                  = 0x40000000
IMAGE_SCN_MEM_WRITE                 = 0x80000000

# FIXME TODO HACK XXX
# * Save PE back out to file

class PE(object):
    def __init__(self, fd, inmem=False):
        """
        Construct a PE object.  use inmem=True if you are
        using a MemObjFile or other "memory like" image.
        """
        object.__init__(self)
        self.inmem = inmem
        self.fd = fd
        self.fd.seek(0)
        self.pe32p = False
        self.psize = 4

        self.IMAGE_DOS_HEADER = vstruct.getStructure("pe.IMAGE_DOS_HEADER")
        dosbytes = fd.read(len(self.IMAGE_DOS_HEADER))
        self.IMAGE_DOS_HEADER.vsParse(dosbytes)

        nt = self.readStructAtOffset(self.IMAGE_DOS_HEADER.e_lfanew,
                                "pe.IMAGE_NT_HEADERS")

        # Parse in a default 32 bit, and then check for 64...
        if nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64:
            nt = self.readStructAtOffset(self.IMAGE_DOS_HEADER.e_lfanew,
                                "pe.IMAGE_NT_HEADERS64")
            self.pe32p = True
            self.psize = 8

        self.IMAGE_NT_HEADERS = nt

    def getPdataEntries(self):
        sec = self.getSectionByName('.pdata')
        if sec == None:
            return ()
        ret = []
        bytes = self.readAtRva(sec.VirtualAddress, sec.VirtualSize)
        while len(bytes):
            f = vs_pe.IMAGE_RUNTIME_FUNCTION_ENTRY()
            f.vsParse(bytes)
            bytes = bytes[len(f):]
            ret.append(f)
        return ret

    def getDllName(self):
        if self.IMAGE_EXPORT_DIRECTORY != None:
            ordoff = self.rvaToOffset(self.IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals)
            ordsize = 2 * self.IMAGE_EXPORT_DIRECTORY.NumberOfNames
            return self.readAtOffset(ordoff + ordsize, 32).split("\x00", 1)[0]
        return None

    def getImports(self):
        """
        Return the list of import tuples for this PE.  The tuples
        are in the format (rva, name).
        """
        return self.imports

    def getExports(self):

        """
        Return the list of exports in this PE.  The list contains
        tuples in the format; (rva, ord, name).
        """
        return self.exports

    def getForwarders(self):
        """
        [ (rva, name, forwardname), ... ]
        """
        return self.forwarders

    def getSections(self):
        return self.sections

    def rvaToOffset(self, rva):
        if self.inmem:
            return rva

        for s in self.sections:
            sbase = s.VirtualAddress
            ssize = s.VirtualSize
            if rva >= sbase and rva < (sbase + ssize):
                return s.PointerToRawData + (rva - sbase)
        return 0

    def getSectionByName(self, name):
        for s in self.getSections():
            if s.Name.split("\x00", 1)[0] == name:
                return s
        return None

    def getIdResources(self):
        return self.id_resources

    def getNamedResources(self):
        return self.name_resources

    def readStructAtRva(self, rva, structname):
        s = vstruct.getStructure(structname)
        bytes = self.readAtRva(rva, len(s))
        #print "%s: %s" % (structname, bytes.encode('hex'))
        s.vsParse(bytes)
        return s

    def readStructAtOffset(self, offset, structname):
        s = vstruct.getStructure(structname)
        bytes = self.readAtOffset(offset, len(s))
        #print "%s: %s" % (structname, bytes.encode('hex'))
        s.vsParse(bytes)
        return s

    def parseResources(self):
        self.id_resources = []
        self.name_resources = []
        self.IMAGE_RESOURCE_DIRECTORY = None

        sec = self.getSectionByName(".rsrc")
        if sec == None:
            return 

        self.IMAGE_RESOURCE_DIRECTORY = self.readStructAtRva(
                                            sec.VirtualAddress,
                                            "pe.IMAGE_RESOURCE_DIRECTORY")

        namecount = self.IMAGE_RESOURCE_DIRECTORY.NumberOfNamedEntries
        idcount = self.IMAGE_RESOURCE_DIRECTORY.NumberOfIdEntries
        entsize = 8

        rsrcbase = sec.VirtualAddress

        namebytes = self.readAtRva(rsrcbase + irdsize, namecount * entsize)
        idbytes = self.readAtRva(rsrcbase + irdsize + (namecount*entsize), idcount * entsize)
        while idbytes:
            name,offset = struct.unpack("<LL", idbytes[:entsize])
            offset = offset & 0x7fffffff # HUH?
            if name == 16:
                print self.readAtRva(rsrcbase + offset, 40).encode("hex")
            self.id_resources.append((name,offset))
            idbytes = idbytes[entsize:]

        while namebytes:
            #FIXME parse out the names to be nice.
            name,offset = struct.unpack("<LL", namebytes[:entsize])
            namebytes = namebytes[entsize:]

    def parseSections(self):
        self.sections = []
        off = self.IMAGE_DOS_HEADER.e_lfanew + len(self.IMAGE_NT_HEADERS)

        secsize = len(vstruct.getStructure("pe.IMAGE_SECTION_HEADER"))

        sbytes = self.readAtOffset(off, secsize * self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections)
        while sbytes:
            s = vstruct.getStructure("pe.IMAGE_SECTION_HEADER")
            s.vsParse(sbytes[:secsize])
            self.sections.append(s)
            sbytes = sbytes[secsize:]

    def readRvaFormat(self, fmt, rva):
        size = struct.calcsize(fmt)
        bytes = self.readAtRva(rva, size)
        return struct.unpack(fmt, bytes)

    def readAtRva(self, rva, size):
        offset = self.rvaToOffset(rva)
        return self.readAtOffset(offset, size)

    def readAtOffset(self, offset, size):
        #FIXME grab an fd seek lock here?
        ret = ""
        self.fd.seek(offset)
        while len(ret) != size:
            rlen = size - len(ret)
            x = self.fd.read(rlen)
            if x == "":
                raise Exception("EOF In readAtOffset()")
            ret += x
        return ret

    def parseLoadConfig(self):
        self.IMAGE_LOAD_CONFIG = None
        cdir = self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
        rva = cdir.VirtualAddress
        if rva != 0:
            self.IMAGE_LOAD_CONFIG = self.readStructAtRva(rva, "pe.IMAGE_LOAD_CONFIG_DIRECTORY")

    def readPointerAtOffset(self, off):
        fmt = "<L"
        if self.psize == 8:
            fmt = "<Q"
        return struct.unpack(fmt, self.readAtOffset(off, self.psize))[0]
        
    def parseImports(self):
        self.imports = []

        idir = self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        poff = self.rvaToOffset(idir.VirtualAddress)

        if poff == 0:
            return

        x = vstruct.getStructure("pe.IMAGE_IMPORT_DIRECTORY")
        isize = len(x)
        x.vsParse(self.readAtOffset(poff, isize))
        while x.Name != 0:

            liboff = self.rvaToOffset(x.Name)
            libname = self.readAtOffset(liboff, 256).split("\x00")[0]

            idx = 0
            noff = self.rvaToOffset(x.OriginalFirstThunk)
            aoff = self.rvaToOffset(x.FirstThunk)

            while True:
                ava = self.readPointerAtOffset(aoff+(self.psize*idx))
                if ava == 0:
                    break

                nva = self.readPointerAtOffset(noff+(self.psize*idx))
                #FIXME high bit testing for 64 bit
                if nva & 0x80000000:
                    name = ordlookup.ordLookup(libname, nva & 0x7fffffff)
                else:
                    nameoff = self.rvaToOffset(nva) + 2 # Skip the short "hint"
                    name = self.readAtOffset(nameoff, 256).split("\x00")[0]

                self.imports.append((x.FirstThunk+(idx*self.psize),libname,name))

                idx += 1
                
            poff += isize
            x.vsParse(self.readAtOffset(poff, len(x)))

    def getRelocations(self):
        """
        Return the list of RVA base-relocations in this PE.
        """
        return self.relocations

    def parseRelocations(self):
        self.relocations = []
        edir = self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        rva = edir.VirtualAddress
        rsize = edir.Size

        if rva == 0: # no relocations
            return

        reloff = self.rvaToOffset(rva)
        relbytes = self.readAtOffset(reloff, rsize)

        while relbytes:
            pageva, chunksize = struct.unpack("<LL", relbytes[:8])
            relcnt = (chunksize - 8) / 2
            rels = struct.unpack("<%dH" % relcnt, relbytes[8:chunksize])
            for r in rels:
                rtype = r >> 12
                roff  = r & 0xfff
                self.relocations.append((pageva+roff, rtype))
            relbytes = relbytes[chunksize:]

    def parseExports(self):

        # Initialize our required locals.
        self.exports = []
        self.forwarders = []
        self.IMAGE_EXPORT_DIRECTORY = None

        edir = self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        poff = self.rvaToOffset(edir.VirtualAddress)

        if poff == 0: # No exports...
            return

        self.IMAGE_EXPORT_DIRECTORY = self.readStructAtOffset(poff, "pe.IMAGE_EXPORT_DIRECTORY")

        funcoff = self.rvaToOffset(self.IMAGE_EXPORT_DIRECTORY.AddressOfFunctions)
        funcsize = 4 * self.IMAGE_EXPORT_DIRECTORY.NumberOfFunctions
        funcbytes = self.readAtOffset(funcoff, funcsize)

        nameoff = self.rvaToOffset(self.IMAGE_EXPORT_DIRECTORY.AddressOfNames)
        namesize = 4 * self.IMAGE_EXPORT_DIRECTORY.NumberOfNames
        namebytes = self.readAtOffset(nameoff, namesize)

        ordoff = self.rvaToOffset(self.IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals)
        ordsize = 2 * self.IMAGE_EXPORT_DIRECTORY.NumberOfNames
        ordbytes = self.readAtOffset(ordoff, ordsize)

        funclist = struct.unpack("%dI" % (len(funcbytes) / 4), funcbytes)
        namelist = struct.unpack("%dI" % (len(namebytes) / 4), namebytes)
        ordlist = struct.unpack("%dH" % (len(ordbytes) / 2), ordbytes)

        #for i in range(len(funclist)):
        for i in range(len(namelist)):

            ord = ordlist[i]
            nameoff = self.rvaToOffset(namelist[i])

            funcoff = funclist[ord]
            ffoff = self.rvaToOffset(funcoff)

            name = None

            if nameoff != 0:
                name = self.readAtOffset(nameoff, 256).split("\x00", 1)[0]
            else:
                name = "ord_%.4x" % ord

            if ffoff >= poff and ffoff < poff + edir.Size:
                fwdname = self.readAtOffset(ffoff, 260).split("\x00", 1)[0]
                self.forwarders.append((funclist[ord],name,fwdname))
            else:
                self.exports.append((funclist[ord], ord, name))

    def __getattr__(self, name):
        """
        Use a getattr over-ride to allow "on demand" parsing of particular sections.
        """
        if name == "exports":
            self.parseExports()
            return self.exports

        elif name == "IMAGE_IMPORT_DIRECTORY":
            self.parseImports()
            return self.IMAGE_IMPORT_DIRECTORY

        elif name == "imports":
            self.parseImports()
            return self.imports

        elif name == "IMAGE_EXPORT_DIRECTORY":
            self.parseExports()
            return self.IMAGE_EXPORT_DIRECTORY

        elif name == "forwarders":
            self.parseExports()
            return self.forwarders

        elif name == "sections":
            self.parseSections()
            return self.sections

        elif name == "IMAGE_RESOURCE_DIRECTORY":
            self.parseResources()
            return self.IMAGE_RESOURCE_DIRECTORY

        elif name == "id_resources":
            self.parseResources()
            return self.id_resources

        elif name == "name_resources":
            self.parseResources()
            return self.name_resources

        elif name == "relocations":
            self.parseRelocations()
            return self.relocations

        elif name == "IMAGE_LOAD_CONFIG":
            self.parseLoadConfig()
            return self.IMAGE_LOAD_CONFIG

        else:
            raise AttributeError


class MemObjFile:
    """
    A file like object that wraps a MemoryObject (envi) compatable
    object with a file-like object where seek == VA.
    """

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

def peFromMemoryObject(memobj, baseaddr):
    fd = MemObjFile(memobj, baseaddr)
    return PE(fd, inmem=True)

def peFromFileName(fname):
    """
    Utility helper that assures that the file is opened in 
    binary mode which is required for proper functioning.
    """
    f = file(fname, "rb")
    return PE(f)

def peFromBytes(bytes):
    pass
    #make a cStringIO thing

