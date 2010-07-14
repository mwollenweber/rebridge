
import getopt
import vtrace
import vtrace.tools.win32heap as win32heap
import vtrace.tools.win32stealth as win32_stealth
import vtrace.util as v_util

import envi.memory as e_mem
import envi.cli as e_cli
import envi.bits as e_bits

import PE
import vstruct.defs.pe as vs_pe

def teb(vdb, line):
    """
    Print out the TEB for the current or specified thread.

    Usage: teb [threadid]
    """
    t = vdb.getTrace()
    threads = t.getThreads()
    tid = t.getMeta("ThreadId")
    if len(line):
        tid = t.parseExpression(line)
    taddr = threads.get(tid)
    if taddr == None:
        vdb.vprint("Invalid Thread ID: %d" % tid)
        return
    teb = t.getStruct("win32.TEB", taddr)
    vdb.vprint(teb.tree(va=taddr))

def peb(vdb, line):
    """
    Print the PEB

    Usage: peb
    """
    t = vdb.getTrace()
    t.requireAttached()
    pebaddr = t.getMeta("PEB")
    peb = t.getStruct("win32.PEB", pebaddr)
    vdb.vprint(peb.tree(pebaddr))

def regkeys(vdb, line):
    """
    Show all the registry keys the target process currently has open.
    If a string is provided, it will be used to filter results

    Usage: regkeys [filter string]
    """
    t = vdb.getTrace()
    t.requireAttached()
    find_string = ""
    if len(args.split()) > 0:
        find_string = args.split()[0].strip()
    vdb.vprint("\nOpen Registry Keys:\n")
    for fd,ftype,fname in t.getFds():
        if ftype == vtrace.FD_REGKEY:
            if find_string == "" or\
				str(fdtype).find(find_string) > -1 or\
				str(id).find(find_string) > -1 or\
				fname.find(find_string) > -1:
				vdb.vprint("0x%.8x [%d] %s" % (id,fdtype,fname))

    vdb.vprint("")

def einfo(vdb, line):
    """
    Show all the current exception information.

    -P    Toggle the "PendingException" meta key which controls
          delivery (or handling) of the current exception.

    Usage: einfo [options]
    """
    argv = e_cli.splitargs(line)
    t = vdb.getTrace()

    try:
        opts,args = getopt.getopt(argv, 'P')
    except Exception, e:
        return vdb.do_help('einfo')

    for opt,optarg in opts:
        if opt == '-P':
            p = t.getMeta('PendingException')
            t.setMeta('PendingException', not p)

    exc = t.getMeta("Win32Event", None)
    if exc == None:
        vdb.vprint("No Exception Information Found")
    ecode = exc.get("ExceptionCode", 0)
    eaddr = exc.get("ExceptionAddress",0)
    chance = 2
    if exc.get("FirstChance", False):
        chance = 1

    einfo = exc.get("ExceptionInformation", [])
    #FIXME get extended infoz
    #FIXME unify with cli thing
    vdb.vprint("Win32 Exception 0x%.8x at 0x%.8x (%d chance)" % (ecode, eaddr, chance))
    vdb.vprint("Exception Information: %s" % " ".join([hex(i) for i in einfo]))
    vdb.vprint('Deliver Exception: %s' % t.getMeta('PendingException'))

def seh(vdb, line):
    """
    Walk and print the SEH chain for the current (or specified) thread.

    Usage: seh [threadid]
    """
    t = vdb.getTrace()
    if len(line) == 0:
        tid = t.getMeta("ThreadId")
    else:
        tid = int(line)
    tinfo = t.getThreads().get(tid, None)
    if tinfo == None:
        vdb.vprint("Unknown Thread Id: %d" % tid)
        return
    teb = t.getStruct("win32.TEB", tinfo)
    addr = long(teb.TIB.ExceptionList)
    vdb.vprint("REG        HANDLER")
    while addr != 0xffffffff:
        #FIXME print out which frame these are in
        er = t.getStruct("win32.EXCEPTION_REGISTRATION", addr)
        vdb.vprint("0x%.8x 0x%.8x" % (addr, er.handler))
        addr = long(er.prev)

def safeseh(vdb, line):
    """
    Show the SafeSEH status of all the loaded DLLs or list the
    handlers for a particular dll by normalized name.

    Usage: safeseh [libname]
    """
    t = vdb.getTrace()
    libs = t.getMeta("LibraryBases")
    if len(line):
        base = libs.get(line)
        if base == None:
            vdb.vprint("Unknown library: %s" % line)
            return

        vdb.vprint("%s:" % line)
        p = PE.peFromMemoryObject(t, base)
        if p.IMAGE_LOAD_CONFIG != None:
            va = int(p.IMAGE_LOAD_CONFIG.SEHandlerTable)
            if va != 0:
                count = int(p.IMAGE_LOAD_CONFIG.SEHandlerCount)
                for h in t.readMemoryFormat(va, "<%dL" % count):
                    vdb.vprint("\t0x%.8x %s" % (base+h, vdb.reprPointer(base+h)))
                return
        vdb.vprint("None...")
            
    else:
        lnames = libs.keys()
        lnames.sort()
        for name in lnames:
            base = libs.get(name)
            p = PE.peFromMemoryObject(t, base)
            enabled = False
            if p.IMAGE_LOAD_CONFIG != None:
                va = int(p.IMAGE_LOAD_CONFIG.SEHandlerTable)
                if va != 0:
                    enabled = True
                #print name
                #print p.IMAGE_LOAD_CONFIG
            vdb.vprint("%16s\t%s" % (name, enabled))

def validate_heaps(db):
    """
    A simple routine that works like the built in windows
    heap checkers to show where blocks and/or freelist
    is potentially dorked.
    """
    trace = db.getTrace()
    db.vprint("Validating:")
    for heap in win32heap.getHeaps(trace):
        db.vprint("%s: 0x%.8x" % ("heap".rjust(9), heap.address))

        try:
            f = heap.getFreeLists()
        except Exception, e:
            db.vprint("%s: %s" % (e.__class__.__name__,e))

        for seg in heap.getSegments():
            db.vprint("%s: 0x%.8x" % ("segment".rjust(9),seg.address))
            try:
                blist = seg.getChunks()
            except Exception, e:
                db.vprint("%s: %s" % (e.__class__.__name__,e))

def heaps(vdb, line):
    """
    Show Win32 Heap Information.

    Usage: heaps [-F <heapaddr>] [-C <address>] [-L <segmentaddr>]
    -F <heapaddr> print the freelist for the heap
    -C <address>  Find and print the heap chunk containing <address>
    -S <segmentaddr> Print the chunks for the given heap segment
    -L <heapaddr> Print the look aside list for the given heap
    -V Validate the heaps (check next/prev sizes and free list)
    -l <heapaddr> Leak detection (list probable leaked chunks)
    (no options lists heaps and segments)
    """
    t = vdb.getTrace()
    t.requireAttached()

    argv = e_cli.splitargs(line)
    freelist_heap = None
    chunkfind_addr = None
    chunklist_seg = None
    lookaside_heap = None
    leakfind_heap = None
    try:
        opts,args = getopt.getopt(argv, "F:C:S:L:l:V")
    except Exception, e:
        return vdb.do_help('heaps')

    for opt,optarg in opts:
        if opt == "-F":
            freelist_heap = t.parseExpression(optarg)
        elif opt == "-C":
            chunkfind_addr = t.parseExpression(optarg)
        elif opt == "-L":
            lookaside_heap = t.parseExpression(optarg)
        elif opt == "-S":
            chunklist_seg = t.parseExpression(optarg)
        elif opt == "-V":
            return validate_heaps(vdb)
        elif opt == "-l":
            leakfind_heap = t.parseExpression(optarg)

    if lookaside_heap != None:
        haddrs = [h.address for h in win32heap.getHeaps(t)]
        if lookaside_heap not in haddrs:
            vdb.vprint("0x%.8x is NOT a valid heap!" % lookaside_heap)
            return

        heap = win32heap.Win32Heap(t, lookaside_heap)
        for i,l in enumerate(heap.getLookAsideLists()):
            if len(l):
                vdb.vprint("Lookaside Index: %d" % i)
                for c in l:
                    vdb.vprint("    %s" % (repr(c)))

    elif freelist_heap != None:
        haddrs = [h.address for h in win32heap.getHeaps(t)]
        if freelist_heap not in haddrs:
            vdb.vprint("0x%.8x is NOT a valid heap!" % freelist_heap)
            return

        heap = win32heap.Win32Heap(t, freelist_heap)
        for i,l in enumerate(heap.getFreeLists()):
            if len(l):
                vdb.vprint("Freelist Index: %d" % i)
                for c in l:
                    vdb.vprint("   %s" % repr(c))

    elif chunkfind_addr != None:
        heap,seg,chunk = win32heap.getHeapSegChunk(t, chunkfind_addr)
        vdb.vprint("Address  0x%.8x found in:" % (chunkfind_addr,))
        vdb.vprint("Heap:    0x%.8x" % (heap.address))
        vdb.vprint("Segment: 0x%.8x" % (seg.address))
        vdb.vprint("Chunk:   0x%.8x (%d) FLAGS: %s" % (chunk.address, len(chunk),chunk.reprFlags()))

    elif chunklist_seg != None:

        for heap in win32heap.getHeaps(t):
            for seg in heap.getSegments():
                if chunklist_seg == seg.address:
                    vdb.vprint("Chunks for segment at 0x%.8x (X == in use)" % chunklist_seg)
                    for chunk in seg.getChunks():
                        c = " "
                        if chunk.isBusy():
                            c = "X"
                        vdb.vprint("0x%.8x %s (%d)" % (chunk.address,c,len(chunk)))
                    return

        vdb.vprint("Segment 0x%.8x not found!" % chunklist_seg)

    elif leakfind_heap != None:
        # FIXME do this the slow way for now...
        haddrs = [h.address for h in win32heap.getHeaps(t)]
        if leakfind_heap not in haddrs:
            vdb.vprint("0x%.8x is NOT a valid heap!" % leakfind_heap)
            return

        h = win32heap.Win32Heap(t, leakfind_heap)
        for seg in h.getSegments():
            for chunk in seg.getChunks():
                if chunk.address == seg.address:
                    continue
                # Obviously, only check for leaks if they are in use...
                # FIXME we will need to check the lookaside also...
                if not chunk.isBusy():
                    continue
                addr = chunk.getDataAddress()
                # FIXME get size and endian from trace
                pat = e_bits.buildbytes(addr, 4)
                l = t.searchMemory(pat)
                if len(l) == 0:
                    vdb.vprint("0x%.8x may be leaked!" % addr)

    else:
        vdb.vprint("Heap\t\tSegment")
        for heap in win32heap.getHeaps(t):
            flags = " ".join(heap.getFlagNames())
            for s in heap.getSegments():
                vdb.vprint("0x%.8x\t0x%.8x\t%s" % (heap.address, s.address, flags))

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040

def showaslr(vdb, base, libname):
    t = vdb.getTrace()
    p = PE.peFromMemoryObject(t, base)
    enabled = False
    c = p.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics
    if c & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        enabled = True
    vdb.vprint("%16s\t%s" % (libname, enabled))

def aslr(vdb, line):
    """
    Determine which PE's in the current process address space
    support Vista's ASLR implementation by the presence of the
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) bit in the 
    DllCharacteristics field of the PE header.

    Usage: aslr [libname]
    """
    t = vdb.getTrace()
    libs = t.getMeta("LibraryBases")
    if line:
        base = libs.get(line)
        if base == None:
            vdb.vprint("Unknown library: %s" % line)
            return
        showaslr(vdb, base, line)
    else:
        lnames = libs.keys()
        lnames.sort()
        for name in lnames:
            base = libs.get(name)
            showaslr(vdb, base, name)

def pagewatch(vdb, line):
    """
    Enable write access watching on a given memory page.  This works
    by setting the page to read-only and then specially handling the
    access violations as though they were hardware Watchpoints.

    Usage: pagewatch [options] [<addr_expression>]
    -C - Clear the current pagewatch log
    -L - List the current hits from the pagewatch log
    -M - Add page watches to the entire memory map from addr_expression
    -S <addr> - Show edits to the specified address
    -P <addr> - Show memory touched by specifed program counter (eip)
    """
    argv = e_cli.splitargs(line)
    try:
        opts,args = getopt.getopt(argv, "CLMP:S:")
    except Exception, e:
        vdb.vprint(pagewatch.__doc__)
        return 

    domap = False
    for opt,optarg in opts:
        if opt == "-C":
            vdb.trace.setMeta("pagewatch", [])
            vdb.vprint("Pagewatch log cleared")
            return

        elif opt == "-L":
            x = vdb.trace.getMeta("pagewatch")
            if x == None:
                vdb.vprint("No pagewatch log!")
                return
            vdb.vprint("[  eip  ] [ mem addr ]")
            for eip,addr in x:
                vdb.vprint("0x%.8x 0x%.8x" % (eip,addr))
            return

        elif opt == "-M":
            domap = True

        elif opt == "-S":
            saddr = vdb.trace.parseExpression(optarg)
            x = vdb.trace.getMeta("pagewatch")
            if x == None:
                vdb.vprint("No pagewatch log!")
                return
            vdb.vprint("[  eip  ] [ mem addr ]")
            for eip,addr in x:
                if addr != saddr:
                    continue
                vdb.vprint("0x%.8x 0x%.8x" % (eip,addr))
            return

        elif opt == "-P":
            saddr = vdb.trace.parseExpression(optarg)
            x = vdb.trace.getMeta("pagewatch")
            if x == None:
                vdb.vprint("No pagewatch log!")
                return
            vdb.vprint("[  eip  ] [ mem addr ]")
            for eip,addr in x:
                if eip != saddr:
                    continue
                vdb.vprint("0x%.8x 0x%.8x" % (eip,addr))
            return

    if len(args) == 0:
        vdb.vprint(pagewatch.__doc__)
        return 

    baseaddr = vdb.trace.parseExpression(args[0])
    # Page align
    baseaddr = baseaddr & 0xfffff000
    maxaddr = baseaddr + 4096

    map = vdb.trace.getMemoryMap(baseaddr)
    if map == None:
        raise Exception("Invalid memory map address 0x%.8x" % map)

    if domap:
        baseaddr = map[0]
        maxaddr  = baseaddr + map[1]

    bpcode = "trace.getMeta('pagewatch').append((eip,trace.platformGetMemFault()));trace.runAgain()"
    vdb.trace.setMeta("pagewatch", [])
    while baseaddr < maxaddr:
        wp = vtrace.PageWatchpoint(baseaddr, size=4096, perms="w")
        wpid = vdb.trace.addBreakpoint(wp)
        vdb.trace.setBreakpointCode(wpid, bpcode)
        baseaddr += 4096

def stealth(vdb, line):
    """
    Enable basic debugger stealth.  This has the following effects:

    Change PEB to show BeingDebugged == 0
    Special breakpoint on CheckRemoteDebuggerPresent

    WARNING:
    break/sendBreak() behave VERY strange with this because the
    kernel aparently doesn't think he needs to post the exception
    to the debugger?
    """
    if vdb.trace.getMeta("Win32Stealth") != None:
        win32_stealth.unstealthify(vdb.trace)
        vdb.vprint("Stealth disabled")
    else:
        win32_stealth.stealthify(vdb.trace)
        vdb.vprint("Stealth enabled")

def pe(vdb, line):
    """
    Show extended info about loaded PE binaries.

    Usage: pe [opts] [<libname>...]
    -I      Show PE import files.
    -t      Show PE timestamp information
    """
    #-v      Show PE version information
    argv = e_cli.splitargs(line)
    try:
        opts,args = getopt.getopt(argv, "Itv")
    except Exception, e:
        vdb.vprint(pe.__doc__)
        return 

    showvers = False
    showtime = False
    showimps = False
    for opt,optarg in opts:
        if opt == '-I':
            showimps = True
        elif opt == '-t':
            showtime = True
        elif opt == '-v':
            showvers = True

    t = vdb.trace
    bases = t.getMeta("LibraryBases")
    paths = t.getMeta("LibraryPaths")

    names = args
    if len(names) == 0:
        names = t.getNormalizedLibNames()

    names.sort()
    names = vdb.columnstr(names)
    for libname in names:
        base = bases.get(libname.strip(), -1)
        path = paths.get(base, "unknown")

        mem = PE.MemObjFile(t, base)
        pobj = PE.PE(mem, inmem=True)

        if showimps:
            ldeps = {}
            for rva,lname,fname in pobj.getImports():
                ldeps[lname.lower()] = True
            lnames = ldeps.keys()
            lnames.sort()
            vdb.vprint('0x%.8x - %.30s %s' % (base, libname, ' '.join(lnames)))
        elif showvers:
            vdb.vprint('0x%.8x - %.30s %s' % (base, libname, path))
        elif showtime:
            tstamp = pobj.IMAGE_NT_HEADERS.FileHeader.TimeDateStamp
            vdb.vprint('0x%.8x - %.30s 0x%.8x' % (base, libname, tstamp))
        else:
            vdb.vprint('0x%.8x - %.30s %s' % (base, libname, path))

def bindiff(mem1, mem2):
    ret = []
    i = 0
    imax = len(mem1)
    while i < imax:
        r = i
        while mem1[r] != mem2[r] and r < imax:
            r += 1
        # We found a discrepency
        if r != i:
            size = (r-i)
            ret.append((i,size))
            i+=r
        i+=1
    return ret

def hooks(vdb, line):
    '''
    Check the executable regions of the target process for any
    hooks by comparing against the PE on disk.  This will
    account for relocations and import entries.
    '''
    t = vdb.getTrace()
    bases = t.getMeta("LibraryBases")
    paths = t.getMeta("LibraryPaths")
    found = False
    for bname in bases.keys():
        base = bases.get(bname)
        fpath = paths.get(base)
        pobj = PE.PE(file(fpath,'rb'))
        filebase = pobj.IMAGE_NT_HEADERS.OptionalHeader.ImageBase

        skips = {}
        # Get relocations for skipping
        r = (0,1,2,3)
        for relrva, reltype in pobj.getRelocations():
            for i in r:
                skips[base+relrva+i] = True
        # Add the import entries to skip
        for iva,libname,name in pobj.getImports():
            for i in r:
                skips[base+iva+i] = True

        for sec in pobj.getSections():
            if sec.Characteristics & PE.IMAGE_SCN_MEM_EXECUTE:
                size = sec.VirtualSize
                va = base + sec.VirtualAddress
                fileva = filebase + sec.VirtualAddress
                filebytes = pobj.readAtRva(sec.VirtualAddress, sec.VirtualSize)
                procbytes = t.readMemory(va, size)
                for off,size in bindiff(filebytes, procbytes):
                    difva = va + off
                    fdifva = fileva + off
                    # Check for a relocation covering this...
                    if skips.get(difva):
                        continue
                    found = True
                    dmem = procbytes[off:off+size].encode('hex')[:10]
                    dfil = filebytes[off:off+size].encode('hex')[:10]

                    vdb.canvas.addVaText('0x%.8x' % difva, difva)
                    vdb.canvas.addText(' (0x%.8x) (%d)' % (fdifva,size))
                    vdb.canvas.addText(' mem: %s file: %s ' % (dmem, dfil))

                    sym = vdb.symobj.getSymByAddr(difva, exact=False)
                    if sym != None:
                        vdb.canvas.addText(' ')
                        vdb.canvas.addVaText('%s + %d' % (repr(sym),difva-long(sym)), difva)
                    vdb.canvas.addText('\n')

    if not found: vdb.canvas.addText('No Hooks Found!\n')

# The necissary module extension function
def vdbExtension(vdb, trace):
    vdb.registerCmdExtension(pe)
    vdb.registerCmdExtension(peb)
    vdb.registerCmdExtension(einfo)
    vdb.registerCmdExtension(heaps)
    vdb.registerCmdExtension(regkeys)
    vdb.registerCmdExtension(seh)
    vdb.registerCmdExtension(safeseh)
    vdb.registerCmdExtension(teb)
    vdb.registerCmdExtension(pagewatch)
    vdb.registerCmdExtension(stealth)
    vdb.registerCmdExtension(aslr)
    vdb.registerCmdExtension(hooks)

