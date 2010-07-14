"""
Tracer Platform Base
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import struct
import vtrace
import traceback
import platform

from Queue import Queue
from threading import Thread,currentThread,Lock

import envi
import envi.resolver as e_resolv
import envi.memory as e_mem

class TracerBase(vtrace.Notifier):
    """
    The basis for a tracer's internals.  All platformFoo/archFoo
    functions are defaulted, and internal state is initialized.
    Additionally, a number of internal utilities are housed here.
    """
    def __init__(self):
        """
        The routine to initialize a tracer's initial internal state.  This
        is used by the initial creation routines, AND on attaches/executes
        to re-fresh the state of the tracer.
        WARNING: This will erase all metadata/symbols (modes/notifiers are kept)
        """
        vtrace.Notifier.__init__(self)

        self.pid = 0 # Attached pid (also used to know if attached)
        self.exited = False
        self.breakpoints = {}
        self.bpbyid = {}
        self.bpid = 0
        self.curbp = None
        self.bplock = Lock()
        self.deferred = []
        self.running = False
        self.runagain = False
        self.attached = False
        # A cache for memory maps and fd listings
        self.mapcache = None
        self.threadcache = None
        self.fds = None
        self.signal_ignores = []
        self.localvars = {}

        self.psize = self.getPointerSize() # From the envi arch mod...

        # Track which libraries are parsed, and their
        # normame to full path mappings
        self.libloaded = {} # True if the library has been loaded already
        self.libpaths = {}  # normname->filename and filename->normname lookup

        # For all transient data (if notifiers want
        # to track stuff per-trace
        self.metadata = {}

        # Set up some globally expected metadata
        self.setMeta("PendingSignal", 0)
        self.setMeta("IgnoredSignals",[])
        self.setMeta("LibraryBases", {}) # name -> base address mappings for binaries
        self.setMeta("LibraryPaths", {}) # base -> path mappings for binaries
        self.setMeta("ThreadId", -1) # If you *can* have a thread id put it here
        arch = envi.getCurrentArch()
        plat = platform.system()
        rel  = platform.release()
        self.setMeta("Architecture", arch)
        self.setMeta("Platform", plat)
        self.setMeta("Release", rel)

        # Use this if we are *expecting* a break
        # which is caused by us (so we remove the
        # SIGBREAK from pending_signal
        self.setMeta("ShouldBreak", False)

    def nextBpId(self):
        self.bplock.acquire()
        x = self.bpid
        self.bpid += 1
        self.bplock.release()
        return x

    def justAttached(self, pid):
        """
        platformAttach() function should call this
        immediately after a successful attach.  This does
        any necessary initialization for a tracer to be
        back in a clean state.
        """
        self.pid = pid
        self.attached = True
        self.breakpoints = {}
        self.bpbyid = {}
        self.setMeta("PendingSignal", 0)
        self.setMeta("PendingException", None)
        self.setMeta("ExitCode", 0)
        self.exited = False

    def getResolverForFile(self, filename):
        res = self.resbynorm.get(filename, None)
        if res: return res
        res = self.resbyfile.get(filename, None)
        if res: return res
        return None

    def steploop(self):
        """
        Continue stepi'ing in a loop until shouldRunAgain()
        returns false (like RunForever mode or something)
        """
        if self.getMode("NonBlocking", False):
            thr = Thread(target=self.doStepLoop)
            thr.setDaemon(True)
            thr.start()
        else:
            self.doStepLoop()

    def doStepLoop(self):
        go = True
        while go:
            self.stepi()
            go = self.shouldRunAgain()

    def _doRun(self):
        # Exists to avoid recursion from loop in doWait
        self.requireAttached()
        self.requireNotRunning()
        self.requireNotExited()

        self.fireNotifiers(vtrace.NOTIFY_CONTINUE)

        # Step past a breakpoint if we are on one.
        self._checkForBreak()
        # Throw down and activate breakpoints...
        self._throwdownBreaks()

        self.running = True
        # Syncregs must happen *after* notifiers for CONTINUE
        # and checkForBreak.
        self._syncRegs()
        self.platformContinue()
        self.setMeta("PendingSignal", 0)

    def wait(self):
        """
        Wait for the trace target to have
        something happen...   If the trace is in
        NonBlocking mode, this will fire a thread
        to wait for you and return control immediately.
        """
        if self.getMode("NonBlocking"):
            thr = Thread(target=self._doWait)
            thr.setDaemon(True)
            thr.start()
        else:
            self._doWait()

    def _doWait(self):
        doit = True
        while doit:
        # A wrapper method for  wait() and the wait thread to use
            event = self.platformWait()
            self.running = False
            self.platformProcessEvent(event)
            doit = self.shouldRunAgain()
            if doit:
                self._doRun()

    def _throwdownBreaks(self):
        """
        Run through the breakpoints and setup
        the ones that are enabled.
        """
        self.curbp = None
        if self.getMode("FastBreak"):
            if self.fb_bp_done:
                return

        # Resolve deferred breaks
        for bp in self.deferred:
            addr = bp.resolveAddress(self)
            if addr != None:
                self.deferred.remove(bp)
                self.breakpoints[addr] = bp

        for bp in self.breakpoints.values():
            if bp.isEnabled():
                try:
                    bp.activate(self)
                except Exception, e:
                    traceback.print_exc()
                    print "WARNING: bpid %d activate failed (deferring): %s" % (bp.id, e)
                    self.deferred.append(bp)

        if self.getMode("FastBreak"):
            self.fb_bp_done = True

    def _syncRegs(self):
        """
        Sync the reg-cache into the target process
        """
        if self.regcache != None:
            for tid, ctx in self.regcache.items():
                if ctx.isDirty():
                    self.platformSetRegCtx(tid, ctx)
        self.regcache = None

    def _cacheRegs(self, threadid):
        """
        Make sure the reg-cache is populated
        """
        if self.regcache == None:
            self.regcache = {}
        ret = self.regcache.get(threadid)
        if ret == None:
            ret = self.platformGetRegCtx(threadid)
            self.regcache[threadid] = ret
        return ret

    def _checkForBreak(self):
        """
        Check to see if we've landed on a breakpoint, and if so
        deactivate and step us past it.

        WARNING: Unfortunatly, cause this is used immidiatly before
        a call to run/wait, we must block briefly even for the GUI
        """
        # Steal a reference because the step should
        # clear curbp...
        bp = self.curbp
        if bp != None and bp.isEnabled():
            bp.deactivate(self)
            orig = self.getMode("FastStep")
            self.setMode("FastStep", True)
            self.stepi()
            self.setMode("FastStep", orig)
            bp.activate(self)

    def shouldRunAgain(self):
        """
        A unified place for the test as to weather this trace
        should be told to run again after reaching some stopping
        condition.
        """
        if not self.attached:
            return False

        if self.exited:
            return False

        if self.getMode("RunForever"):
            return True

        if self.runagain:
            return True

        return False

    def __repr__(self):
        run = "stopped"
        exe = "None"
        if self.isRunning():
            run = "running"
        elif self.exited:
            run = "exited"
        exe = self.getMeta("ExeName")
        return "[%d]\t- %s <%s>" % (self.pid, exe, run)

    def initMode(self, name, value, descr):
        """
        Initialize a mode, this should ONLY be called
        during setup routines for the trace!  It determines
        the available mode setings.
        """
        self.modes[name] = bool(value)
        self.modedocs[name] = descr

    def release(self):
        """
        Do cleanup when we're done.  This is mostly necissary
        because of the thread proxy holding a reference to this
        tracer...  We need to let him die off and try to get
        garbage collected.
        """
        if self.thread:
            self.thread.go = False

    def __del__(self):
        if self.attached:
            self.detach()

        if self.thread:
            self.thread.go = False


    def fireTracerThread(self):
        self.thread = TracerThread()

    def fireNotifiers(self, event):
        """
        Fire the registered notifiers for the NOTIFY_* event.
        """
        if currentThread().__class__ == TracerThread:
            raise Exception("ERROR: you can't fireNotifiers from *inside* the TracerThread")

        # Skip out on notifiers for NOTIFY_BREAK when in
        # FastBreak mode
        if self.getMode("FastBreak", False) and event == vtrace.NOTIFY_BREAK:
            return

        if self.getMode("FastStep", False) and event == vtrace.NOTIFY_STEP:
            return

        if event == vtrace.NOTIFY_SIGNAL:
            win32 = self.getMeta("Win32Event", None)
            if win32:
                code = win32["ExceptionCode"]
            else:
                code = self.getMeta("PendingSignal", 0)

            if code in self.getMeta("IgnoredSignals", []):
                if vtrace.verbose: print "Ignoring",code
                self.runAgain()
                return

        alllist = self.getNotifiers(vtrace.NOTIFY_ALL)
        nlist = self.getNotifiers(event)

        trace = self
        # if the trace has a proxy it's notifiers
        # need that, cause we can't be pickled ;)
        if self.proxy:
            trace = self.proxy

        # The "NOTIFY_ALL" guys get priority
        for notifier in alllist:
            try:
                if notifier == self:
                    notifier.handleEvent(event,self)
                else:
                    notifier.handleEvent(event,trace)
            except:
                print "WARNING: Notifier exception for",repr(notifier)
                traceback.print_exc()

        for notifier in nlist:
            try:
                if notifier == self:
                    notifier.handleEvent(event,self)
                else:
                    notifier.handleEvent(event,trace)
            except:
                print "WARNING: Notifier exception for",repr(notifier)
                traceback.print_exc()

    def _cleanupBreakpoints(self):
        self.fb_bp_done = False
        for bp in self.breakpoints.itervalues():
            # No harm in calling deactivate on
            # an inactive bp
            bp.deactivate(self)

    def _fireBreakpoint(self, bp):
        self.curbp = bp
        try:
            bp.notify(vtrace.NOTIFY_BREAK, self)
        except Exception, msg:
            print "Breakpoint Exception 0x%.8x : %s" % (bp.address,msg)
        self.fireNotifiers(vtrace.NOTIFY_BREAK)

    def checkPageWatchpoints(self):
        """
        Check if the given memory fault was part of a valid
        MapWatchpoint.
        """
        faultaddr = self.platformGetMemFault()

        #FIXME this is some AWESOME but intel specific nonsense
        if faultaddr == None: return False
        faultpage = faultaddr & 0xfffff000

        wp = self.breakpoints.get(faultpage, None)
        if wp == None:
            return False

        self._fireBreakpoint(wp)
        return True

    def checkWatchpoints(self):
        # Check for hardware watchpoints
        waddr = self.archCheckWatchpoints()
        if waddr != None:
            wp = self.breakpoints.get(waddr, None)
            self._fireBreakpoint(wp)
            return True

    def checkBreakpoints(self):
        """
        This is mostly for systems (like linux) where you can't tell
        the difference between some SIGSTOP/SIGBREAK conditions and
        an actual breakpoint instruction.
        This method will return true if either the breakpoint
        subsystem or the sendBreak (via ShouldBreak meta) is true
        """
        pc = self.getProgramCounter()
        bi = self.archGetBreakInstr()
        bl = pc - len(bi)
        bp = self.breakpoints.get(bl, None)

        if bp:
            addr = bp.getAddress()
            # Step back one instruction to account break
            self.setProgramCounter(addr)
            self._fireBreakpoint(bp)
            return True

        if self.getMeta("ShouldBreak"):
            self.setMeta("ShouldBreak", False)
            self.fireNotifiers(vtrace.NOTIFY_BREAK)
            return True

        return False

    def notify(self, event, trace):
        """
        We are frequently a notifier for ourselves, so we can do things
        like handle events on attach and on break in a unified fashion.
        """
        self.threadcache = None
        self.mapcache = None
        self.fds = None
        self.running = False

        if event in self.auto_continue:
            self.runAgain()

        # For thread exits, make sure the tid
        # isn't in 
        if event == vtrace.NOTIFY_EXIT_THREAD:
            tid = self.getMeta("ThreadId")
            self.sus_threads.pop(tid, None)

        # Do the stuff we do for detach/exit or
        # cleanup breaks etc...
        if event == vtrace.NOTIFY_ATTACH:
            pass

        elif event == vtrace.NOTIFY_DETACH:
            for tid in self.sus_threads.keys():
                self.resumeThread(tid)
            self._cleanupBreakpoints()

        elif event == vtrace.NOTIFY_EXIT:
            self.setMode("RunForever", False)
            self.exited = True
            self.attached = False

        elif event == vtrace.NOTIFY_CONTINUE:
            self.runagain = False

        else:
            # Any of the events in this pool mean we're
            # stopping but still attached.
            if not self.getMode("FastBreak"):
                self._cleanupBreakpoints()

    def delLibraryBase(self, baseaddr):

        libname = self.getMeta("LibraryPaths").get(baseaddr, "unknown")
        normname = self.normFileName(libname)

        sym = self.getSymByName(normname)

        self.setMeta("LatestLibrary", libname)
        self.setMeta("LatestLibraryNorm", normname)

        self.fireNotifiers(vtrace.NOTIFY_UNLOAD_LIBRARY)

        self.getMeta("LibraryBases").pop(normname, None)
        self.getMeta("LibraryPaths").pop(baseaddr, None)
        if sym != None:
            self.delSymbol(sym)

    def addLibraryBase(self, libname, address):
        """
        This should be used *at load time* to setup the library
        event metadata.

        This *must* be called from a context where it's safe to
        fire notifiers, because it will fire a notifier to alert
        about a LOAD_LIBRARY. (This means *not* from inside another
        notifer)
        """

        self.setMeta("LatestLibrary", None)
        self.setMeta("LatestLibraryNorm", None)

        normname = self.normFileName(libname)
        if self.getSymByName(normname) != None:
            normname = "%s_%.8x" % (normname,address)

        # Only actually do library work
        if os.path.exists(libname):

            self.getMeta("LibraryPaths")[address] = libname
            self.getMeta("LibraryBases")[normname] = address
            self.setMeta("LatestLibrary", libname)
            self.setMeta("LatestLibraryNorm", normname)

            width = self.arch.getPointerSize()
            sym = e_resolv.FileSymbol(normname, address, 0, width=width)
            sym.casesens = self.casesens
            self.addSymbol(sym)

            self.libpaths[normname] = libname

            self.fireNotifiers(vtrace.NOTIFY_LOAD_LIBRARY)

    def normFileName(self, libname):
        basename = os.path.basename(libname)
        return basename.split(".")[0].split("-")[0].lower()

    def _loadBinaryNorm(self, normname):
        if not self.libloaded.get(normname, False):
            fname = self.libpaths.get(normname)
            if fname != None:
                self._loadBinary(fname)
                return True
        return False

    def _loadBinary(self, filename):
        """
        Check if a filename has yet to be parsed.  If it has NOT
        been parsed, parse it and return True, otherwise, return False
        """
        normname = self.normFileName(filename)
        if not self.libloaded.get(normname, False):
            address = self.getMeta("LibraryBases").get(normname)
            if address != None:
                self.platformParseBinary(filename, address, normname)
                self.libloaded[normname] = True
                return True
        return False

    def threadWrap(self, name, meth):
        """
        Cause the method (given in value) to be wrapped
        by a single thread for carying out.
        (which allows us to only synchronize what *needs* to
        synchronized...)
        """
        wrapmeth = TracerMethodProxy(meth, self.thread)
        setattr(self, name, wrapmeth)

#######################################################################
#
# NOTE: all platform/arch defaults are populated here.
#
    def platformGetThreads(self):
        """
        Return a dictionary of <threadid>:<tinfo> pairs where tinfo is either
        the stack top, or the teb for win32
        """
        raise Exception("Platform must implement platformGetThreads()")

    def platformSelectThread(self, thrid):
        """
        Platform implementers are encouraged to use the metadata field "ThreadId"
        as the identifier (int) for which thread has "focus".  Additionally, the
        field "StoppedThreadId" should be used in instances (like win32) where you
        must specify the ORIGINALLY STOPPED thread-id in the continue.
        """
        self.setMeta("ThreadId",thrid)

    def platformSuspendThread(self, thrid):
        raise Exception("Platform must implement platformSuspendThread()")

    def platformResumeThread(self, thrid):
        raise Exception("Platform must implement platformResumeThread()")

    def platformInjectThread(self, pc, arg=0):
        raise Exception("Platform must implement platformInjectThread()")

    def platformKill(self):
        raise Exception("Platform must implement platformKill()")

    def platformExec(self, cmdline):
        """
        Platform exec will execute the process specified in cmdline
        and return the PID
        """
        raise Exception("Platmform must implement platformExec")

    def platformInjectSo(self, filename):
        raise Exception("Platform must implement injectso()")

    def platformGetFds(self):
        """
        Return what getFds() wants for this particular platform
        """
        raise Exception("Platform must implement platformGetFds()")

    def platformGetMaps(self):
        """
        Return a list of the memory maps where each element has
        the following structure:
        (address, length, perms, file="")
        NOTE: By Default this list is available as Trace.maps
        because the default implementation attempts to populate
        them on every break/stop/etc...
        """
        raise Exception("Platform must implement GetMaps")

    def platformPs(self):
        """
        Actually return a list of tuples in the format
        (pid, name) for this platform
        """
        raise Exception("Platform must implement Ps")

    def archGetStackTrace(self):
        raise Exception("Architecure must implement argGetStackTrace()!")

    def archAddWatchpoint(self, address, size=4, perms="rw"):
        """
        Add a watchpoint for the given address.  Raise if the platform
        doesn't support, or too many are active...
        """
        raise Exception("Architecture doesn't implement watchpoints!")

    def archRemWatchpoint(self, address):
        raise Exception("Architecture doesn't implement watchpoints!")

    def archCheckWatchpoints(self):
        """
        If the current register state indicates that a watchpoint was hit, 
        return the address of the watchpoint and clear the event.  Otherwise
        return None
        """
        pass

    def archGetRegCtx(self):
        """
        Return a new empty envi.registers.RegisterContext object for this
        trace.
        """
        raise Exception("Platform must implement archGetRegCtx()")

    def getStackTrace(self):
        """
        Return a list of the stack frames for this process
        (currently Intel/ebp based only).  Each element of the
        "frames list" consists of another list which is (eip,ebp)
        """
        raise Exception("Platform must implement getStackTrace()")

    def getExe(self):
        """
        Get the full path to the main executable for this
        *attached* Trace
        """
        return self.getMeta("ExeName","Unknown")

    def platformAttach(self, pid):
        """
        Actually carry out attaching to a target process.  Like
        platformStepi this is expected to be ATOMIC and not return
        until a complete attach.
        """
        raise Exception("Platform must implement platformAttach()")

    def platformContinue(self):
        raise Exception("Platform must implement platformContinue()")

    def platformDetach(self):
        """
        Actually perform the detach for this type
        """
        raise Exception("Platform must implement platformDetach()")

    def platformStepi(self):
        """
        PlatformStepi should be ATOMIC, meaning it gets called, and
        by the time it returns, you're one step further.  This is completely
        regardless of blocking/nonblocking/whatever.
        """
        raise Exception("Platform must implement platformStepi!")

    def platformCall(self, address, args, convention=None):
        """
        Platform call takes an address, and an array of args
        (string types will be mapped and located for you)

        platformCall is expected to return a dicionary of the
        current register values at the point where the call
        has returned...
        """
        raise Exception("Platform must implement platformCall")

    def platformGetRegCtx(self, threadid):
        raise Exception("Platform must implement platformGetRegCtx!")

    def platformSetRegCtx(self, threadid, ctx):
        raise Exception("Platform must implement platformSetRegCtx!")

    def platformProtectMemory(self, va, size, perms):
        raise Exception("Plaform does not implement protect memory")
        
    def platformAllocateMemory(self, size, perms=e_mem.MM_RWX, suggestaddr=0):
        raise Exception("Plaform does not implement allocate memory")
        
    def platformReadMemory(self, address, size):
        raise Exception("Platform must implement platformReadMemory!")
        
    def platformWriteMemory(self, address, bytes):
        raise Exception("Platform must implement platformWriteMemory!")

    def platformGetMemFault(self):
        """
        Return the addr of the current memory fault
        or None
        """
        #NOTE: This is used by the MapWatchpoint subsystem
        # (and is still considered experimental)
        return None

    def platformWait(self):
        """
        Wait for something interesting to occur and return a
        *platform specific* representation of what happened.

        This will then be passed to the platformProcessEvent()
        method which will be responsible for doing things like
        firing notifiers.  Because the platformWait() method needs
        to be commonly ThreadWrapped and you can't fire notifiers
        from within a threadwrapped function...
        """
        raise Exception("Platform must implement platformWait!")

    def platformProcessEvent(self, event):
        """
        This method processes the event data provided by platformWait()

        This method is responsible for firing ALL notifiers *except*:

        vtrace.NOTIFY_CONTINUE - This is handled by the run api (and isn't the result of an event)
        """
        raise Exception("Platform must implement platformProcessEvent")

    def platformParseBinary(self, filename, baseaddr, normname):
        """
        Platforms must parse the given binary file and load any symbols
        into the internal SymbolResolver using self.addSymbol()
        """
        raise Exception("Platform must implement platformParseBinary")

class TracerMethodProxy:
    def __init__(self, proxymeth, thread):
        self.thread = thread
        self.proxymeth = proxymeth

    def __call__(self, *args, **kwargs):
        if currentThread().__class__ == TracerThread:
            return self.proxymeth(*args, **kwargs)

        queue = Queue()
        self.thread.queue.put((self.proxymeth, args, kwargs, queue))
        ret = queue.get()

        if issubclass(ret.__class__, Exception):
            raise ret
        return ret

class TracerThread(Thread):
    """
    Ok... so here's the catch... most debug APIs do *not* allow
    one thread to do the attach and another to do continue and another
    to do wait... they just dont.  So there.  I have to make a thread
    per-tracer (on most platforms) and proxy requests (for *some* trace
    API methods) to it for actual execution.  SUCK!

    However, this lets async things like GUIs and threaded things like
    cobra not have to be aware of which one is allowed and not allowed
    to make particular calls and on what platforms...  YAY!
    """
    def __init__(self):
        Thread.__init__(self)
        self.queue = Queue()
        self.setDaemon(True)
        self.go = True
        self.start()

    def run(self):
        """
        Run in a circle getting requests from our queue and
        executing them based on the thread.
        """
        while self.go:
            try:
                meth, args, kwargs, queue = self.queue.get()
                try:
                    queue.put(meth(*args, **kwargs))
                except Exception,e:
                    queue.put(e)
                    if vtrace.verbose:
                        traceback.print_exc()
                    continue
            except:
                if vtrace.verbose:
                    traceback.print_exc()


