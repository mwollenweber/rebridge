"""
Vtrace Debugger Framework

Vtrace is a *mostly* native python debugging framework which
can be used to quickly write programatic debuggers and research
tools.

I'm not known for writting great docs...  but the code should
be pretty straight forward...

This has been in use for over 2 years privately, but is nowhere
*near* free of bugs...  idiosyncracies abound.

==== Werd =====================================================

Blah blah blah... many more docs to come.

Brought to you by kenshoto.  e-mail invisigoth.

Greetz:
    h1kari - eeeeeooorrrmmm  CHKCHKCHKCHKCHKCHKCHK
    Ghetto - wizoo... to the tizoot.
    atlas - *whew* finally...  no more teasing...
    beatle/dnm - come out and play yo!
    The Kenshoto Gophers.
    Blackhats Everywhere.

"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import sys
import code
import copy
import time
import types
import struct
import getopt
import signal
import inspect
import platform
import traceback

import cPickle as pickle

import envi
import envi.bits as e_bits
import envi.memory as e_mem
import envi.registers as e_reg
import envi.expression as e_expr
import envi.resolver as e_resolv

import cobra
import vstruct

remote = None       # If set, we're a vtrace client (set to serverhost)
cobra_daemon = None
port = 0x5656
verbose = False

# Order must match format junk
# NOTIFY_ALL is kinda special, if you registerNotifier
# with it, you get ALL notifications.
NOTIFY_ALL = 0          # Get all notifications
NOTIFY_SIGNAL = 1       # Callback on signal/exception
NOTIFY_BREAK = 2        # Callback on breakpoint / sigtrap
NOTIFY_STEP = 3         # Callback on singlestep complete
NOTIFY_SYSCALL = 4      # Callback on syscall (linux only for now)
NOTIFY_CONTINUE = 5     # Callback on continue (not done for step)
NOTIFY_EXIT = 6         # Callback on process exit
NOTIFY_ATTACH = 7       # Callback on successful attach
NOTIFY_DETACH = 8       # Callback on impending process detach       
# The following notifiers are *only* available on some platforms
# (and may be kinda faked out ala library load events on posix)
NOTIFY_LOAD_LIBRARY = 9
NOTIFY_UNLOAD_LIBRARY = 10 
NOTIFY_CREATE_THREAD = 11
NOTIFY_EXIT_THREAD = 12
NOTIFY_DEBUG_PRINT = 13 # Some platforms support this (win32).
NOTIFY_MAX = 20

# File Descriptor / Handle Types
FD_UNKNOWN = 0 # Unknown or we don't have a type for it
FD_FILE = 1
FD_SOCKET = 2
FD_PIPE = 3
FD_LOCK = 4   # Win32 Mutant/Lock/Semaphore
FD_EVENT = 5  # Win32 Event/KeyedEvent
FD_THREAD = 6 # Win32 Thread
FD_REGKEY = 7 # Win32 Registry Key

# Vtrace Symbol Types
SYM_MISC = -1
SYM_GLOBAL = 0 # Global (mostly vars)
SYM_LOCAL = 1 # Locals
SYM_FUNCTION = 2 # Functions
SYM_SECTION = 3 # Binary section
SYM_META = 4 # Info that we enumerate

# Vtrace Symbol Offsets
VSYM_NAME = 0
VSYM_ADDR = 1
VSYM_SIZE = 2
VSYM_TYPE = 3
VSYM_FILE = 4

from vtrace.rmi import *
from vtrace.notifiers import *
from vtrace.breakpoints import *
from vtrace.watchpoints import *
import vtrace.util as v_util

class PlatformException(Exception):
    """
    A universal way to represent a failure in the
    platform layer for this tracer.  platformFoo methods
    should raise this rather than allowing their platform
    specific exception types (which don't likely pickle, or
    are not cross platform)
    """
    pass

class AccessViolation(Exception):
    """
    An exception which is raised on bad-touch to memory
    """
    def __init__(self, va, perm=0):
        self.va = va
        self.perm = perm
        Exception.__init__(self, "AccessViolation at 0x%.8x (%d)" % (va, perm))

class Trace(e_mem.IMemory, e_reg.RegisterContext, e_resolv.SymbolResolver, object):
    """
    The main tracer object.  A trace instance is dynamically generated using
    this and *many* potential mixin classes.  However, API users should *not*
    worry about the methods that come from the mixins...  Everything that is
    *meant* to be used from the API is contained and documented here.
    """
    def __init__(self):
        # For the crazy thread-call-proxy-thing
        # (must come first for __getattribute__
        self.requires_thread = {}
        self.proxymeth = None # FIXME hack for now...
        self.fireTracerThread()

        # The universal place for all modes
        # that might be platform dependant...
        self.modes = {}
        self.modedocs = {}
        self.notifiers = {}

        self.initMode("RunForever", False, "Run until RunForever = False")
        self.initMode("NonBlocking", False, "A call to wait() fires a thread to wait *for* you")
        self.initMode("ThreadProxy", True, "Proxy necissary requests through a single thread (can deadlock...)")
        self.initMode("FastBreak", False, "Do *NOT* add/remove breakpoints per-run, but leave them there once active")
        self.initMode("SingleStep", False, "All calls to run() actually just step.  This allows RunForever + SingleStep to step forever ;)")
        self.initMode("FastStep", False, "All stepi() will NOT generate a step event")

        self.regcache = None
        self.regcachedirty = False
        self.fb_bp_done = False # A little hack for FastBreak mode
        self.sus_threads = {}   # A dictionary of suspended threads

        # Set if we're a server and this trace is proxied
        self.proxy = None

        # Set us up with an envi arch module
        # FIXME eventually we should just inherit one...
        self.arch = envi.getArchModule()

        e_resolv.SymbolResolver.__init__(self, width=self.arch.getPointerSize())
        e_mem.IMemory.__init__(self)
        e_reg.RegisterContext.__init__(self)

        # We'll just use our own notify interface to catch some stuff
        # (which also more-or-less guarentees we'll be first notified for these)
        self.registerNotifier(NOTIFY_ALL, self)

        # Add event numbers to here for auto-continue
        self.auto_continue = [NOTIFY_LOAD_LIBRARY, NOTIFY_CREATE_THREAD, NOTIFY_UNLOAD_LIBRARY, NOTIFY_EXIT_THREAD, NOTIFY_DEBUG_PRINT]

    def execute(self, cmdline):
        """
        Start a new process and debug it
        """
        if self.isAttached():
            raise Exception("ERROR - Tracer must first be detached before you can execute()")

        pid = self.platformExec(cmdline)
        self.justAttached(pid)
        self.wait()

    def addIgnoreSignal(self, code, address=0):
        """
        By adding an IgnoreSignal you tell the tracer object to
        supress the notification of a particular type of signal.
        In POSIX, these are regular signals, in Win32, these
        are exception codes.  This is mostly useful in RunForever
        mode because you still need the process to begin running again.
        (these may be viewed/modified by the metadata key "IgnoredSignals")
        FIXME: make address do something.
        """
        self.getMeta("IgnoredSignals").append(code)

    def delIgnoreSignal(self, code, address=0):
        """
        See addIgnoreSignal for a description of signal ignoring.
        This removes an ignored signal and re-enables it's delivery.
        """
        self.getMeta("IgnoredSignals").remove(code)

    def attach(self, pid):
        """
        Attach to a new process ID.
        """
        if self.isAttached():
            self.detach()
    
        try:
            self.platformAttach(pid)
            self.justAttached(pid)
            self.wait()
        except Exception, msg:
            raise PlatformException(str(msg))

    def stepi(self):
        """
        Single step the target process ONE instruction (and do
        NOT activate breakpoints for the one step). Also, we 
        don't deliver pending signals for the single step...
        Use the mode FastStep to allow/supress notifier callbacks on step
        """
        self.requireNotRunning()

        # Since we don't go through the normal run/wait
        # code, we have a little house-keeping to do...
        self.curbp = None

        self._syncRegs()
        self.platformStepi()
        event = self.platformWait()
        self.platformProcessEvent(event)

    def run(self, until=None):
        """
        Allow the traced target to continue execution.  (Depending on the mode
        "Blocking" this will either block until an event, or return immediately)
        Additionally, the argument until may be used to cause execution to continue
        until the specified address is reached (internally uses and removes a breakpoint).
        """
        self.requireNotRunning()
        if self.getMode("SingleStep", False):
            self.steploop()

        else:
            if until != None:
                self.setMode("RunForever", True)
                self.addBreakpoint(StopAndRemoveBreak(until))

            self._doRun()
            self.wait()

    def runAgain(self, val=True):
        """
        The runAgain() method may be used from inside a notifier
        (Notifier, Breakpoint, Watchpoint, etc...) to inform the trace
        that once event processing is complete, it should continue
        running the trace.
        """
        self.runagain = val

    def kill(self):
        """
        Kill the target process for this trace (will result in process
        exit and fire appropriate notifiers)
        """
        self.requireAttached()
        self.requireNotExited()
        # kill may require that we continue
        # the process before it gets processed,
        # so we'll try to run the process until it
        # exits due to the kill
        self.setMode("RunForever", True) # Forever actually means util exit
        if self.isRunning():
            self.platformKill()
        else:
            self.platformKill()
            self.run()

    def detach(self):
        """
        Detach from the currently attached process.
        """
        self.requireNotRunning()
        self.fireNotifiers(NOTIFY_DETACH)
        self._syncRegs()
        self.platformDetach()
        self.attached = False
        self.pid = 0
        self.mapcache = None

    def getPid(self):
        """
        Return the pid for this Trace
        """
        return self.pid

    def getNormalizedLibNames(self):
        """
        Symbols are stored internally based off of
        "normalized" library names.  This method returns
        the list of normalized names for the loaded libraries.

        (probably only useful for writting symbol browsers...)
        """
        return self.getMeta("LibraryBases").keys()

    def getSymsForFile(self, libname):
        """
        Return the entire symbol list for the specified
        normalized library name.
        """
        self._loadBinaryNorm(libname)
        sym = self.getSymByName(libname)
        return sym.getSymList()

    def getSymByAddr(self, addr, exact=True):
        """
        Return an envi Symbol object for an address.
        Use exact=False to get the nearest previous match.
        """
        # NOTE: Override this from envi.SymbolResolver to do on-demand
        # file parsing.

        r = e_resolv.SymbolResolver.getSymByAddr(self, addr, exact=exact)
        if r != None:
            return r

        # See if we need to parse the file.
        map = self.getMemoryMap(addr)
        if map == None:
            return None

        va,size,perms,fname = map

        if not self._loadBinary(fname):
            return None

        # Take a second shot after parsing
        return e_resolv.SymbolResolver.getSymByAddr(self, addr, exact=exact)

    def getSymByName(self, name):
        """
        Return an envi.Symbol object for the given name (or None)
        """
        self._loadBinaryNorm(name)
        return e_resolv.SymbolResolver.getSymByName(self, name)

    def getRegisterContext(self, threadid=None):
        """
        Retrieve the envi.registers.RegisterContext object for the
        specified thread.  Use this API to iterate over threads
        register values without setting the global tracer thread context.
        """
        if threadid == None:
            threadid = self.getMeta("ThreadId")
        return self._cacheRegs(threadid)

#######################################################################
#
# We mirror the RegisterContext API using our own thread index based
# cache.  These APIs must stay in sync with envi.registers.RegisterContext
# NOTE: for now we only need to over-ride get/setRegister because all the
# higher level APIs call them.
#

    def getRegister(self, idx):
        ctx = self.getRegisterContext()
        return ctx.getRegister(idx)

    def setRegister(self, idx, value):
        ctx = self.getRegisterContext()
        ctx.setRegister(idx, value)

#######################################################################

    def allocateMemory(self, size, perms=e_mem.MM_RWX, suggestaddr=0):
        """
        Allocate a chunk of memory inside the target process' address
        space.  Memory wil be mapped rwx unless otherwise specified with
        perms=envi.memory.MM_FOO values. Optionally you may *suggest* an address
        to the allocator, but there is no guarentee.  Returns the mapped
        memory address.
        """
        self.requireNotRunning()
        self.mapcache = None # We may have a new memory map
        return self.platformAllocateMemory(size, perms=perms, suggestaddr=suggestaddr)

    def protectMemory(self, va, size, perms):
        """
        Change the page protections on the specified region of memory.
        See envi.memory for perms values.
        """
        self.requireNotRunning()
        self.mapcache = None # We may have new memory protections
        return self.platformProtectMemory(va, size, perms)

    def readMemory(self, address, size):
        """
        Read memory from address.  Areas that are NOT valid memory will be read
        back as \x00s (this probably goes in a mixin soon)
        """
        self.requireNotRunning()
        return self.platformReadMemory(long(address), long(size))

    def writeMemory(self, address, bytes):
        """
        Write the given bytes to the address in the current trace.
        """
        self.requireNotRunning()
        self.platformWriteMemory(long(address), bytes)

    def searchMemory(self, needle, regex=False):
        """
        Search all of process memory for a sequence of bytes.
        """
        ret = e_mem.IMemory.searchMemory(self, needle, regex=regex)
        self.setMeta('search', ret)
        self.setVariable('search', ret)
        return ret

    def searchMemoryRange(self, needle, address, size, regex=False):
        """
        Search a memory range for the specified sequence of bytes
        """
        ret = e_mem.IMemory.searchMemoryRange(self, needle, address, size, regex=regex)
        self.setMeta('search', ret)
        self.setVariable('search', ret)
        return ret

    def setMeta(self, name, value):
        """
        Set some metadata.  Metadata is a clean way for
        arbitrary trace consumers (and notifiers) to present
        and track additional information in trace objects.

        Any modules which use this *should* initialize them
        on attach (so when they get re-used they're clean)

        Some examples of metadata used:
        ShouldBreak - We're expecting a non-signal related break
        ExitCode - The int() exit code  (if exited)
        PendingSignal - Used on posix systems
        PendingException - Mostly for win32 for now

        """
        self.metadata[name] = value

    def getMeta(self, name, default=None):
        """
        Get some metadata.  Metadata is a clean way for
        arbitrary trace consumers (and notifiers) to present
        and track additional information in trace objects.

        If you specify a default and the key doesn't exist, not
        not only will the default be returned, but the key will
        be set to the default specified.
        """
        if default:
            if not self.metadata.has_key(name):
                self.metadata[name] = default
        return self.metadata.get(name, None)

    def hasMeta(self, name):
        """
        Check to see if a metadata key exists... Mostly un-necissary
        as getMeta() with a default will set the key to the default
        if non-existant.
        """
        return self.metadata.has_key(name)

    def getMode(self, name, default=False):
        """
        Get the value for a mode setting allowing
        for a clean default...
        """
        return self.modes.get(name, default)

    def setMode(self, name, value):
        """
        Set a mode setting...  This is ONLY valid
        if that mode has been iniitialized with
        initMode(name, value).  Otherwise, it's an
        unsupported mode for this platform ;)  cute huh?
        This way, platform sections can cleanly setmodes
        and such.
        """
        if not self.modes.has_key(name):
            raise Exception("Mode %s not supported on this platform" % name)
        self.modes[name] = bool(value)

    def injectso(self, filename):
        """
        Inject a shared object into the target of the trace.  So, on windows
        this is easy with InjectDll and on *nix... it's.. fugly...
        """
        self.requireNotRunning()
        self.platformInjectSo(filename)

    def ps(self):
        """
        Return a list of proccesses which are currently running on the
        system.
        (pid, name)
        """
        return self.platformPs()

    def addBreakpoint(self, breakpoint):
        """
        Add a breakpoint/watchpoint to the trace.  The "breakpoint" argument
        is a vtrace Breakpoint/Watchpoint object or something that extends it.

        To add a basic breakpoint use trace.addBreakpoint(vtrace.Breakpoint(address))
        NOTE: expression breakpoints do *not* get evaluated in fastbreak mode

        This will return the internal ID given to the new breakpoint
        """
        breakpoint.id = self.nextBpId()
        addr = breakpoint.resolveAddress(self)
        if addr == None:
            self.bpbyid[breakpoint.id] = breakpoint
            self.deferred.append(breakpoint)
            return breakpoint.id

        if self.breakpoints.has_key(addr):
            raise Exception("ERROR: Duplicate break for address 0x%.8x" % addr)
        self.bpbyid[breakpoint.id] = breakpoint
        self.breakpoints[addr] = breakpoint

        return breakpoint.id
    
            
    def removeAllBreakpoints(self):
        """
        Remove all the breakpoints
        """
        self.requireAttached()
        map(self.removeBreakpoint, self.getBreakpoints())

        
    def removeBreakpoint(self, id):
        """
        Remove the breakpoint with the specified ID
        """
        self.requireAttached()
        bp = self.bpbyid.pop(id, None)
        if bp != None:
            bp.deactivate(self)
            if bp in self.deferred:
                self.deferred.remove(bp)
            else:
                self.breakpoints.pop(bp.address, None)

            # If the bp is also curbp, set curbp to None
            if self.curbp == bp:
                self.curbp = None

        # Remove cached breakpoint code
        Breakpoint.bpcodeobj.pop(id, None)

    def getCurrentBreakpoint(self):
        """
        Return the current breakpoint otherwise None
        """
        return self.curbp

    def getBreakpoint(self,id):
        """
        Return a reference to the breakpoint with the requested ID.

        NOTE: NEVER set locals or use things like setBreakpointCode()
        method on return'd breakpoint objects as they may be remote
        and would then be *coppies* of the bp objects. (use the trace's
        setBreakpointCode() instead).
        """
        return self.bpbyid.get(id)

    def getBreakpoints(self):
        """
        Return a list of the current breakpoints.
        """
        return self.bpbyid.values()

    def getBreakpointEnabled(self, bpid):
        """
        An accessor method for returning if a breakpoint is
        currently enabled.
        NOTE: code which wants to be remote-safe should use this
        """
        bp = self.getBreakpoint(bpid)
        if bp == None:
            raise Exception("Breakpoint %d Not Found" % bpid)
        return bp.isEnabled()

    def setBreakpointEnabled(self, bpid, enabled=True):
        """
        An accessor method for setting a breakpoint enabled/disabled.

        NOTE: code which wants to be remote-safe should use this
        """
        bp = self.getBreakpoint(bpid)
        if bp == None:
            raise Exception("Breakpoint %d Not Found" % bpid)
        return bp.setEnabled(enabled)

    def setBreakpointCode(self, bpid, pystr):
        """
        Because breakpoints are potentially on the remote debugger
        and code is not pickleable in python, special access methods
        which takes strings of python code are necissary for the
        vdb interface to quick script breakpoint code.  Use this method
        to set the python code for this breakpoint.
        """
        bp = self.getBreakpoint(bpid)
        if bp == None:
            raise Exception("Breakpoint %d Not Found" % bpid)
        bp.setBreakpointCode(pystr)

    def getBreakpointCode(self, bpid):
        """
        Return the python string of user specified code that will run
        when this breakpoint is hit.
        """
        bp = self.getBreakpoint(bpid)
        if bp != None:
            return bp.getBreakpointCode()
        return None

    def call(self, address, args, convention=None):
        """
        Setup the "stack" and call the target address with the following
        arguments.  If the argument is a string or a buffer, copy that into
        memory and hand in the argument.

        The current state of ALL registers are returned as a dictionary at the
        end of the call...

        Additionally, a "convention" string may be specified that the underlying
        platform may be able to interpret...
        """
        self.requireNotRunning()
        return self.platformCall(address, args, convention)

    def registerNotifier(self, event, notifier):
        """
        Register a notifier who will be called for various
        events.  See NOTIFY_* constants for handler hooks.
        """
        nlist = self.notifiers.get(event,None)
        if nlist:
            nlist.append(notifier)
        else:
            nlist = []
            nlist.append(notifier)
            self.notifiers[event] = nlist

    def deregisterNotifier(self, event, notifier):
        nlist = self.notifiers.get(event, [])
        if notifier in nlist:
            nlist.remove(notifier)

    def getNotifiers(self, event):
        return self.notifiers.get(event, [])

    def requireNotExited(self):
        if self.exited:
            raise Exception("ERROR - Request invalid for trace which exited")

    def requireNotRunning(self):
        """
        Just a quick method to throw an error if the
        tracer is already running...
        """
        self.requireAttached()
        if self.isRunning():
            raise Exception("ERROR - Request invalid for running trace")

    def requireAttached(self):
        """
        A utility method for other methods to use in order
        to require being attached
        """
        if not self.attached:
            raise Exception("ERROR - Must be attached to a process")

    def getFds(self):
        """
        Get a list of (fd,type,bestname) pairs.  This is MOSTLY useful
        for HUMON consumtion...  or giving HUMONs consumption...
        """
        self.requireNotRunning()
        if not self.fds:
            self.fds = self.platformGetFds()
        return self.fds

    def getMemoryMaps(self):
        """
        Return a list of the currently mapped memory for the target
        process.  This is acomplished by calling the platform's
        platformGetMaps() mixin method.  This will also cache the
        results until CONTINUE.  The format is (addr,len,perms,file).
        """
        self.requireNotRunning()
        if not self.mapcache:
            self.mapcache = self.platformGetMaps()
        return self.mapcache

    def isAttached(self):
        """
        Return boolean true/false for weather or not this trace is
        currently attached to a process.
        """
        return self.attached

    def isRunning(self):
        """
        Return true or false if this trace's target process is "running".
        """
        return self.running

    def enableAutoContinue(self, event):
        """
        Put the tracer object in to AutoContinue mode
        for the specified event.  To make all events
        continue running see RunForever mode in setMode().
        """
        if event not in self.auto_continue:
            self.auto_continue.append(event)

    def disableAutoContinue(self, event):
        """
        Disable Auto Continue for the specified
        event.
        """
        if event in self.auto_continue:
            self.auto_continue.remove(event)

    def getAutoContinueList(self):
        """
        Retrieve the list of vtrace notification events
        that will be auto-continued.
        """
        return list(self.auto_continue)

    def parseExpression(self, expression):
        """
        Parse a python expression with many useful helpers mapped
        into the execution namespace.

        Example: trace.parseExpression("ispoi(ecx+ntdll.RtlAllocateHeap)")
        """
        locs = VtraceExpressionLocals(self)
        return long(e_expr.evaluate(expression, locs))

    def sendBreak(self):
        """
        Send an asynchronous break signal to the target process.
        This is only valid if the target is actually running...
        """
        self.requireAttached()
        if not self.isRunning():
            raise Exception("Why sending a break when not running?!?!")
        self.setMode("RunForever", False)
        self.setMode("FastBreak", False)
        self.setMeta("ShouldBreak", True)
        self.platformSendBreak()
        # If we're non-blocking, we gotta wait...
        if self.getMode("NonBlocking", True):
            while self.isRunning():
                time.sleep(0.01)

    def getStackTrace(self):
        """
        Returns a list of (instruction pointer, stack frame) tuples.
        If stack tracing results in an error, the error entry will
        be (-1,-1).  Otherwise most platforms end up with 0,0 as
        the top stack frame
        """
        # FIXME thread id argument!
        return self.archGetStackTrace()

    def getThreads(self):
        """
        Get a dictionary of <threadid>:<tinfo> pairs where
        tinfo is platform dependant, but is tyically either
        the top of the stack for that thread, or the TEB on
        win32
        """
        if not self.threadcache:
            self.threadcache = self.platformGetThreads()
        return self.threadcache

    def selectThread(self, threadid):
        """
        Set the "current thread" context to the given thread id.
        (For example stack traces and register values will depend
        on the current thread context).  By default the thread
        responsible for an "interesting event" is selected.
        """
        if threadid not in self.getThreads():
            raise Exception("ERROR: Invalid threadid chosen: %d" % threadid)
        self.requireNotRunning()
        self.platformSelectThread(threadid)
        self.setMeta("ThreadId", threadid)

    def isThreadSuspended(self, threadid):
        """
        Used to determine if a thread is suspended.
        """
        return self.sus_threads.get(threadid, False)

    def suspendThread(self, threadid):
        """
        Suspend a thread by ID.  This will mean that on continuing
        the trace, the suspended thread will not be scheduled.
        """
        self.requireNotRunning()
        if self.sus_threads.get(threadid):
            raise Exception("The specified thread is already suspended")
        if threadid not in self.getThreads().keys():
            raise Exception("There is no thread %d!" % threadid)
        self.platformSuspendThread(threadid)
        self.sus_threads[threadid] = True

    def resumeThread(self, threadid):
        """
        Resume a suspended thread.
        """
        self.requireNotRunning()
        if not self.sus_threads.get(threadid):
            raise Exception("The specified thread is not suspended")
        self.platformResumeThread(threadid)
        self.sus_threads.pop(threadid)

    def injectThread(self, pc):
        """
        Create a new thread inside the target process.  This thread
        will begin execution on the next process run().
        """
        self.requireNotRunning()
        #FIXME platformInjectThread()
        pass

    def getStruct(self, sname, address):
        """
        Retrieve a vstruct structure populated with memory from
        the specified address.  Returns a standard vstruct object.
        """
        vs = vstruct.getStructure(sname)
        bytes = self.readMemory(address, len(vs))
        vs.vsParse(bytes)
        return vs

    def setVariable(self, name, value):
        """
        Set a named variable in the trace which may be used in
        subsequent VtraceExpressions.

        Example:
        trace.setVariable("whereiam", trace.getProgramCounter())
        """
        self.localvars[name] = value

    def getVariable(self, name):
        """
        Get the value of a previously set variable name.
        (or None on not found)
        """
        return self.localvars.get(name)

    def getVariables(self):
        """
        Get the dictionary of named variables.
        """
        return dict(self.localvars)

    def hex(self, value):
        """
        Much like the python hex routine, except this will automatically
        pad the value's string length out to pointer width.
        """
        w = self.arch.getPointerSize()
        return e_bits.hex(value, width)

class TraceGroup(Notifier, v_util.TraceManager):
    """
    Encapsulate several traces, run them, and continue to 
    handle their event notifications.
    """
    def __init__(self):
        Notifier.__init__(self)
        v_util.TraceManager.__init__(self)
        self.traces = {}
        self.go = True # A little ghetto switch for those who read the source

        # We are a notify all notifier by default
        self.registerNotifier(NOTIFY_ALL, self)

        self.setMode("NonBlocking", True)

    def setMeta(self, name, value):
        """
        A trace group's setMeta function will set "persistant" metadata
        which will be added again to any trace on attach.  Additionally,
        setting metadata on a tracegroup will cause all current traces
        to get the update as well....
        """
        v_util.TraceManager.setMeta(self,name,value)
        for trace in self.traces.values():
            trace.setMeta(name, value)

    def setMode(self, name, value):
        v_util.TraceManager.setMode(self, name, value)
        for trace in self.getTraces():
            trace.setMode(name, value)

    def detachAll(self):
        """
        Detach from ALL the currently targetd processes
        """
        for trace in self.traces.values():
            try:
                if trace.isRunning():
                    trace.sendBreak()
                trace.detach()
            except:
                pass

    def run(self):
        """
        Our run method  is a little different than a traditional
        trace. It will *never* block.
        """
        if len(self.traces.keys()) == 0:
            raise Exception("ERROR - can't run() with no traces!")

        for trace in self.traces.values():

            if trace.exited:
                self.traces.pop(trace.pid)
                trace.detach()
                continue

            if not trace.isRunning():
                trace.run()

    def execTrace(self, cmdline):
        trace = getTrace()
        self.initTrace(trace)
        trace.execute(cmdline)
        self.traces[trace.getPid()] = trace
        return trace

    def addTrace(self, proc):
        """
        Add a new tracer to this group the "proc" argument
        may be either an long() for a pid (which we will attach
        to) or an already attached (and broken) tracer object.
        """

        if (type(proc) == types.IntType or
            type(proc) == types.LongType):
            trace = getTrace()
            self.initTrace(trace)
            self.traces[proc] = trace
            try:
                trace.attach(proc)
            except:
                self.delTrace(proc)
                raise

        else: # Hopefully a tracer object... if not.. you're dumb.
            trace = proc
            self.initTrace(trace)
            self.traces[trace.getPid()] = trace

        return trace

    def initTrace(self, trace):
        """
         - INTERNAL -
        Setup a tracer object to be ready for being in this
        trace group (setup modes and notifiers).  Only addTrace()
        and execTrace() probably need to be aware of this.
        """
        self.manageTrace(trace)

    def delTrace(self, pid):
        """
        Remove a trace from the current TraceGroup
        """
        trace = self.traces.pop(pid, None)
        self.unManageTrace(trace)

    def getTraces(self):
        """
        Return a list of the current traces
        """
        return self.traces.values()

    def getTraceByPid(self, pid):
        """
        Return the the trace for process PID if we're
        already attached.  Return None if not.
        """
        return self.traces.get(pid, None)

    def notify(self, event, trace):
        # Remove this trace, and free it
        # on the server if present
        if event == NOTIFY_EXIT:
            self.delTrace(trace.getPid())

class VtraceExpressionLocals(e_expr.MemoryExpressionLocals):
    """
    A class which serves as the namespace dictionary during the
    evaluation of an expression on a tracer.
    """
    def __init__(self, trace):
        e_expr.MemoryExpressionLocals.__init__(self, trace, symobj=trace)
        self.trace = trace
        self.update({
                'trace':trace,
                'vtrace':vtrace
        })
        self.update({
            "struct":self.struct,
            "frame":self.frame,
            "teb":self.teb,
            "bp":self.bp,
            "meta":self.meta,
        })

    def __getitem__(self, name):
        # Check registers
        if self.trace.isAttached():
            regs = self.trace.getRegisters()
            r = regs.get(name, None)
            if r != None:
                return r
        # Check local variables
        locs = self.trace.getVariables()
        r = locs.get(name, None)
        if r != None:
            return r
        return e_expr.MemoryExpressionLocals.__getitem__(self, name)

    def struct(self, sname, saddr):
        """
        Return a VStruct structure of type "sname" which has been
        populated with the values from saddr.

        Usage: struct("PEB", <peb address>)
        """
        return self.trace.getStruct(sname, saddr)

    def frame(self, index):
        """
        Return the address of the saved base pointer for
        the specified frame.

        Usage: frame(<index>)
        """
        stack = self.trace.getStackTrace()
        return stack[index][1]

    def teb(self, threadnum=None):
        """
        The expression teb(threadid) will return whatever the
        platform stores as the int for threadid.  In the case
        of windows, this is the TEB, others may be the thread
        stack base or whatever.  If threadid is left out, it
        uses the threadid of the current thread context.
        """
        if threadnum == None:
            # Get the thread ID of the current Thread Context
            threadnum = self.trace.getMeta("ThreadId")

        teb = self.trace.getThreads().get(threadnum, None)
        if teb == None:
            raise Exception("ERROR - Unknown Thread Id %d" % threadnum)

        return teb

    def bp(self, bpid):
        """
        The expression bp(0) returns the resolved address of the given
        breakpoint
        """
        bp = self.trace.getBreakpoint(bpid)
        if bp == None:
            raise Exception("Unknown Breakpoint ID: %d" % bpid)
        return bp.resolveAddress(self.trace)

    def meta(self, name):
        """
        An expression friendly (terse) way to get trace metadata
        (equiv to trace.getMeta(name))

        Example: meta("foo")
        """
        return self.trace.getMeta(name)

def getTrace():
    """
    Return a tracer object appropriate for this platform.
    This is the function you will use to get a tracer object
    with the appropriate ancestry for your host.
    ex. mytrace = vtrace.getTrace()
    """

    if remote: #We have a remote server!
        return getRemoteTrace()

    os_name = platform.system() # Like "Linux", "Darwin","Windows"
    arch = envi.getCurrentArch()

    if os_name == "Linux":
        import vtrace.platforms.linux as v_linux
        if arch == "amd64":
            return v_linux.LinuxAmd64Trace()

        elif arch == "i386":
            return v_linux.Linuxi386Trace()

        else:
            raise Exception("Sorry, no linux support for %s" % arch)

    elif os_name == "FreeBSD":

        import vtrace.platforms.freebsd as v_freebsd

        if arch == "i386":
            return v_freebsd.FreeBSDi386Trace()

        elif arch == "amd64":
            return v_freebsd.FreeBSDAmd64Trace()

        else:
            raise Exception("Sorry, no FreeBSD support for %s" % arch)

        #import vtrace.platforms.posix as v_posix
        #import vtrace.platforms.freebsd as v_freebsd
        #ilist.append(v_posix.PosixMixin)
        #ilist.append(v_posix.ElfMixin)
        #if arch == "i386":
            #import vtrace.archs.intel as v_intel
            #ilist.append(v_intel.i386Mixin)
            #ilist.append(v_freebsd.FreeBSDMixin)
            #ilist.append(v_freebsd.FreeBSDIntelRegisters)
        #else:
            #raise Exception("Sorry, no FreeBSD support for %s" % arch)

    elif os_name == "sunos5":
        raise Exception("Solaris needs porting!")
        #import vtrace.platforms.posix as v_posix
        #import vtrace.platforms.solaris as v_solaris
        #ilist.append(v_posix.PosixMixin)
        #if arch == "i386":
            #import vtrace.archs.intel as v_intel
            #ilist.append(v_intel.i386Mixin)
            #ilist.append(v_solaris.SolarisMixin)
            #ilist.append(v_solaris.Solarisi386Mixin)

    elif os_name == "Darwin":

        #if 9 not in os.getgroups():
            #print 'You MUST be in the procmod group....'
            #print 'Use: sudo dscl . append /Groups/procmod GroupMembership invisigoth'
            #print '(put your username in there unless you want to put me in too... ;)'
            #raise Exception('procmod group membership required')
        if os.getuid() != 0:
            print 'For NOW you *must* be root.  There are some crazy MACH perms...'
            raise Exception('You must be root for now....')

        print 'Also... the darwin port is not even REMOTELY working yet.  Solid progress though...'

        #'sudo dscl . append /Groups/procmod GroupMembership invisigoth'
        #'sudo dscl . read /Groups/procmod GroupMembership'
        import vtrace.platforms.darwin as v_darwin
        if arch == 'i386':
            return v_darwin.Darwini386Trace()
        else:
            raise Exception('Darwin not supported on %s (only i386...)' % arch)

    elif os_name == "Windows":

        import vtrace.platforms.win32 as v_win32

        if arch == "i386":
            return v_win32.Windowsi386Trace()

        elif arch == "amd64":
            return v_win32.WindowsAmd64Trace()

        else:
            raise Exception("Windows with arch %s is not supported!" % arch)

    else:

        raise Exception("ERROR - OS %s not supported yet" % os_name)

def interact(pid=0,server=None,trace=None):

    """
    Just a cute and dirty way to get a tracer attached to a pid
    and get a python interpreter instance out of it.
    """

    global remote
    remote = server

    if trace == None:
        trace = getTrace()
        if pid:
            trace.attach(pid)

    mylocals = {}
    mylocals["trace"] = trace

    code.interact(local=mylocals)

