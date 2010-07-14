import os
import sys
import pprint
import signal
import string
import traceback

from ConfigParser import *

from cmd import *
from struct import *
from getopt import getopt
from UserDict import *
from threading import *

import vtrace
import vtrace.util as v_util
import vtrace.notifiers as v_notif

import vdb
import vdb.extensions as v_ext

import envi
import envi.cli as e_cli
import envi.bits as e_bits
import envi.memory as e_mem
import envi.config as e_config
import envi.resolver as e_resolv
import envi.memcanvas as e_canvas

import vstruct
import vstruct.primitives as vs_prims

vdb.basepath = vdb.__path__[0] + "/"

class VdbLookup(UserDict):
    def __init__(self, initdict={}):
        UserDict.__init__(self)
        for key,val in initdict.items():
            self.__setitem__(self, key, value)

    def __setitem__(self, key, item):
        UserDict.__setitem__(self, key, item)
        UserDict.__setitem__(self, item, key)

class ScriptThread(Thread):
    def __init__(self, cobj, locals):
        Thread.__init__(self)
        self.setDaemon(True)
        self.cobj = cobj
        self.locals = locals

    def run(self):
        try:
            exec(self.cobj, self.locals)
        except Exception, e:
            traceback.print_exc()
            print "Script Error: ",e

class VdbTrace:
    """
    Used to hand thing that need a persistant reference to a trace
    when using vdb to manage tracers.
    """
    def __init__(self, db):
        self.db = db

    def attach(self, pid):
        # Create a new tracer for the debugger and attach.
        trace = self.db.newTrace()
        trace.attach(pid)

    # Take over all notifier registration
    def registerNotifier(self, event, notif):
        self.db.registerNotifier(event, notif)

    def deregisterNotifier(self, event, notif):
        self.db.deregisterNotifier(event, notif)

    #FIXME should we add modes to this?

    def selectThread(self, threadid):
        #FIXME perhaps a thread selected LOCAL event?
        trace = self.db.getTrace()
        trace.selectThread(threadid)
        self.db.fireLocalNotifiers(vtrace.NOTIFY_BREAK, trace)

    def __getattr__(self, name):
        return getattr(self.db.getTrace(), name)

defconfig = """
[Vdb]

[RegisterView]
i386=eax,ebx,ecx,edx,esi,edi,eip,esp,ebp,eflags,ds,es,cs,fs,gs,ss
x64=rax,rbx,rcx,rdx,rsi,rdi,rip,rsp,rbp,r8,r9,r10,r11,r12,r13,r14,r15

[Aliases]
<f1>=stepi
<f2>=go -I 1
<f5>=go
"""
        
class Vdb(e_cli.EnviMutableCli, v_notif.Notifier, v_util.TraceManager):

    """
    A VDB object is a debugger object which may be used to embed full
    debugger like functionality into a python application.  The
    Vdb object contains a CLI impelementation which extends envi.cli>
    """

    def __init__(self, trace=None):
        v_notif.Notifier.__init__(self)
        v_util.TraceManager.__init__(self)

        if trace == None:
            trace = vtrace.getTrace()

        arch = trace.getMeta("Architecture")
        self.arch = envi.getArchModule(arch)
        self.difftracks = {}

        # We hangn on to an opcode renderer instance
        self.opcoderend = None

        # If a VdbGui instance is present it will set this.
        self.gui = None

        self.setMode("NonBlocking", True)

        self.manageTrace(trace)
        self.registerNotifier(vtrace.NOTIFY_ALL, self)

        # FIXME if config verbose
        #self.registerNotifier(vtrace.NOTIFY_ALL, vtrace.VerboseNotifier())

        self.vdbhome = e_config.gethomedir(".vdb")

        self.loadConfig()

        self.setupSignalLookups()

        # Ok... from here down we're handing everybody the crazy
        # on-demand-resolved trace object.
        trace = vdb.VdbTrace(self)
        e_cli.EnviMutableCli.__init__(self, trace, self.config, symobj=trace)

        self.prompt = "vdb > "
        self.banner = "Welcome To VDB!\n"

        self.loadDefaultRenderers(trace)
        self.loadExtensions(trace)

    def loadConfig(self):
        cfgfile = None
        if self.vdbhome != None:
            if not os.path.exists(self.vdbhome):
                os.mkdir(self.vdbhome)
            cfgfile = os.path.join(self.vdbhome, "vdb.conf")

        self.config = e_config.EnviConfig(filename=cfgfile, defaults=defconfig)

    def loadDefaultRenderers(self, trace):
        import envi.memcanvas.renderers as e_render
        import vdb.renderers as v_rend
        # FIXME check endianness
        self.canvas.addRenderer("bytes", e_render.ByteRend())
        self.canvas.addRenderer("u_int_16", e_render.ShortRend())
        self.canvas.addRenderer("u_int_32", e_render.LongRend())
        self.canvas.addRenderer("u_int_64", e_render.QuadRend())
        self.opcoderend = v_rend.OpcodeRenderer(self.trace)
        self.canvas.addRenderer("disasm", self.opcoderend)
        drend = v_rend.DerefRenderer(self.trace)
        self.canvas.addRenderer("Deref View", drend)

    def verror(self, msg, addnl=True):
        if addnl:
            msg += "\n"
        sys.stderr.write(msg)

    def loadExtensions(self, trace):
        """
        Load up any extensions which are relevant for the current tracer's
        platform/arch/etc...
        """
        v_ext.loadExtensions(self, trace)

    def getTrace(self):
        return self.trace

    def newTrace(self):
        """
        Generate a new trace for this vdb instance.  This fixes many of
        the new attach/exec data munging issues because tracer re-use is
        *very* sketchy...
        """
        oldtrace = self.getTrace()
        if oldtrace.isRunning():
            oldtrace.sendBreak()
        if oldtrace.isAttached():
            oldtrace.detach()

        self.trace = vtrace.getTrace()
        self.manageTrace(self.trace)
        return self.trace

    def setupSignalLookups(self):
        self.siglookup = VdbLookup()

        self.siglookup[0] = "None"

        for name in dir(signal):
            if name[:3] == "SIG" and "_" not in name:
                self.siglookup[name] = eval("signal.%s"%name)
        
    def getSignal(self, sig):
        """
        If given an int, return the name, for a name, return the int ;)
        """
        return self.siglookup.get(sig,None)

    def parseExpression(self, exprstr):
        return self.trace.parseExpression(exprstr)

    def getExpressionLocals(self):
        r = vtrace.VtraceExpressionLocals(self.trace)
        r["db"] = self
        return r

    def reprPointer(self, address):
        """
        Return a string representing the best known name for
        the given address
        """
        if not address:
            return "NULL"

        # Do we have a symbol?
        sym = self.trace.getSymByAddr(address, exact=False)
        if sym != None:
            return "%s + %d" % (repr(sym),address-long(sym))

        # Check if it's a thread's stack
        for tid,tinfo in self.trace.getThreads().items():
            ctx = self.trace.getRegisterContext(tid)
            sp = ctx.getStackCounter()
            stack,size,perms,fname = self.trace.getMemoryMap(sp)
            if address >= stack and address < (stack+size):
                off = address - sp
                op = "+"
                if off < 0:
                    op = "-"
                off = abs(off)
                return "tid:%d sp%s%s (stack)" % (tid,op,off)

        map = self.trace.getMemoryMap(address)
        if map:
            return map[3]

        return "Who knows?!?!!?  The Shadow knows."

    def script(self, filename, args=[]):
        """
        Execute a vdb script.
        """
        text = file(filename).read()
        self.scriptstring(text, filename, args)

    def scriptstring(self, script, filename, args=[]):
        """
        Do the actual compile and execute for the script data
        contained in script which was read from filename.
        """
        local = self.getExpressionLocals()
        cobj = compile(script, filename, "exec")
        sthr = ScriptThread(cobj, local)
        sthr.start()

    def notify(self, event, trace):

        pid = trace.getPid()

        if event == vtrace.NOTIFY_ATTACH:
            self.vprint("Attached to : %d" % pid)
            self.difftracks = {}

        elif event == vtrace.NOTIFY_CONTINUE:
            pass

        elif event == vtrace.NOTIFY_DETACH:
            self.difftracks = {}
            self.vprint("Detached from %d" % pid)

        elif event == vtrace.NOTIFY_SIGNAL:
            win32 = trace.getMeta("Win32Event", None)
            if win32:
                code = win32.get("ExceptionCode", 0)
                addr = win32.get("ExceptionAddress")
                chance = 2
                if win32.get("FirstChance", False):
                    chance = 1
                self.vprint("Win32 Exception: 0x%.8x at 0x%.8x (%d chance)" % (code, addr, chance))
            else:
                self.vprint("Process Recieved Signal %d" % trace.getMeta("PendingSignal"))

        elif event == vtrace.NOTIFY_BREAK:
            tid = trace.getMeta("ThreadId")
            bp = trace.getCurrentBreakpoint()
            if bp:
                self.vprint("Thread: %.8x Hit Break: %s" % (tid, repr(bp)))
            else:
                self.vprint("Thread: %.8x NOTIFY_BREAK" % tid)

        elif event == vtrace.NOTIFY_EXIT:
            self.vprint("PID %d exited: %d" % (pid,trace.getMeta("ExitCode")))

        elif event == vtrace.NOTIFY_LOAD_LIBRARY:
            self.vprint("Loading Binary: %s" % trace.getMeta("LatestLibrary",None))

        elif event == vtrace.NOTIFY_UNLOAD_LIBRARY:
            self.vprint("Unloading Binary: %s" % trace.getMeta("LatestLibrary",None))

        elif event == vtrace.NOTIFY_CREATE_THREAD:
            self.vprint("New Thread: %d" % trace.getMeta("ThreadId"))

        elif event == vtrace.NOTIFY_EXIT_THREAD:
            ecode = trace.getMeta("ExitCode", 0)
            self.vprint("Exit Thread: %d (ecode: 0x%.8x (%d))" % (trace.getMeta("ThreadId"),ecode,ecode))

        elif event == vtrace.NOTIFY_DEBUG_PRINT:
            s = "<unknown>"
            win32 = trace.getMeta("Win32Event", None)
            if win32:
                s = win32.get("DebugString", "<unknown>")
            self.vprint("DEBUG PRINT: %s" % s)


    ###################################################################
    #
    # All CLI extension commands start here
    #

    def do_vstruct(self, line):
        """
        List the available structure modules and optionally
        structure definitions from a particular module in the
        current vstruct.

        Usage: vstruct [modname]
        """
        if len(line) == 0:
            self.vprint("\nVStruct Modules:")
            plist = vstruct.getModuleNames()
        else:
            self.vprint("\nKnown Structures:")
            plist = vstruct.getStructNames(line)

        for n in plist:
            self.vprint(n)
        self.vprint("\n")

    def do_dis(self, line):
        """
        Print out the opcodes for a given address expression

        Usage: dis <address expression> [<size expression>]
        """

        argv = e_cli.splitargs(line)

        size = 20
        argc = len(argv)
        if argc == 0:
            addr = self.trace.getProgramCounter()
        elif argv[0].find("0x") > -1:
            addr = int(argv[0],16)
        else:
            addr = self.parseExpression(argv[0])

        if argc > 1:
            size = self.parseExpression(argv[1])

        self.vprint("Dissassembly:")
        self.canvas.render(addr, size, rend=self.opcoderend)

    def do_eignore(self, line):
        """
        Print out the opcodes for a given address expression

        Usage: dis <address expression> [<size expression>]
        """

        argv = e_cli.splitargs(line)
        print argv


    def do_var(self, line):
        """
        Set a variable in the expression parsing context.  This allows
        for scratchspace names (python compatable names) to be used in
        expressions.

        Usage: var <name> <addr_expression>

        NOTE: The address expression *must* resolve at the time you set it.
        """
        t = self.trace

        if len(line):
            argv = e_cli.splitargs(line)
            if len(argv) == 1:
                return self.do_help("var")
            name = argv[0]
            expr = " ".join(argv[1:])
            addr = t.parseExpression(expr)
            t.setVariable(name, addr)

        vars = t.getVariables()
        self.vprint("Current Variables:")
        if not vars:
            self.vprint("None.")
        else:
            vnames = vars.keys()
            vnames.sort()
            for n in vnames:
                val = vars.get(n)
                if type(val) in (int, long):
                    self.vprint("%20s = 0x%.8x" % (n,val))
                else:
                    rstr = repr(val)
                    if len(rstr) > 30:
                        rstr = rstr[:30] + '...'
                    self.vprint("%20s = %s" % (n,rstr))

    def do_alloc(self, args):
        #"""
        #Allocate a chunk of memory in the target process.  You may
        #optionally specify permissions and a suggested base address.

        #Usage: alloc [-p rwx] [-s <base>] <size>
        #"""
        """
        Allocate a chunk of memory in the target process.  It will be
        allocated with rwx permissions.

        Usage: alloc <size expr>
        """
        if len(args) == 0:
            return self.do_help("alloc")
        t = self.trace
        #argv = e_cli.splitargs(args)
        try:
            size = t.parseExpression(args)
            base = t.allocateMemory(size)
            self.vprint("Allocated %d bytes at: 0x%.8x" % (size, base))
        except Exception, e:
            traceback.print_exc()
            self.vprint("Allocation Error: %s" % e)

    def do_struct(self, args):
        """
        Break out a strcuture from memory.  You may use the command
        "vstruct" to show the known structures in vstruct.

        Usage: struct <StructName> <vtrace expression>
        """
        try:
            clsname, vexpr = e_cli.splitargs(args)
        except:
            return self.do_help("struct")

        t = self.trace

        addr = t.parseExpression(vexpr)
        s = t.getStruct(clsname, addr)
        self.vprint(s.tree(va=addr))

    def do_signal(self, args):
        """
        Show or set the current pending signal (this is ONLY relavent on POSIX signaling
        systems).

        Usage: signal [newsigno]
        """
        t = self.trace
        t.requireAttached()
        cursig = t.getMeta("PendingSignal", 0)
        self.vprint("Current signal: %d" % cursig)
        if args:
            newsig = int(args)
            t.setMeta("PendingSignal", newsig)
            self.vprint("New signal: %d" % newsig)

    def do_snapshot(self, line):
        """
        Take a process snapshot of the current (stopped) trace and
        save it to the specified file.

        Usage: snapshot <filename>
        """
        if len(line) == 0:
            return self.do_help("snapshot")
        alist = e_cli.splitargs(line)
        if len(alist) != 1:
            return self.do_help("snapshot")

        t = self.trace
        t.requireAttached()
        self.vprint("Taking Snapshot...")
        snap = t.takeSnapshot()
        self.vprint("Saving To File")
        snap.saveToFile(alist[0])
        self.vprint("Done")

    def do_ignore(self, args):
        """
        Add the specified signal id (exception id for windows) to the ignored
        signals list for the current trace.  This will make the smallest possible
        performance impact for that particular signal but will also not alert
        you that it has occured.

        Usage: ignore [[-d] <sigcode>]
        """
        alist = e_cli.splitargs(args)
        if len(alist) == 1:
            sigid = int(args, 0)
            self.vprint("ADDING 0x%.8x to the ignores list" % sigid)
            self.trace.addIgnoreSignal(sigid)
        elif len(alist) == 2 and alist[0] == "-d":
            sigid = int(alist[1], 0)
            self.trace.delIgnoreSignal(sigid)
        else:
            ilist = self.trace.getMeta("IgnoredSignals")
            self.vprint("Currently Ignored Signals/Exceptions:")
            for x in ilist:
                self.vprint("0x%.8x" % x)

    def do_exec(self, string):
        """
        Execute a program with the given command line and
        attach to it.
        Usage: exec </some/where and some args>
        """
        t = self.newTrace()
        t.execute(string)

    def do_threads(self, line):
        """
        List the current threads in the target process or select
        the current thread context for the target tracer.
        Usage: threads [thread id]
        """
        self.trace.requireNotRunning()
        if self.trace.isRunning():
            self.vprint("Can't list threads while running!")
            return

        if len(line) > 0:
            thrid = int(line, 0)
            self.trace.selectThread(thrid)
            if self.gui != None: self.gui.setTraceWindowsActive(True)

        self.vprint("Current Threads:")
        self.vprint("[thrid] [thrinfo]  [pc]")

        curtid = self.trace.getMeta("ThreadId")
        for tid,tinfo in self.trace.getThreads().items():
            a = " "
            if tid == curtid:
                a = "*"

            sus = ""
            if self.trace.isThreadSuspended(tid):
                sus = "(suspended)"
            ctx = self.trace.getRegisterContext(tid)
            pc = ctx.getProgramCounter()
            self.vprint("%s%6d 0x%.8x 0x%.8x %s" % (a, tid, tinfo, pc, sus))
    
    def do_btall(self, line):
        """
        List the current threads in the target process or select
        the current thread context for the target tracer.
        Usage: threads [thread id]
        """
        self.trace.requireNotRunning()
        if self.trace.isRunning():
            self.vprint("Can't list all bts while running!")
            return

        curtid = self.trace.getMeta("ThreadId")
        for tid,tinfo in self.trace.getThreads().items():
			sus = ""
			a = ''
			if tid == curtid:
				a = "=="
			self.trace.selectThread(tid)
			if self.trace.isThreadSuspended(tid):
				sus = "(suspended)"
			self.vprint("%s Backtrace for TID: %d %s %s"%(a, tid, sus, a))
			self.vprint("      [   PC   ] [ Frame  ] [ Location ]")
			idx = 0
			for pc,frame in self.trace.getStackTrace():
				self.vprint("[%3d] 0x%.8x 0x%.8x %s" % (idx,pc,frame,self.reprPointer(pc)))
				idx += 1


    def do_suspend(self, line):
        """
        Suspend a thread.

        Usage: suspend <-A | <tid>[ <tid>...]>
        """
        argv = e_cli.splitargs(line)
        try:
            opts,args = getopt(argv, "A")
        except Exception, e:
            return self.do_help("suspend")

        for opt,optarg in opts:
            if opt == "-A":
                # hehe...
                args = [str(tid) for tid in self.trace.getThreads().keys()]

        if not len(args):
            return self.do_help("suspend")

        for arg in args:
            tid = int(arg)
            self.trace.suspendThread(tid)
            self.vprint("Suspended Thread: %d" % tid)

    def do_resume(self, line):
        """
        Resume a thread.

        Usage: resume <-A | <tid>[ <tid>...]>
        """
        argv = e_cli.splitargs(line)
        try:
            opts,args = getopt(argv, "A")
        except Exception, e:
            return self.do_help("suspend")

        for opt,optarg in opts:
            if opt == "-A":
                # hehe...
                args = [str(tid) for tid in self.trace.getThreads().keys()]

        if not len(args):
            return self.do_help("resume")

        for arg in args:
            tid = int(arg)
            self.trace.resumeThread(tid)
            self.vprint("Resumed Thread: %d" % tid)

    #def do_inject(self, line):

    def do_mode(self, args):
        """
        Set modes in the tracers...
        mode Foo=True/False
        """
        if args:
            mode,val = args.split("=")
            newmode = eval(val)
            self.setMode(mode, newmode)
        else:
            for key,val in self.trace.modes.items():
                self.vprint("%s -> %d" % (key,val))

    def do_reg(self, args):
        """
        Show the current register values.  Additionally, you may specify
        name=<expression> to set a register

        Usage: reg [regname=vtrace_expression]
        """
        if len(args):
            if args.find("=") == -1:
                return self.do_help("reg")
            regname,expr = args.split("=", 1)
            val = self.trace.parseExpression(expr)
            self.trace.setRegisterByName(regname, val)
            self.vprint("%s = 0x%.8x" % (regname, val))
            return

        regs = self.trace.getRegisters()
        rnames = regs.keys()
        rnames.sort()
        final = []
        for r in rnames:
            # Capitol names are used for reg vals that we don't want to see
            # (by default)
            if r.lower() != r:
                continue
            val = regs.get(r)
            vstr = e_bits.hex(val, 4)
            final.append(("%12s:0x%.8x (%d)" % (r,val,val)))
        self.columnize(final)

    def do_stepi(self, args):
        """
        Single step the target tracer.
        Usage: stepi [count expression]
        """
        t = self.trace
        if len(args):
            count = t.parseExpression(args)
        else:
            count = 1

        oldmode = self.getMode('FastStep')
        self.setMode('FastStep', True)
        try:
            for i in xrange(count):
                pc = t.getProgramCounter()
                self.canvas.render(pc, 1, rend=self.opcoderend)
                t.stepi()
                if t.getMeta('PendingException'):
                    break
                if t.getMeta('PendingSignal'):
                    break
        finally:
            self.setMode('FastStep', oldmode)
            # We ate all the events, tell the GUI to update
            # if it's around...
            if self.gui != None: self.gui.setTraceWindowsActive(True)

    def do_go(self, line):
        """
        Continue the target tracer.
        -I go icount linear instructions forward (step over style)
        -U go *out* of fcount frames (step out style)
        <until addr> go until explicit address

        Usage: go [-U <fcount> | -I <icount> | <until addr expression>]
        """
        until = None
        icount = None
        fcount = None

        argv = e_cli.splitargs(line)
        try:
            opts,args = getopt(argv, "U:I:")
        except:
            return self.do_help("go")

        for opt,optarg in opts:
            if opt == "-U":
                if len(optarg) == 0: return self.do_help("go")
                fcount = self.trace.parseExpression(optarg)
            elif opt == "-I":
                if len(optarg) == 0: return self.do_help("go")
                icount = self.trace.parseExpression(optarg)

        if icount != None:
            addr = self.trace.getProgramCounter()
            for i in xrange(icount):
                addr += len(self.arch.makeOpcode(self.trace.readMemory(addr, 16)))
            until = addr

        elif fcount != None:
            until = self.trace.getStackTrace()[fcount][0]

        elif len(args):
            until = self.trace.parseExpression(" ".join(args))

        if not until:
            self.vprint("Running Tracer (use 'break' to stop it)")

        self.trace.run(until=until)

    def do_server(self, port):
        """
        Start a vtrace server on the local box
        optionally specify the port

        Usage: server [port]
        """
        if port:
            vtrace.port = int(port)

        vtrace.startVtraceServer()

    def do_syms(self, line):
        """
        List symbols and by file.

        Usage: syms [-s <pattern>] [filename]

        With no arguments, syms will self.vprint(the possible
        libraries with symbol resolvers.  Specify a library
        to see all the symbols for it.
        """

        argv = e_cli.splitargs(line)
        try:
            opts,args = getopt(argv, "s:")
        except:
            return self.do_help("syms")

        pattern = None
        for opt,optarg in opts:
            if opt == "-s":
                pattern = optarg.lower()

        libs = self.trace.getNormalizedLibNames()
        if len(args) == 0:
            self.vprint("Current Library Symbol Resolvers:")
            libs.sort()
            for libname in libs:
                self.vprint("  %s" % libname)

        else:
            libname = args[0]
            if libname not in libs:
                self.vprint("Unknown libname: %s" % libname)
                return
            if pattern:
                self.vprint("Matching Symbols From %s:" % libname)
            else:
                self.vprint("Symbols From %s:" % libname)

            for sym in self.trace.getSymsForFile(libname):
                r = repr(sym)
                if pattern != None:
                    if r.lower().find(pattern) == -1:
                        continue
                self.vprint("0x%.8x %s" % (sym.value, r))

    def do_call(self, string):
        """
        Allows a C-like syntax for calling functions inside
        the target process (from his context).
        Example: call printf("yermom %d", 10)
        """
        self.trace.requireAttached()
        ind = string.index("(")
        if ind == -1:
            raise Exception('ERROR - call wants c-style syntax: ie call printf("yermom")')
        funcaddr = self.trace.parseExpression(string[:ind])
        def create_args_tuple(string, ind):
            args = None
            magic = "vtrace__1m4g1n4r3_c0d35"
            replace = lambda arg: arg.replace(magic,"\x00") if isinstance(arg,str) else arg
            if string.find("\x00") > -1:
                string = string.replace("\x00", magic)
                args = eval(string[ind:])
            if not isinstance(args, tuple):
                args = tuple([args,])
            #now we undo the magic and return
            return tuple(map(replace, args))
		
        try:
			# issue this does not automatically create an array if ther is one argument
			# also will fail if the string contains in null
			# 
			# rather than this: args = eval(string[ind:])
			args = create_args_tuple(string, ind)
				
        except:
            raise Exception('ERROR - call wants c-style syntax: ie call printf("yermom")')

        self.vprint("calling %s -> 0x%.8x" % (string[:ind], funcaddr))
        self.trace.call(funcaddr, args)

    def do_bestname(self, args):
        """
        Return the "best name" string for an address.

        Usage: bestname <vtrace expression>
        """
        if len(args) == 0:
            return self.do_help("bestname")
        addr = self.trace.parseExpression(args)
        self.vprint(self.reprPointer(addr))

    def do_EOF(self, string):
        self.vprint("No.. this is NOT a python interpreter... use quit ;)")

    def do_quit(self,args):
        """
        Quit VDB
        """
        if self.trace.isRunning():
            self.trace.setMode("RunForever", False)
            self.trace.sendBreak()

        if self.trace.isAttached():
            self.vprint("Detaching...")
            self.trace.detach()

        self.vprint("Exiting...")
        e_cli.EnviMutableCli.do_quit(self, args)

    def do_detach(self, args):
        """
        Detach from the current tracer
        """
        self.trace.requireAttached()
        if self.trace.isRunning():
            self.trace.setMode("RunForever", False)
            self.trace.sendBreak()
        self.trace.detach()

    def do_attach(self, args):
        """
        Attach to a process by PID
        Usage: attach <pid>
        """
        pid = int(args)
        self.vprint("Attaching to %d" % pid)
        self.newTrace().attach(pid)

    def do_autocont(self, line):
        """
        Manipulate the auto-continue behavior for the trace.  This
        will cause particular event types to automagically continue
        execution.

        Usage: autocont [event name]
        """
        argv = e_cli.splitargs(line)
        acnames = ["attach",
                   "signal",
                   "break",
                   "loadlib",
                   "unloadlib",
                   "createthread",
                   "exitthread",
                   "dbgprint"]

        acvals = [ vtrace.NOTIFY_ATTACH,
                   vtrace.NOTIFY_SIGNAL, 
                   vtrace.NOTIFY_BREAK,
                   vtrace.NOTIFY_LOAD_LIBRARY,
                   vtrace.NOTIFY_UNLOAD_LIBRARY,
                   vtrace.NOTIFY_CREATE_THREAD,
                   vtrace.NOTIFY_EXIT_THREAD,
                   vtrace.NOTIFY_DEBUG_PRINT]

        c = self.trace.getAutoContinueList()

        if len(line):
            try:
                index = acnames.index(line)
            except ValueError, e:
                self.vprint("Unknown event name: %s" % line)
                return
            sig = acvals[index]
            if sig in c:
                self.trace.disableAutoContinue(sig)
                c.remove(sig)
            else:
                self.trace.enableAutoContinue(sig)
                c.append(sig)

        self.vprint("Auto Continue Status:")
        for i in range(len(acnames)):
            name = acnames[i]
            sig = acvals[i]
            acont = False
            if sig in c:
                acont = True
            self.vprint("%s %s" % (name.rjust(14),repr(acont)))

    def emptyline(self):
        self.do_help("")

    def do_bt(self, line):
        """
        Show a stack backtrace for the currently selected thread.

        Usage: bt
        """
        self.vprint("      [   PC   ] [ Frame  ] [ Location ]")
        idx = 0
        for pc,frame in self.trace.getStackTrace():
            self.vprint("[%3d] 0x%.8x 0x%.8x %s" % (idx,pc,frame,self.reprPointer(pc)))
            idx += 1

    def do_lm(self, args):
        """
        Show the loaded libraries and their base addresses.

        Usage: lm [libname]
        """
        bases = self.trace.getMeta("LibraryBases")
        paths = self.trace.getMeta("LibraryPaths")
        if len(args):
            base = bases.get(args)
            path = paths.get(base, "unknown")
            if base == None:
                self.vprint("Library %s is not found!" % args)
            else:
                self.vprint("0x%.8x - %s %s" % (base, args, path))
        else:
            self.vprint("Loaded Libraries:")
            names = self.trace.getNormalizedLibNames()
            names.sort()
            names = self.columnstr(names)
            for libname in names:
                base = bases.get(libname.strip(), -1)
                path = paths.get(base, "unknown")
                self.vprint("0x%.8x - %.30s %s" % (base, libname, path))

    def columnstr(self, slist):
        msize = 0
        for s in slist:
            if len(s) > msize:
                msize = len(s)
        return [x.ljust(msize) for x in slist]

    def do_guid(self, line):
        """
        Parse and display a Global Unique Identifier (GUID) from memory
        (eventually, use GUID db to lookup the name/meaning of the GUID).

        Usage: guid <addr_exp>
        """
        self.trace.requireNotRunning()
        if not line:
            return self.do_help("guid")

        addr = self.parseExpression(line)
        guid = vs_prims.GUID()
        bytes = self.trace.readMemory(addr, len(guid))
        guid.vsSetValue(bytes)
        self.vprint("GUID 0x%.8x %s" % (addr, repr(guid)))

    def do_bpfile(self, line):
        """
        Set the python code for a breakpoint from the contents
        of a file.

        Usage: bpfile <bpid> <filename>
        """
        argv = e_cli.splitargs(line)
        if len(argv) != 2:
            return self.do_help("bpfile")

        bpid = int(argv[0])
        pycode = file(argv[1], "rU").read()

        self.trace.setBreakpointCode(bpid, pycode)

    def do_bpedit(self, line):
        """
        Manipulcate the python code that will be run for a given
        breakpoint by ID.  (Also the way to view the code).

        Usage: bpedit <id> ["optionally new code"]

        NOTE: Your code must be surrounded by "s and may not
        contain any "s
        """
        argv = e_cli.splitargs(line)
        if len(argv) == 0:
            return self.do_help("bpedit")
        bpid = int(argv[0])

        if len(argv) == 2:
            self.trace.setBreakpointCode(bpid, argv[1])

        pystr = self.trace.getBreakpointCode(bpid)
        self.vprint("[%d] Breakpoint code: %s" % (bpid,pystr))

    def do_bp(self, line):
        """
        Show, add,  and enable/disable breakpoints
        USAGE: bp [-d <addr>] [-a <addr>] [-o <addr>] [[-c pycode] <address> ...]
        -C - Clear All Breakpoints
        -c "py code" - Set the breakpoint code to the given python string
        -d <id> - Disable Breakpoint
        -e <id> - Enable Breakpoint
        -r <id> - Remove Breakpoint
        -o <addr> - Create a OneTimeBreak
        -R <original base>,<original addr>,<Module Name>- rebase and set the break point for module
        -L <libname> - Add bp's to all functions in <libname>
        -F <filename> - Load bpcode from file
        -W perms:size - Set a hardware Watchpoint with perms/size (ie -W rw:4)
        <address>... - Create Breakpoint

        NOTE: -c adds python code to the breakpoint.  The python code will
            be run with the following objects mapped into it's namespace
            automagically:
                vtrace  - the vtrace package
                trace   - the tracer
                bp      - the breakpoint object
        """
        self.trace.requireNotRunning()

        argv = e_cli.splitargs(line)
        opts,args = getopt(argv, "F:e:d:o:r:L:R:Cc:W:")
        pycode = None
        wpargs = None

        for opt,optarg in opts:
            if opt == "-e":
                self.trace.setBreakpointEnabled(eval(optarg), True)

            elif opt == "-c":
                pycode = optarg
                test = compile(pycode, "test","exec")

            elif opt == "-F":
                bp_lines = file(optarg, "rU").readlines()
                for line in bp_lines:
                    if line.find("#") > -1:
                        line = line.split('#')[0]
                    if line == "":
                        continue
                    if line.find("-c") > -1:                
                        pycode = line.split("-c")[1].split()[0].strip()
                        try:
                            test = compile(pycode, "test","exec")
                        except:
					        self.vprint("Error: Not adding BP, bad line entry: %s",line)
					        continue
                    bp_addr = line.split()[-1]
                    try:
                        bp = vtrace.Breakpoint(None, expression=bp_addr)
                        bp.setBreakpointCode(pycode)
                        self.trace.addBreakpoint(bp)
                    except:
                        self.vprint("Error: Not adding BP, bad line entry: %s",line)
                self.vprint(" [ Breakpoints ]")
                for bp in self.trace.getBreakpoints():
                    self.vprint("%s enabled: %s" % (bp, bp.isEnabled()))
                return

            elif opt == "-r":
                self.trace.removeBreakpoint(eval(optarg))

            elif opt == "-R":
                margs = optarg.strip().split(",")
                original_base = None
                original_addr = None
                maps = None
                if "".join(margs[0][0:2]).lower() == "0x":
                    original_base = int(margs[0],16)
                    print original_base
                if "".join(margs[1][0:2]).lower() == "0x":
                    original_addr = int(margs[1],16)
                    print original_addr
                if "".join(margs[2][0:2]).lower() == "0x":
                    va = int(margs[2],16)
                    map = self.memobj.getMemoryMap(va)
                else:
                    maps = [i for i in self.trace.platformGetMaps() if i[3].find(margs[2]) > -1]
                    if len(maps):
                        map = maps[0]
                print map
                if not map or not original_base or not original_addr:
                    self.vprint("Unable to add the breakpoint :-(")
                    print map
                    print original_base
                    print original_addr
                maddr,size,perm,fname = map
                rebased_bp = maddr+(original_addr - original_base)
                args = []
                args.append(hex(rebased_bp))
                

            elif opt == "-C":
                for bp in self.trace.getBreakpoints():
                    self.trace.removeBreakpoint(bp.id)

            elif opt == "-d":
                self.trace.setBreakpointEnabled(eval(optarg), False)

            elif opt == "-o":
                self.trace.addBreakpoint(vtrace.OneTimeBreak(None, expression=optarg))

            elif opt == "-L":
                for sym in self.trace.getSymsForFile(optarg):
                    if not isinstance(sym, e_resolv.FunctionSymbol):
                        continue
                    try:
                        bp = vtrace.Breakpoint(None, expression=str(sym))
                        bp.setBreakpointCode(pycode)
                        self.trace.addBreakpoint(bp)
                        self.vprint("Added: %s" % str(sym))
                    except Exception, msg:
                        self.vprint("WARNING: %s" % str(msg))

            elif opt == "-W":
                wpargs = optarg.split(":")

        for arg in args:
            if wpargs != None:
                size = int(wpargs[1])
                bp = vtrace.Watchpoint(None, expression=arg, size=size, perms=wpargs[0])
            else:
                bp = vtrace.Breakpoint(None, expression=arg)
            bp.setBreakpointCode(pycode)
            self.trace.addBreakpoint(bp)

        self.vprint(" [ Breakpoints ]")
        for bp in self.trace.getBreakpoints():
            self.vprint("%s enabled: %s" % (bp, bp.isEnabled()))

    def do_fds(self, args):
        """
        Show all the open Handles/FileDescriptors for the target process.
        The "typecode" shown in []'s is the vtrace typecode for that kind of
        fd/handle.  If a string is provided, it will be used to filter results

        Usage: fds [filter string]
        """
        find_string = ""
        if len(args.split()) > 0:
            find_string = args.split()[0].strip()
        self.trace.requireAttached()
        for id,fdtype,fname in self.trace.getFds():
            if find_string == "" or\
				str(fdtype).find(find_string) > -1 or\
				str(id).find(find_string) > -1 or\
				fname.find(find_string) > -1:
				self.vprint("0x%.8x [%d] %s" % (id,fdtype,fname))



    def do_ps(self, args):
        """
        Show the current process list.

        Usage: ps
        """
        self.vprint("[Pid]\t[ Name ]")
        for ps in self.trace.ps():
            self.vprint("%s\t%s" % (ps[0],ps[1]))

    def do_break(self, args):
        """
        Send the break signal to the target tracer to stop
        it's execution.

        Usage: break
        """
        self.trace.setMode("RunForever", False)
        self.trace.sendBreak()

    def do_meta(self, string):
        """
        Show the metadata for the current trace.

        Usage: meta
        """
        meta = self.trace.metadata
        x = pprint.pformat(meta)
        self.vprint(x)

    def do_memdiff(self, line):
        """
        Save and compare snapshots of memory to enumerate changes.

        Usage: memdiff [options]
        -C             Clear all current memory diff snapshots.
        -A <va:size>   Add the given virtual address to the list.
        -M <va>        Add the entire memory map which contains VA to the list.
        -D             Compare currently tracked memory with the target process
                       and show any differences.
        """
        argv = e_cli.splitargs(line)
        opts,args = getopt(argv, "A:CDM:")

        if len(opts) == 0:
            return self.do_help('memdiff')

        self.trace.requireNotRunning()

        for opt,optarg in opts:

            if opt == "-A":
                if optarg.find(':') == -1:
                    return self.do_help('memdiff')

                vastr,sizestr = optarg.split(':')
                va = self.parseExpression(vastr)
                size = self.parseExpression(sizestr)
                bytes = self.trace.readMemory(va,size)
                self.difftracks[va] = bytes

            elif opt == '-C':
                self.difftracks = {}

            elif opt == '-D':
                difs = self._getDiffs()
                if len(difs) == 0:
                    self.vprint('No Differences!')
                else:
                    for va,thenbytes,nowbytes in difs:
                        self.vprint('0x%.8x: %s %s' %
                                    (va,
                                     thenbytes.encode('hex'),
                                     nowbytes.encode('hex')))

            elif opt == '-M':
                va = self.parseExpression(optarg)
                map = self.trace.getMemoryMap(va)
                if map == None:
                    self.vprint('No Memory Map At: 0x%.8x' % va)
                    return
                mva,msize,mperm,mfile = map
                bytes = self.trace.readMemory(mva, msize)
                self.difftracks[mva] = bytes

    def _getDiffs(self):

        ret = []
        for va, bytes in self.difftracks.items():
            nowbytes = self.trace.readMemory(va, len(bytes))

            i = 0
            while i < len(bytes):
                thendiff = ""
                nowdiff = ""
                iva = va+i
                while (i < len(bytes) and
                            bytes[i] != nowbytes[i]):
                    thendiff += bytes[i]
                    nowdiff += nowbytes[i]
                    i += 1

                if thendiff:
                    ret.append((iva, thendiff, nowdiff))
                    continue

                i += 1
        
        return ret

    def FIXME_do_remote(self, line):
        """
        Act as a remote debugging client to the server running on
        the specified host/ip.

        Usage: remote <host>
        """
        vtrace.remote = line
        # FIXME how do we re-init the debugger?

    def do_maps_filter(self, line):
        """
        Display either a list of all the memory maps or the memory map
        details for the given address expression.

        Usage: maps [addr_expression]
        """
        argv = ""
        if len(line) > 0:
            argv = line.strip()
        print "Line", line
        totsize = 0
        self.vprint("[ address ] [ size ] [ perms ] [ File ]")
        for addr,size,perm,fname in self.memobj.getMemoryMaps():
            pname = e_mem.reprPerms(perm)
            totsize += size
            sizestr = ("%dK" % (size/1024,)).rjust(8)
            output_str = "%s\t%s\t%s\n" % (sizestr,pname,fname)
            if output_str.find(argv) == -1:
                continue

            self.canvas.addVaText("0x%.8x" % addr, addr)
            self.canvas.addText("%s\t%s\t%s\n" % (sizestr,pname,fname))
        self.vprint("Total Virtual Memory: %s MB" % ((totsize/1024)/1024))
