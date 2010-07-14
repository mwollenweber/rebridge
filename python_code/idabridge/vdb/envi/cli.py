"""
Unified CLI code for things like vivisect and vdb.
"""

import code
import traceback
import threading

import envi.memory as e_mem
import envi.memcanvas as e_canvas
import envi.config as e_config
import envi.expression as e_expr

from cmd import Cmd
from getopt import getopt

import re                                                                                                          
def splitargs(cmdline):
    cmdline = cmdline.replace('\\\\"', '"').replace('\\"', '')
    patt = re.compile('\".+?\"|\S+')
    for item in cmdline.split('\n'):
        return [s.strip('"') for s in patt.findall(item)]

class CliExtMeth:
    """
    This is used to work around the difference
    between functions and bound methods for extended
    command modules
    """
    def __init__(self, cli, func):
        self.cli = cli
        self.func = func
        self.__doc__ = func.__doc__

    def __call__(self, line):
        return self.func(self.cli, line)

cfgdefs = """

[Aliases]

"""

class EnviCli(Cmd):

    def __init__(self, memobj, config=None, symobj=None):

        self.extcmds = {}

        Cmd.__init__(self, stdout=self)

        self.shutdown = threading.Event()

        # If they didn't give us a resolver, make one.
        if symobj == None:
            symobj = e_resolv.SymbolResolver()

        if config == None:
            config = e_config.EnviConfig(defaults=cfgdefs)

        self.config = config
        self.memobj = memobj
        self.symobj = symobj
        self.canvas = e_canvas.MemoryCanvas(memobj, syms=symobj)

    def setCanvas(self, canvas):
        """
        Set a new canvas for the CLI and add all the current renderers
        to the new one.
        """
        for name in self.canvas.getRendererNames():
            canvas.addRenderer(name, self.canvas.getRenderer(name))
        self.canvas = canvas

    def write(self, data):
        # For stdout/stderr
        self.canvas.write(data)

    def get_names(self):
        ret = []
        ret.extend(Cmd.get_names(self))
        ret.extend(self.extcmds.keys())
        return ret

    def getExpressionLocals(self):
        """
        Over-ride this to have things like the eval command
        and the python command use more locals than the sybolic
        defaults.
        """
        return e_expr.MemoryExpressionLocals(self.memobj, symobj=self.symobj)

    def registerCmdExtension(self, func):
        self.extcmds["do_%s" % func.__name__] = CliExtMeth(self, func)

    def vprint(self, msg, addnl=True):
        if addnl:
            msg = msg+"\n"
        self.canvas.write(msg)

    def __getattr__(self, name):
        func = self.extcmds.get(name, None)
        if func == None:
            raise AttributeError(name)
        return func

    def doAlias(self, line):
        for opt in self.config.options("Aliases"):
            if line.startswith(opt):
                line = line.replace(opt, self.config.get("Aliases", opt))
        return line

    def cmdloop(self, intro=None):
        if intro != None:
            self.vprint(intro)

        while not self.shutdown.isSet():
            try:
                Cmd.cmdloop(self, intro=intro)
            except:
                traceback.print_exc()

    def onecmd(self, line):
        lines = line.split("&&")
        try:
            for line in lines:
                line = self.doAlias(line)
                Cmd.onecmd(self, line)
        except SystemExit:
            raise
        except Exception, msg:
            self.vprint(traceback.format_exc())
            self.vprint("ERROR: (%s) %s" % (msg.__class__.__name__,msg))

        if self.shutdown.isSet():
            return True

    def do_EOF(self, line):
        self.vprint("Use quit")

    def do_quit(self, line):
        """
        Quit

        Usage: quit
        """
        self.shutdown.set()

    def do_config(self, line):
        """
        Show or edit a config option from the command line

        Usage: config [-S section] [option=value]
        """
        argv = splitargs(line)
        secname = None
        try:
            opts,args = getopt(argv, "S:")
            for opt,optarg in opts:
                if opt == "-S":
                    secname = optarg

        except Exception, e:
            print e
            return self.do_help("config")

        if len(args) > 1:
            return self.do_help("config")

        if len(args) == 0:
            if secname != None:
                secs = [secname,]
            else:
                secs = self.config.sections()

            for secname in secs:
                self.vprint("")
                self.vprint("[%s]" % secname)
                for oname in self.config.options(secname):
                    val = self.config.get(secname, oname)
                    self.vprint("%s=%s" % (oname, val))

        else:
            if secname == None:
                secname = ""
            key,val = args[0].split("=",1)
            self.config.set(secname, key, val)
            self.vprint("[%s] %s = %s" % (secname,key,val))

    def do_alias(self, line):
        """
        Add an alias to the command line interpreter's aliases dictionary

        Usage: alias <alias_word> rest of the alias command
        To delete an alias:
        Usage: alias <alias_word>
        """
        if len(line):
            row = line.split(None, 1)
            if len(row) == 1:
                self.config.remove_option("Aliases",row[0])
            else:
                self.config.set("Aliases",row[0],row[1])

        self.vprint("Current Aliases:\n")

        opts = self.config.options("Aliases")
        opts.sort()

        for opt in opts:
            val = self.config.get("Aliases", opt)
            self.vprint("%s -> %s" % (opt,val))
        self.vprint("")
        return

    def do_python(self, line):
        """
        Start an interactive python interpreter. The namespace of the
        interpreter is updated with expression nicities.  You may also
        specify a line of python code as an argument to be exec'd without
        beginning an interactive python interpreter on the controlling
        terminal.

        Usage: python [pycode]
        """
        locals = self.getExpressionLocals()
        if len(line) != 0:
            cobj = compile(line, 'cli_input', 'exec')
            exec(cobj, locals)
        else:
            code.interact(local=locals)

    def parseExpression(self, expr):
        l = self.getExpressionLocals()
        return long(e_expr.evaluate(expr, l))

    def do_eval(self, line):
        """
        Evaluate an expression on the CLI to show it's value.

        Usage: eval (ecx+edx)/2
        """
        if not line:
            return self.do_help("eval")
        value = self.parseExpression(line)

        self.canvas.addText("%s = " % line)
        if self.memobj.isValidPointer(value):
            self.canvas.addVaText("0x%.8x" % value, value)
            sym = self.symobj.getSymByAddr(value, exact=False)
            if sym != None:
                self.canvas.addText(" ")
                self.canvas.addVaText("%s + %d" % (repr(sym),value-long(sym)), value)
        else:
            self.canvas.addText("0x%.8x (%d)" % (value, value))

        self.canvas.addText("\n")

    def do_script(self, line):
        """
        Execute a python file.

        The script file is arbitrary python code which is run with the
        full compliment of expression extensions mapped in as locals.

        Usage: script <scriptfile>
        """
        if len(line) == 0:
            return self.do_help("script")

        locals = self.getExpressionLocals()
        script = file(line).read()
        cobj = compile(script, line, "exec")
        exec(cobj, locals)

    def do_maps(self, line):
        """
        Display either a list of all the memory maps or the memory map
        details for the given address expression.

        Usage: maps [addr_expression]
        """
        argv = splitargs(line)
        if len(argv):
            expr = " ".join(argv)
            va = self.parseExpression(expr)
            map = self.memobj.getMemoryMap(va)
            if map == None:
                self.vprint("Memory Map Not Found For: 0x%.8x"%va)

            else:
                addr,size,perm,fname = map
                pname = e_mem.reprPerms(perm)
                self.canvas.addText("Memory Map For: ")
                self.canvas.addVaText("0x%.8x" % va, va)
                self.canvas.addText("\n")
                self.canvas.addVaText("0x%.8x" % addr, addr)
                self.canvas.addText("\t%d\t%s\t%s\n" % (size,pname,fname))
        else:
            totsize = 0
            self.vprint("[ address ] [ size ] [ perms ] [ File ]")
            for addr,size,perm,fname in self.memobj.getMemoryMaps():
                pname = e_mem.reprPerms(perm)
                totsize += size
                self.canvas.addVaText("0x%.8x" % addr, addr)
                sizestr = ("%dK" % (size/1024,)).rjust(8)
                self.canvas.addText("%s\t%s\t%s\n" % (sizestr,pname,fname))
            self.vprint("Total Virtual Memory: %s MB" % ((totsize/1024)/1024))

    def do_search(self, line):
        """
        Search memory for patterns.

        Usage: search [options] <pattern>
        -X The specified pattern is in hex (ie.  414141424242 is AAABBB)
        -E The specified pattern is an expression (search for numeric values)
        -R <baseexpr:sizeexpr> Search a specific range only.
        -r The specified pattern is a regular expression
        """
        if len(line) == 0:
            return self.do_help("search")

        range = None
        dohex = False
        doexpr = False
        regex = False

        argv = splitargs(line)
        try:
            opts,args = getopt(argv, "ER:rX")
        except:
            return self.do_help("search")

        for opt,optarg in opts:
            if opt == "-E":
                doexpr = True
            elif opt == "-R":
                range = optarg
            elif opt == '-r':
                regex = True
            elif opt == "-X":
                dohex = True

        pattern = " ".join(args)
        if doexpr:
            import struct #FIXME see below
            sval = self.parseExpression(pattern)
            pattern = struct.pack("<L", sval) # FIXME 64bit (and alt arch)
        if dohex: pattern = pattern.decode('hex')
        if range:
            try:
                addrexpr, sizeexpr = range.split(":")
            except Exception, e:
                return self.do_help("search")
            addr = self.parseExpression(addrexpr)
            size = self.parseExpression(sizeexpr)
            self.canvas.addText("Searching from ")
            self.canvas.addVaText("0x%.8x", addr)
            self.canvas.addText(" for %d bytes\n" % size)
            res = self.memobj.searchMemoryRange(pattern, addr, size, regex=regex)
        else:
            self.vprint("Searching all memory...")
            res = self.memobj.searchMemory(pattern, regex=regex)

        if len(res) == 0:
            self.vprint('Pattern Not Found: %s' % pattern.encode('hex'))
            return

        self.vprint('Matches for: %s' % pattern.encode('hex'))
        for r in res:
            self.canvas.addVaText("0x%.8x" % r, r)
            self.canvas.addText(": ")

            mbase,msize,mperm,mfile = self.memobj.getMemoryMap(r)
            pname = e_mem.reprPerms(mperm)

            self.canvas.addText("%s " % pname)

            sname = self.reprPointer(r)

            self.canvas.addText(sname)
            self.canvas.addText("\n")

    def reprPointer(self, va):
        """
        Do your best to create a humon readable name for the
        value of this pointer.
        """
        if va == 0:
            return "NULL"

        mbase,msize,mperm,mfile = self.memobj.getMemoryMap(va)
        ret = mfile
        sym = self.symobj.getSymByAddr(va, exact=False)
        if sym != None:
            ret = "%s + %d" % (repr(sym),va-long(sym))
        return ret

    def do_memdump(self, line):
        """
        Dump memory out to a file.

        Usage: memdump <addr_expression> <size_expression> <filename>
        """
        if len(line) == 0:
            return self.do_help("memdump")

        argv = splitargs(line)
        if len(argv) != 3:
            return self.do_help("memdump")

        addr = self.parseExpression(argv[0])
        size = self.parseExpression(argv[1])

        mem = self.memobj.readMemory(addr, size)
        file(argv[2], "wb").write(mem)
        self.vprint("Wrote %d bytes!" % len(mem))

    def do_mem(self, line):
        """
        Show some memory (with optional formatting and size)

        Usage: mem [-F <format>] <addr expression> [size]

        NOTE: use -F ? for a list of the formats
        """
        fmtname = "bytes"

        if len(line) == 0:
            return self.do_help("mem")

        argv = splitargs(line)
        try:
            opts,args = getopt(argv, "F:")
        except:
            return self.do_help("mem")

        for opt,optarg in opts:
            if opt == "-F":
                fmtname = optarg
                fnames = self.canvas.getRendererNames()

                if fmtname == "?":
                    self.vprint("Registered renderers:")
                    for name in fnames:
                        self.vprint(name)
                    return

                if fmtname not in fnames:
                    self.vprint("Unknown renderer: %s" % fmtname)
                    return

        if len(args) == 0:
            return self.do_help("mem")

        size = 256
        addr = self.parseExpression(args[0])
        if len(args) == 2:
            size = self.parseExpression(args[1])

        self.canvas.setRenderer(fmtname)
        self.canvas.render(addr, size)

class EnviMutableCli(EnviCli):
    """
    Cli extensions which require a mutable memory object
    (emulator/trace) rather than a static one (viv workspace)
    """

    def do_memcpy(self, line):
        '''
        Copy memory from one location to another...

        Usage: memcpy <dest_expr> <src_expr> <size_expr>
        '''
        argv = splitargs(line)
        if len(argv) != 3:
            return self.do_help('memcpy')


        dst = self.parseExpression(argv[0])
        src = self.parseExpression(argv[1])
        siz = self.parseExpression(argv[2])

        mem = self.memobj.readMemory(src, siz)
        self.memobj.writeMemory(dst, mem)

    def do_memprotect(self, line):
        """
        Change the memory permissions of a given page/map.

        Usage: memprotect [options] <addr_expr> <perms>
        -S <size> Specify the size of the region to change (default == whole memory map)
        <perms> = "rwx" string "rw", "rx" "rwx" etc...
        """
        if len(line) == 0:
            return self.do_help("memprotect")

        size = None
        argv = splitargs(line)
        try:
            opts, args = getopt(argv, "S:")
        except Exception, e:
            return self.do_help("memprotect")

        for opt,optarg in opts:
            if opt == "-S":
                size = self.parseExpression(optarg)

        if len(args) != 2:
            return self.do_help("memprotect")


        addr = self.parseExpression(args[0])
        perm = e_mem.parsePerms(args[1])

        map = self.memobj.getMemoryMap(addr)
        if map == None:
            raise Exception("Unknown memory map for 0x%.8x" % addr)

        if size == None:
            size = map[1]

        self.memobj.protectMemory(addr, size, perm)

    def do_writemem(self, args):
        """
        Over-write some memory in the target address space.
        Usage: writemem [options] <addr expression> <string>
        -X    The specified string is in hex (ie 414141 = AAA)
        -U    The specified string needs to be unicode in mem (AAA -> 410041004100)
        """
        dohex = False
        douni = False

        try:
            argv = splitargs(args)
            opts,args = getopt(argv, "XU")
        except:
            return self.do_help("writemem")

        if len(args) != 2:
            return self.do_help("writemem")

        for opt,optarg in opts:
            if opt == "-X":
                dohex = True
            elif opt == "-U":
                douni = True

        exprstr, memstr = args
        if dohex: memstr = memstr.decode('hex')
        if douni: memstr = ("\x00".join(memstr)) + "\x00"

        addr = self.parseExpression(exprstr)
        self.memobj.writeMemory(addr, memstr)

