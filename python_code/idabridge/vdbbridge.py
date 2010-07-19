import struct, sys, time, Queue, threading, os
from buffer import *
from socket import socket
from socket import timeout
from threading import Thread
import bridgecomms
from vdbhandlers import *
from idapython_aliases import *
import envi.cli as e_cli
import PE
from vdbbridgeutils import *
import time
sys.path.append("vdb/")
import vdb

def init_vdbbridge_cmds(vdbbridge):
    vdbbridge_vals = {}
    vdbbridge_vals['parent']=vdbbridge
    fail(**vdbbridge_vals)
    breakc(**vdbbridge_vals)
    rebase(**vdbbridge_vals)
    pyeval(**vdbbridge_vals)
    pycmd(**vdbbridge_vals)
    resume(**vdbbridge_vals)
    rabp(**vdbbridge_vals)
    
    # these appear to work
    setbps(**vdbbridge_vals)
    getbps(**vdbbridge_vals)
    setregs(**vdbbridge_vals)
    getregs(**vdbbridge_vals)
    
    # need to test these
    writemem(**vdbbridge_vals)
    readmem(**vdbbridge_vals)

class MemoryBlock(object):
    def __init__(self, addr, **kargs):
        object.__init__(self)
        self.time = kargs.get("time", time.time())
        self.addr = addr
        self.data = kargs.get("data","")
        self.name = kargs.get("name","")
        self.appname = kargs.get("appname","")
    
    def __str__(self):
        return "%s:%s %s"%(self.addr, self.name, repr(self.data))

class Vdbbridge(vdb.Vdb, bridgecomms.IDARS):
    def __init__(self, trace):
        bridgecomms.IDARS.__init__(self)
        vdb.Vdb.__init__(self,trace=None)
        self.handlers = {}
        self.pycmds = {}
        self.aliases = {}
        self.bps = []
        self.reg_history = []
        self.regs = {}
        self.current_address = "0x0"
        self.pc_name = None
        self.remote_cmd_queue = []
        #self.tid_to_handle = 0xFFFFFFFF
        self.handle_remote_cmd = False
        self.remote_cmd_lock = threading.Lock()
        self.memory_blocks = []
        
        # add commands here
        d = {'parent':self}
        self.evt_cmdnotifier = EventNotifier(**d)
        init_vdbbridge_cmds(self)
        
    def do_start(self, args=None):
        host = None
        port = None
        if args is None or len(args) == 0:
            self.start_listener(host, port)
        elif len(args.split()) > 0:
            host = args.split()[0]
            self.start_listener(host, port)
        elif len(args.split()) > 0:
            host = args.split()[0]
            port = args.split()[1]
            if port.isdigit():
                port = int(port)
            else:
                port = None
            self.start_listener(host, port)
    
    # TODO: figure out how to make the
    # do_quit play nicely with e_cli voodoo
    def do_quit(self, args=None):
        self.do_stop(args)
        e_cli.EnviMutableCli.do_quit(self, args)
    
    def do_stop(self, args=None):
        self.stop_listener()
    
    def do_ib(self, args):
        # handle commands we are 
        # going to send to idabridge here
        if not self.is_connected():
            raise Exception("Need to be connected to IDA")
        
        if len(args.strip()) == "" :
            raise Exception("Need to specify a command")
        
        cmd = args.strip().split()[0]
        myargs = ""
        if len(args.strip().split()) > 1:
            myargs = " ".join(args.strip().split()[1:])
        results = self.handle_cli(cmd, myargs)
        
        # if necessary this should send the resulting buffer
        if results.find("<BUFFER>:") == 0:
            buffer_data = "<BUFFER>:".join(reults.split("<BUFFER>:")[1:])
            buffer = Buffer(buffer_data)
            self.send(buffer)
        self.vprint("%s: %s" % (cmd, results))
    

    def do_start(self, args=None):
        host = None
        port = None
        if args is None or len(args) == 0:
            self.start_listener(host, port)
        elif len(args.split()) > 0:
            host = args.split()[0]
            self.start_listener(host, port)
        elif len(args.split()) > 0:
            host = args.split()[0]
            port = args.split()[1]
            if port.isdigit():
                port = int(port)
            else:
                port = None
            self.start_listener(host, port)
    
    def do_stop(self, args):
        self.stop_listener()
    
    
    def add_pycmd_alias(self, name, alias):
        self.pycmds[alias] = name
        
    
    def platformGetRegisters(self, id=None):
        if not id is None:
            return self.reg_history[id]
        return self.regs
    
    def platformUpdateRegisters(self, **kargs):
        regs = kargs.get('regs',None)
        if regs is None:
            regs = self.trace.getRegisters()
            
        self.regs = regs
        for k,v in regs.items():
            self.regs[k] = v
    
    
    def platformSetRegisters(self, regs):
        self.regs = regs
        for regname,val in self.regs.items():
            self.trace.setRegisterByName(regname, val)
        

    def platformSaveRegisters(self):
        self.reg_history.insert(0, self.regs)
    
    def platformAddBreakpoint(self, bp, **kargs):
        # at the moment i am not going to play the bp game
        addr = self.trace.parseExpression(bp)
        vdbname = self.trace.getSymNameDeltaByAddr(addr)
        if vdbname:
            kargs['vdbname'] = vdbname
        kargs['expression'] = bp
        bp = vtrace.Breakpoint(None, **kargs)
        self.trace.addBreakpoint(bp)
    
    def platformGetBreakpoints(self):
        # should make this more robust
        # support code and active, condition etc.
        bp_strs = []
        for bp in self.trace.getBreakpoints():
            try:
                addr = bp.getAddress()
                if addr is None:
                    print "Bp had no addr :(\n"
                    addr = bp.resolveAddress(self.trace)
                    if addr is None:
                        print "Bp had no addr and it could not be resolved\n"
                        continue
                bp_str = "0x%08x:%s"%(addr,"")# bp.idaname)
                bp_strs.append(bp_str)
            except:
                self.platformPrintResult("Ooops! breakpoint exception occurred: %s\n"%(str(sys.exc_info()[0])))
        return bp_strs
        
    def platformClearBreakpoints(self):
        # should make this more robust
        # support code and active, condition etc.
        self.trace.removeAllBreakpoints()
            
    def platformPrintResult(self, results, cmd_name=None):
        if not cmd_name:
            cmd_name = ""
        else:
            cmd_name = cmd_name +"=> "
        self.vprint("Recv'd Result: %s"%(cmd_name+results))
    
    def register_cmd_evt(self, evt, cmd_name):
        self.evt_cmdnotifier.registerCmdHandler(evt, cmd_name)
        self.registerNotifier(evt, self.evt_cmdnotifier)
        
    def unregister_cmd_evt(self, evt, cmd_name):
        if not self.evt_cmdnotifier.unregisterCmdHandler(evt, cmd_name):
            self.unregisterNotifier(evt, self.evt_cmdnotifier)
    
    def notify_cmd_evt(self, evt):
        self.evt_cmdnotifier.notify(evt, self)
    
    def register_cmd(self, handler):
        cmd_name = handler.get_name()
        self.handlers[cmd_name] = handler
        self.aliases[cmd_name] = cmd_name
        
    def unregister_cmd(self, handler):
        cmd_name = handler.get_name()
        del self.handlers[cmd_name]
        del self.aliases[cmd_name]
        for k in self.aliases:
            if self.aliases[k] == cmd_name:
                del self.aliases[k]
    
    def handle_msg(self, buffer, **kargs):
        #print buffer
        cmd_type = buffer.read_int()
        cmd_name = buffer.read_string()
        result = "eh?!?"
        if kargs is None:
            kargs = {}
        if not cmd_type in set([CMD_REQ, CMD_RES]):
            kargs['reason'] = "Invalid command type."
            # calling command directly
            result = self.handler['fail'](CMD_CLI, None, **kargs)
        else:
            result = self.execute_cmd(cmd_type, cmd_name, buffer, **kargs)
        #print "Result of network msg: %s"%(str(result))
        return result

    def handle_cli(self, cmd, args, **kargs):
        if kargs is None:
            kargs = {}
        return str(self.execute_cmd(CMD_CLI, cmd, args, **kargs))
        
    def handle_evt(self, cmd, evt, **kargs):
        if kargs is None:
            kargs = {}
        return str(self.execute_cmd(CMD_EVT, cmd, evt, **kargs))
        
    def execute_cmd(self, cmd_type, cmd_name, data, **kargs):
        #print "Cmd Type: %s cmd_name: %s data: %s"%(cmd_type, cmd_name, data)
        #print "not cmd_name in self.aliases and not cmd_name in self.pycmds: %s"%str(not cmd_name in self.aliases and not cmd_name in self.pycmds) 
        #print "(cmd_name in self.aliases and self.aliases[cmd_name] in self.pycmds): %s"%str(cmd_name in self.aliases and self.aliases[cmd_name] in self.pycmds)
        if cmd_name is None:
            kargs['reason'] = "Command name was None."
            # calling command directly
            return self.handler['fail'](CMD_CLI, None, **kargs)
        if cmd_name in self.aliases and self.aliases[cmd_name] != "pycmd":
            cmd_name = self.aliases[cmd_name]
        elif (cmd_name != "pycmd") and\
            ((not cmd_name in self.aliases) or\
            (cmd_name in self.pycmds)):
            mydata = ""
            if cmd_name in self.pycmds:
                cmd_name = self.pycmds[cmd_name]
            if isinstance(data, str):
                data = cmd_name+" "+data
                mydata = data
            elif isinstance(data, Buffer):
                buf = Buffer()
                buf.write_string(cmd_name)
                
                args = data.read_string()
                if args is None:
                    args = ""
                mydata = cmd_name +" "+args
                buf.write_string(args)
                data = buf
            is_pycmd = cmd_name in self.pycmds
            cmd_name = "pycmd"
            print "CMD in (%s), CMD passed to pycmd: %s"%(str(is_pycmd), mydata)
            
        print "Final cmd_name: %s cmd_type: %d"%(cmd_name, cmd_type)
        handler = self.handlers[cmd_name]
        return handler.handle(cmd_type, data, **kargs)
    
    def add_aliases(self, cmd_name, aliases):
        self.aliases[cmd_name] = cmd_name
        for alias in aliases:
            self.aliases[alias] = cmd_name
        
    def platformGetImageBaseAddress(self, name=None):
        trace = self.trace
        if name is None:
            name = trace.getMeta("ExeName")
            #print "Exe name is %s"%(str(name))
            if name and os.path.split(trace.metadata['ExeName']) > 0:
                fname = os.path.split(trace.metadata['ExeName'])[-1]
                name = os.path.splitext(fname)[0]
        #print "Exe base name is %s"%(str(name))
        if name is None or\
            not trace.hasMeta('LibraryBases') or\
            not name in trace.getMeta('LibraryBases'):
            return "0xFFFFFFFF"
        baseAddr = trace.getMeta('LibraryBases')[name]
        mem = PE.MemObjFile(trace, baseAddr)
        pobj = PE.PE(mem, inmem=True)
        optionalHeader = pobj.IMAGE_NT_HEADERS.OptionalHeader
        #+x.BaseOfCode
        return "0x%x"%(baseAddr+optionalHeader.BaseOfCode)
        
    def platformEval(self, code):
        result = None
        print "Executing the following code",code
        try:
            result = eval(code)
        except:
            "Print Recv'd the following exception:\n%s"%str(sys.exc_info()[0].args)
            result = str(sys.exc_info()[0].args)
        return (str(result))
        
    def platformGetPC(self,tid=None):
        regs = {}
        if tid is None:
            tid = self.trace.getMeta("ThreadId")            
        #regs = self.trace.platformGetRegCtx(tid)
        regs = self.trace.getRegisters()
        if self.pc_name:
            return regs[self.pc_name]
        # i think order matters
        pc_regs = ['pc', 'rip', 'eip',]
        for pc_name in pc_regs:
            if pc_name in regs:
                self.pc_name = pc_name
                return regs[pc_name]
        return 0xFFFFFFFF

    def do_stepi(self, args):
        """
        Single step the target tracer.
        Usage: stepi [count expression]
        (moved into the vdbbridge, because this command will 
            eat events, and i wont be able to upadte if that happens)
        """
        t = self.trace
        if len(args):
            count = t.parseExpression(args)
        else:
            count = 1

        #oldmode = self.getMode('FastStep')
        #self.setMode('FastStep', True)
        try:
            for i in xrange(count):
                pc = t.getProgramCounter()
                self.canvas.render(pc, 1, rend=self.opcoderend)
                t.stepi()
                if t.getMeta('PendingException'):
                    break
                if t.getMeta('PendingSignal'):
                    break
                #self.notify_cmd_evt(vtrace.NOTIFY_STEP)
        finally:
            #self.setMode('FastStep', oldmode)
            # We ate all the events, tell the GUI to update
            # if it's around...
            if self.gui != None: self.gui.setTraceWindowsActive(True)        
    
    
    def platformEvalString(self, code):
        result = ""
        try:
            result = eval(code)
        except Exception as inst:
            result += str(type(inst))+"\n"
            result += str(inst.args)+"\n"
            #result += str(inst.message)+"\n"
        return result
    
    def platformExecString(self, code):
        result = False
        try:
            exec(code)
            result = True
        except:
            pass
        return result
    
    def platformHandleRemoteResume(self, tid=0xFFFFFFFF):
        # since we are in a cmd loop we can not break and resume
        # traditionally, so we ssend a cmd to the cmd loop
        # for a envi without a cmd loop, i will need to implement
        # sometion like in the handle_remote_cmds + platformRemote.*
        if tid == 0xFFFFFFFF:
            self.onecmd("go\r\n")
        elif tid.isdigit():
            self.onecmd("resume %d\r\n"%tid)
        
    def platformHandleRemoteBreak(self, tid=0xFFFFFFFF):
        # since we are in a cmd loop we can not break and resume
        # traditionally, so we ssend a cmd to the cmd loop
        # for a envi without a cmd loop, i will need to implement
        # sometion like in the handle_remote_cmds + platformRemote.*
        if tid == 0xFFFFFFFF:
            self.onecmd("break\r\n")
        elif tid.isdigit():
            self.onecmd("suspend %d\r\n"%tid)
    
    def check_pending_evt_queue(self, evt):
        return len(self.remote_cmd_queue) and evt == self.remote_cmd_queue[0][1]
    
    def platformAddMemoryBlock(self, addr, data, id=0, **kargs):
        kargs['trace'] = self.trace
        kargs['regs']=self.regs
        addr_val = VdbbridgeUtils.guess_addr_by_name_expression(addr, **kargs)
        mb = MemoryBlock(addr_val, data=data, **kargs)
        self.memory_blocks.insert(id, mb)
        
    def platformRemoveMemoryBlock(self, id):
        if id > len(self.memory_blocks):
            return None
        mb = self.memory_blocks[id]
        self.pop(id)
        return mb
    
    def platformGetMemoryBlock(self, id):
        if id > len(self.memory_blocks):
            return None
        return self.memory_blocks[id]