from buffer import *
from basehandler import *
import threading

from vtrace.notifiers import Notifier
import vtrace
import traceback


#from aliases import *

from idapython_aliases import *

# this will break how i handle commands
# need another way to approach this :/
# figured it out uuuu-uuuu-t



class EventNotifier(Notifier):
    def __init__(self, **kargs):
        self.parent = kargs.get('parent',None)
        self.events = {}
        self.event_callbacks = {}
        self.executing_events = []
        self.ee_lock  =threading.Lock()
        
    def registerCmdHandler(self, event, cmd_name, callback=None):
        if not event in self.events:
            self.events[event] = set()
        self.events[event].add(cmd_name)
        if callback:
            self.event_callbacks[str(event)+":"+cmd_name] = callback
        
    def unregisterCmdHandler(self, event, cmd_name):
        if (str(event)+":"+cmd_name) in self.event_callbacks:
            del self.event_callbacks[str(event)+":"+cmd_name]
        
        if event in self.events and\
            cmd_name in self.events[event]:
            self.events[event].remove(cmd_name)
            return len(self.events[event]) > 0
        return True
        
    def clean_up(self):
        self.ee_lock.acquire()
        new_ee = []
        for i in self.executing_events:
            if i.isAlive():
                new_ee.append(i)
        self.executing_events = new_ee
        self.ee_lock.release()
    
    def notify(self, event, trace):
        self.clean_up()
        self.ee_lock.acquire()
        #print "Handling an events"
        if event in self.events:
            for cmd in self.events[event]:
                try:
                    callback = None
                    if (str(event)+":"+cmd) in self.event_callbacks:
                        callback = self.event_callbacks[str(event)+":"+cmd_name]
                    self.executing_events.append(EventThread(self.parent, cmd, event, trace=trace, callback=callback))
                except:
                    # part of me wants to swallow this exception, but i only know
                    # that would lead to real drama, so we raise
                    print "ohh noes! "
                    self.ee_lock.release()
                    raise
        self.ee_lock.release()

        
class rebase(Handler):
    
    def __post_init__(self):
        self.aliases = ['rebase']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_RES)
        base = self.parent.platformGetImageBaseAddress()
        #print "Base address was: %s"%base
        buffer.write_string(base)
        return self.parent.send(buffer)

    def req(self, buffer, **kargs):
        buffer = self.create_base_buffer(CMD_RES)
        base = self.parent.platformGetImageBaseAddress()
        buffer.write_string(base)
        return self.parent.send(buffer)

class pyeval(Handler):
    def __post_init__(self):
        self.aliases = ['pyeval']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ)
        buffer.write_string(string)
        return self.parent.send(buffer)
    
    def req(self, buffer, **kargs):
        code = buffer.read_string()
        results = self.parent.platformEvalString(code)
        buffer = self.create_base_buffer(CMD_RSP, "pyeval")
        buffer.write_string(results)
        return self.parent.send(buffer)
        
    def rsp(self, buffer, **kargs):
        result = buffer.read_string()
        self.parent.platformPrintResult(result)
        return True
        
    def req(self, buffer, **kargs):
        code = buffer.read_string()
        buffer = self.create_base_buffer(CMD_RES)
        result = self.parent.platformEval(code)
        buffer.write_string(result)
        return self.parent.send(buffer)

        
class pycmd(Handler):
    
    def __post_init__(self):
        self.aliases = ['pycmd']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
        for idapython_cmd in IDAPYTHON_ALIASES:
            name = idapython_cmd.split(",")[0]
            for alias in  idapython_cmd.split(","):
                self.parent.add_pycmd_alias(name, alias)
    
    def cli(self, string, **kargs):
        if len(string) == 0:
            return False
        cmd = string.split()[0]
        args = ""
        if len(string.split()) > 0:
            args = " ".join(string.split()[1:])
        buffer = self.create_base_buffer(CMD_REQ, "pycmd")
        buffer.write_string(cmd)
        buffer.write_string(args)
        return self.parent.send(buffer)
    
    def req(self, buffer, **kargs):
        cmd = buffer.read_string()
        args = buffer.read_string()
        code = "%s(%s)"%(cmd,args)
        results = self.parent.platformEvalString(code)
        buffer = self.create_base_buffer(CMD_RSP, "pycmd")
        buffer.write_string(code)
        buffer.write_string(str(results))
        return self.parent.send(buffer)
        
    def rsp(self, buffer, **kargs):
        cmd = buffer.read_string()
        result = buffer.read_string()
        self.parent.platformPrintResult(result, cmd)
        return True
        
# breakc implements an event handler
# that is notified by the parent class
# the parent class has an attribute that is a
# notifier (cmd_evt_motifier).
# The notifier tracks all the commands that want
# to         
class breakc(Handler):
    def __post_init__(self):
        self.aliases = ['bphit','break','stop','b','br']
        self.interested_evts = [vtrace.NOTIFY_BREAK, vtrace.NOTIFY_STEP]
        # break is a python keyword, so i need to work around that
        self.parent.unregister_cmd(self)
        self.cmd_name = "break"
        self.parent.register_cmd(self)
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
        # register commands of interests
        for evt in self.interested_evts:
            self.parent.register_cmd_evt(evt,self.cmd_name)
    
    def requirements(self):
        return self.parent.is_connected()
    
    def break_tid(self, string):
        tid = self.get_tid(string)
        result = True
        self.parent.platformHandleRemoteBreak(tid)
        return result
    
    def evt(self, evt, **kargs):
        #print "w000t, break occurred!"
        #print "If you are here, chances are you are another thread in the matrix."
        #if "trace" in kargs:
        #    self.parent.trace = kargs['trace']
        self.parent.platformSaveRegisters()    
        if not self.requirements():
            #print "but you forgot to follow the white rabbit, goto sleep:"
            return False
        #print "And the moment of trut"
        # update registers and append to register history, nyuk, nyuk
        self.parent.platformSaveRegisters()
        pc = self.parent.platformGetPC()
        buffer = self.create_base_buffer(CMD_RES, "break")
        buffer.write_string("0x%08x"%(pc))
        return self.parent.send(buffer)
        
    def cli(self, string, **kargs):
        #pc = self.break_tid(string)
        result = self.break_tid(string)
        #buffer = self.create_base_buffer(CMD_RES, "break")
        #buffer.write_string("0x%08x"%(pc))
        #return self.parent.send(buffer)
        self.parent.platformPrintResult(str(result), "break=>cli")
        return result
    
    def req(self, buffer, **kargs):
        string = buffer.read_string()
        #pc = self.break_tid(string)
        result = self.break_tid(string)
        #buffer = self.create_base_buffer(CMD_RES, "break")
        #buffer.write_string("0x%08x"%(pc))
        #return self.parent.send(buffer)
        self.parent.platformPrintResult(str(result), "break=>cli")
        return result
        
    def rsp(self, buffer, **kargs):
        return self.req(buffer)

class resume(Handler):
    def __post_init__(self):
        self.aliases = ['resume','continue','go','g']
        # break is a python keyword, so i need to work around that
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def req(self, buffer, **kargs):
        string = buffer.read_string()
        print "Attempting to perform a resume???"
        tid,result = self.resume_tid(string)
        self.parent.platformPrintResult("Resuming exection tid: 0x%x Result:%s"%(tid, str(result)))
        return result
    
    def resume_tid(self, string):
        tid = self.get_tid(string)
        result = True
        self.parent.platformHandleRemoteResume(tid)
        return tid, result

        
# resolve, and add break point
class rabp(Handler):
    def __post_init__(self):
        self.aliases = ['rabp']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        if len(string.strip()) == 0:
            return
        buffer = self.create_base_buffer(CMD_REQ)
        buffer.write_string(string)
        return self.parent.send(buffer)
            
    def rsp(self, buffer, **kargs):
        expression = buffer.read_string()
        if expression == "":
            self.parent.platformPrintResult("Location does not exist, bp failed"%expression)
            return False
        addr = buffer.read_string()
        if addr == "0xFFFFFFFF":
            self.parent.platformPrintResult("%s: No Resolution bp failed"%expression)
            return False
        # value should be the ida address
        bp = vtrace.Breakpoint(None, expression=addr)
        self.parent.trace.addBreakpoint(bp)
        self.parent.platformPrintResult("Added breakpoint for %s: %s"%(expression, addr))
        return True
        
class saveregs(Handler):
    def __post_init__(self):
        self.aliases = ['save','saveregs','sa']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def cli(self, string, **kargs):
        self.parent.saveRegisters()
        return True
    
class setregs(Handler):
    def __post_init__(self):
        self.aliases = ['setregs','sr','sregs']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def cli(self, string, **kargs):
        regs = self.platformGetRegisters()
        buffer = self.create_base_buffer(CMD_REQ, "setregs")
        regs = self.parent.platformGetRegisters()
        regs_str = ""
        if not regs is None:
            regs_str = ",".join(["%s:0x%08"%(reg,regs[reg]) for reg in regs])
        buffer.write_string(regs_str)
        return self.parent.send(buffer)
                
    def req(self, buffer, **kargs):
        regs_str = buffer.read_string()
        regs = {}
        for reg_val in regs_str.split(','):
            reg,val = reg_val.split(":")
            ival = self.convert_str_to_numval(val)
            if ival is None:
                regs[reg] = 0
            regs[reg] = ival
        self.parent.platformSetRegisters(regs)
        return True
            
    #def rsp(self,buffer):
    #    self.req(buffer)

class getregs(Handler):
    def __post_init__(self):
        self.aliases = ['getregs','gr','gregs']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "getregs")
        return self.parent.send(buffer)
                
    def req(self, buffer, **kargs):
        regs = self.parent.platformGetRegisters()
        regs_str = ""
        if not regs is None:
            regs_str = ",".join(["%s:0x%08x"%(reg,regs[reg]) for reg in regs])
        buffer = self.create_base_buffer(CMD_RSP, "getregs")
        buffer.write_string(regs_str)
        return self.parent.send(buffer)
            
    def rsp(self,buffer):
        regs_str = buffer.read_string()
        regs = {}
        for reg_val in regs_str.split(','):
            reg,val = reg_val.split(":")
            ival = self.convert_str_to_numval(val)
            if ival is None:
                regs[reg] = 0
            regs[reg] = ival
        self.parent.platformSetRegisters(regs)
        return True
        
# TODO:Copied from idahandlers fixme  
class setbps(Handler):
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "setbps")
        bp_str = ",".join([bp.getAddress() for i in self.parent.getBreakpoints()])
        buffer.write_string(bp_str)
        return self.parent.send(buffer)
        
    def req(self, buffer, **kargs):
        breakpoints = buffer.read_string()
        bp_list = [bp for i in breakpoints.split(',')]
        self.parent.removeAllBreakpoints()
        for bp in bp_list:
            self.parent.addBreakpointByAddr(bp)
        return True

# TODO: Not tested.          
class getbps(Handler):
    
    def __post_init__(self):
        self.aliases = ['getbps','gbps']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "getbps")
        return self.parent.send(buffer)
        
    def req(self, buffer, **kargs):
        bp_str = ",".join(self.parent.platformGetBreakpoints())
        buffer = self.create_base_buffer(CMD_REQ, "setbps")
        buffer.write_string(bp_str)
        return self.parent.send(buffer)
            

# TODO: Not tested.       
class setbps(Handler):
    
    def __post_init__(self):
        self.aliases = ['setbps','sbps']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "setbps")
        bp_str = ",".join(self.parent.platformGetBreakpoints())
        buffer.write_string(bp_str)
        return self.parent.send(buffer)
        
    def req(self, buffer, **kargs):
        breakpoints = buffer.read_string()
        bp_list = [bp for bp in breakpoints.split(',')]
        self.parent.platformClearBreakpoints()
        # ignore the names provided by the debugger at the moment
        kargs = {'idaname':""}
        for bp in bp_list:
            kargs['idaname'] = ""
            bpaddr = bp.split(":")[0]
            if len(bp.split(":")) > 1:
                kargs['idaname'] = bp.split(":")[1]
            self.parent.addBreakpointByAddr(bp.split(":")[0], **kargs)
        return True

class writemem(Handler):
    def __post_init__(self):
        self.aliases = ['writemem','write_mem']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def cli(self, string):
        buffer = self.create_base_buffer(CMD_REQ, "writemem")
        buffer_args = ""
        toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
        
        #do any pre-processing on the args
        print "in writemem.cli got str=%s\n" % string
        string = string.strip()
        args = string.split(' ')
        
        try:
            if str(args[0]).isalnum() == True:     
                int(args[0], 16)
                buffer_args += args[0] + ","
                args[1] = args[1].strip()
                args[1] = args[1].strip('"')
                buffer_args += toHex(args[1]) +","
                print "out = %s\n" % buffer_args
            else:
                raise
        except:
            #else also consider passed an integer
            #else also consider passed a variable
            print "fuxk\n"
            exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
            traceback.print_exception(exceptionType, exceptionValue, exceptionTraceback, limit=2, file=sys.stdout)
            return self.return_data(False)
        
        buffer.write_string(buffer_args)
        buffer.write_string("0x%08x"%addr_val)
        return self.return_data(buffer)
        
    def req(self, buffer):
        print "got a writemem req\n"
        print "buffer str = %s" % buffer.read_string()
        return self.return_data(True)

    def rsp(self, buffer):
        print "writemem.rsp " + buffer.read_string()
        return self.return_data(True)
    
class readmem(Handler):
    def __post_init__(self):
        self.aliases = ['readmem','read_mem']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string):
        #do any pre-processing on the args
        buffer_args = ""
        
        print "in writemem.cli got str=%s\n" % string
        string = string.strip()
        args = string.split(' ')
        
        try:
            if len(args) == 2 and str(args[0]).isalnum() and str(args[1]).isalnum():
                int(args[0], 16)
                int(args[1], 10)
                buffer_args += args[0] + ","
                buffer_args += args[1] +","
                
            elif len(args) == 1 and str(args[0]).isalnum():
                int(args[0], 16)
                buffer_args += args[0] + ","
                buffer_args += "4," #default to a dword read
                
            else:
                return self.return_data(False)
        except:
            print "ERROR: unable to process readmem\n"
            return self.return_data(False)
        
        buffer = self.create_base_buffer(CMD_REQ, "readmem")
        buffer.write_string(buffer_args)
        return self.return_data(buffer)
        
    def req(self, buffer):
        print "got a read_mem req\n"
        print "buffer str = %s" % buffer.read_string()
        return self.return_data(True)

    def rsp(self, buffer):
        print "readmem.rsp: " + buffer.read_string()
        return self.return_data(True)
