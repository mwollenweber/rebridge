from buffer import *
from idahandlers import *
from basehandler import *
from idapython_aliases import *
from idabridgeutils import *
from time import *
from bridgecomms import *

try:
    import bridgecomms
except:
    print "If you are having socket issues, make sure you're PATH includes PythonXX\DLLS"
    raise


try:
    import idc
    import idaapi
    import idautils
    import pywraps
    #import sys
    import os
except:
    print "unable to load the ida modules"

    
def unload_modules():
    del sys.modules['idahandlers']
    del sys.modules['Buffer']
    del sys.modules['idabridge']

def init_idabridge_cmds(idabridge):
    idabridge_vals = {}
    idabridge_vals['parent']=idabridge
    fail(**idabridge_vals)
    rebase(**idabridge_vals)
    #python(**idabridge_vals)

    pyeval(**idabridge_vals)
    pycmd(**idabridge_vals)
    pyadd(**idabridge_vals)

    setbps(**idabridge_vals)
    getbps(**idabridge_vals)

    resume(**idabridge_vals)
    breakc(**idabridge_vals)
    #bphit(**idabridge_vals)

    setregs(**idabridge_vals)
    getregs(**idabridge_vals)
    rabp(**idabridge_vals)
    writemem(**idabridge_vals)
    readmem(**idabridge_vals)
 
 
class MemoryBlock(object):
    def __init__(self, addr, **kargs):
        object.__init__(self)
        self.time = kargs.get("time", time())
        self.addr = addr
        self.data = kargs.get("data","")
        self.name = kargs.get("name","")
        self.appname = kargs.get("appname","")
    
    def __str__(self):
        return "%s:%s %s"%(self.addr, self.name, repr(self.data))

class Registers(dict):
    def __init__(self, **kargs):
        dict.__init__(self)
        self.time = kargs.get("time", time())
 
class Idabridge:
    def __init__(self):
        self.handlers = {}
        self.pycmds = {}
        self.aliases = {}
        self.bps = []
        self.reg_history = []
        self.regs = {}
        #self.x86reg_names = ["EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "EDI", "ESI"]
        self.current_address_val = "0x0"
        self.previous_address_val = self.current_address_val 
        self.current_address_str = 0
        self.previous_address_str = self.current_address_str
        self.memory_blocks = []
    
    def getRegs(self):
        return self.regs
    
    def add_pycmd_alias(self, name, alias):
        self.pycmds[alias] = name
    
    def setPreviousAddress(self):
        try:
            idc.SetColor(self.previous_address_val, idc.CIC_ITEM, 0xffffff)
        except:
            pass
        self.previous_address_str = self.current_address_str
        self.previous_address_val = self.current_address_val
        try:
            idc.SetColor(self.previous_address_val, idc.CIC_ITEM, 0xa0a0ff)
        except:
            pass
        
    def setCurrentAddress(self, addr):
        self.setPreviousAddress()
        self.current_address_str = IdabridgeUtils.guess_name(addr, regs=self.regs)
        self.current_address_val = IdabridgeUtils.guess_name(self.current_address_str)
        result = False
        try:
            result = idc.Jump(self.current_address_val)
            if result:
                idc.SetColor(self.current_address_val, idc.CIC_ITEM, 0xffa0a0)
                return result
        except:
            # might ask to load a file here?
            pass
        return False
    
    def getPreviousAddress(self):
        return (self.previous_address_val, self.previous_address_str)

        
    def getCurrentAddress(self):
        return (self.current_address_val, self.current_address_str)
    
    def platformGetRegisterNames(self):
        return self.reg.keys()

    def platformAddMemoryBlock(self, addr, data, id=0, **kargs):
        appname = IdabridgeUtils.guess_addr_by_name_expression(string.strip(), **kargs)
        kargs['appname'] = appname
        mb = MemoryBlock(addr, data=data, **kargs)
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
    
    def platformUpdateRegisters(self, regs):
        self.regs = regs
        for k,v in regs.items():
            self.regs[k] = v
        
    def platformGetRegisters(self, id=None):
        if not id is None:
            return self.reg_history[id]
        return self.regs
        
    def platformSetRegisters(self, regs):
        kargs = {'time':time()}
        self.regs = Registers(**kargs)
        for k,v in regs.items():
            self.regs[k] = v
        
    
    def platformSaveRegisters(self):
        self.reg_history.insert(0, self.regs)
    
        
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
            result = self.handlers['fail'](CMD_CLI, None, **kargs)
        else:
            result = self.execute_cmd(cmd_type, cmd_name, buffer, **kargs)
        return str(result)

    def handle_evt(self, cmd, args, **kargs):
        if kargs is None:
            kargs = {}
        return str(self.execute_cmd(CMD_EVT, cmd, args, **kargs))        

    def handle_cli(self, cmd, args, **kargs):
        if kargs is None:
            kargs = {}
        return str(self.execute_cmd(CMD_CLI, cmd, args, **kargs))
        
    def add_aliases(self, cmd_name, aliases):
        self.aliases[cmd_name] = cmd_name
        for alias in aliases:
            self.aliases[alias] = cmd_name
     
    def execute_cmd(self, cmd_type, cmd_name, data, **kargs):
        #print self.handlers.keys()
        # treat cmd as a pycmd by default or resolve if the command is a pycmd
        if cmd_name is None:
            kargs['reason'] = "Command name was None."
            # calling command directly
            return self.handlers['fail'](CMD_CLI, None, **kargs)
        if (cmd_name != "pycmd") and\
            ((cmd_name in self.aliases and self.aliases[cmd_name] in self.pycmds) or\
            (not cmd_name in self.aliases and not cmd_name in self.pycmds)):
            mydata = ""
            if cmd_name in self.aliases and\
                self.aliases[cmd_name] in self.pycmds and\
                self.aliases[cmd_name] != "pycmds":
                cmd_name = self.aliases[cmd_name]
                
            if isinstance(data, str):
                data = cmd_name+" "+data
                mydata = data
            elif isinstance(data, Buffer):
                buf = Buffer()
                buf.write_string(cmd_name)
                args = data.read_string()
                mydata = cmd_name +" "+args
                buf.write_string(args)
                data = buf
            is_pycmd = cmd_name in self.pycmds
            cmd_name = "pycmd"
            print "CMD in (%s), CMD passed to pycmd: %s"%(str(is_pycmd), mydata)
        if cmd_name in self.aliases:
            cmd_name = self.aliases[cmd_name]
        
        print "Final cmd_name: %s cmd_type: %d"%(cmd_name, cmd_type)
        handler = self.handlers[cmd_name]
        
        return handler.handle(cmd_type, data, **kargs)
        
    def platformGetImageBaseAddress(self):
        return idc.BeginEA()
        
    def platformPrintResult(self, results, cmd_name=None):
        if not cmd_name:
            cmd_name = ""
        else:
            cmd_name = cmd_name +"=> "
        idc.Message("Recv'd Result: %s"%(cmd_name+results))
    
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

    def platformAddBreakpoint(self, bp):
        idc.Message("In platform add breakpoint.  Attempting to add the following bps: %s\n"%(str(bp)))
        if not IdabridgeUtils.convert_str_to_numval(bp) is None:
            idc.Message("could not convert the bp to a numval.\n")
            return self.platformAddBreakpointByAddr(IdabridgeUtils.convert_str_to_numval(bp))
        return self.platformAddBreakpointByName(bp)
    
    def platformAddBreakpointByAddr(self, bp):
        if bp is None:
            return False
        bp_name = IdabridgeUtils.guess_name(bp)
        bp_addr = "0x%08x"%bp
        if bp_name == bp_addr:
            bp_name = ""
        self.bps.append(bp_addr+":"+bp_name)
        return True
    
    def platformAddBreakpointByName(self, bp_name):
        if bp_name is None:
            return False
        addr = IdabridgeUtils.guess_addr_by_name_expression(bp_name)
        if addr == idc.BADADDR:
            self.platformPrintResult("Can't Add BP by Name: %s"%bp_name)
            return False
        bp_addr = "0x%08"%addr
        self.bps.append(bp_addr+" : "+bp_name)
        return True
    
    def platformGetBreakpoints(self):
        # should make this more robust
        # support code and active, condition etc.
        bps = []
        for bp in self.bps:
            bps.append(bp.replace(" ",''))
        return bps
        
    def platformClearBreakpoints(self):
        # should make this more robust
        # support code and active, condition etc.
        self.bps = []
    
    def platformRemoveBreakpoint(self, bp):
        result = false
        if not IdabridgeUtils.convert_str_to_numval(bp) is None:
            result = self.platformRemoveBreakpointByAddr(bp)
            if not result and bp < len(self.bps):
                result = platformRemoveBreakpointById(self.bps)
        else:
            result = platformAddBreakpointByName(bp)
        return result
    
    def platformRemoveBreakpointById(self, bp_id):
        # should make this more robust
        # support code and active, condition etc.
        if len(self.bps) < bp_id:
            del self.bps[bp_id]
            return True
        raise Exception("BP position exceeds bp list length")
    
    def platformRemoveBreakpointByName(self, bp_name):
        # should make this more robust
        # support code and active, condition etc.
        cnt = 0
        while cnt < len(self.bps):
            if self.bps[cnt].split(":")[1].strip() == bp_name.strip():
                del self.bps[cnt]
                return True
        return False
    
    def platformRemoveBreakpointByAddr(self, bp_addr):
        # should make this more robust
        # support code and active, condition etc.
        bp_addr_val = IdabridgeUtils.convert_str_to_numval(bp_addr)
        cnt = 0
        while cnt < len(self.bps):
            addr = self.bps[cnt].split(":")[0].strip()
            addr_val = IdabridgeUtils.convert_str_to_numval(addr)
            if  addr_val == bp_addr_val:
                del self.bps[cnt]
                return True
        return False
        
# has the client thread built into it
class IdabridgeC(bridgecomms.IDAC, Idabridge):
    def __init__(self):
        idarserver.IDAC.__init__(self)
        idabridge.__init__(self)
    
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
    
    def setCurrentAddress(self, addr):
        self.previous_address_val = idc.Name(self.current_address_val)
        if isinstance(addr, int) or isinstance(addr, long):
            self.current_address_val = idc.Name(addr)
        else:
            self.current_address_val = "0x%08x"%addr
        
        if idc.Jump(addr):
            idc.SetColor(addr, idc.CIC_ITEM, 0xffa0a0)
            return True
        return False
        
    
    def getCurrentAddress(self, addr):
        x = convert_str_to_numval(addr)
        if x is None:
            return LocByName(self.current_address_val)
        return x
    
    
    def getRegisters(self, id=0):
        if id > 0:
            return self.reg_history[id]
        return self.regs
    
    def platformSetRegisters(self, regs):
        self.regs = regs
        self.reg_history.insert(0, regs)
