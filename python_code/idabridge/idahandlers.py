#from buffer import Buffer
from buffer import *
from basehandler import *
from idapython_aliases import *
from idabridgeutils import *
from binascii import hexlify
import time

import traceback, sys
try:
    import idc
    import idaapi
    import idautils
    import pywraps
except:
    print "unable to load the ida modules\nTry updating PYTHON_PATH"

#make sure to register handler in idabridge.py in the init_idabridge_cmd function


class pyeval(Handler):
    
    def __post_init__(self):
        self.aliases = ['pyeval','eval']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        code = string
        buffer = self.create_base_buffer(CMD_REQ)
        buffer.write_string(code)
        return self.return_data(buffer)#self.execute_python_eval(code)
    
    def execute_python_eval(self, string):
        result = eval(string)
        return result
        
    def req(self, buffer, **kargs):
        code = buffer.read_string()
        #print "Executing Code: %s"%(code)
        result = self.parent.platformEvalString(code)
        #print "Result of Executing Code: %s"%(result)
        buffer = self.create_base_buffer(CMD_RES)
        buffer.write_string(str(result))
        return self.return_data(buffer)
    
    def rsp(self, buffer, **kargs):
        # debugger specific for handling the response?
        string = buffer.read_string()
        idc.Message("pyeval: %s"%string)
        return self.return_data(True)

    
class rebase(Handler):
    
    def __post_init__(self):
        self.aliases = ['rebase']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        idc.Message("Handling a rebase command from the cli!")
        return self.return_data(self.create_base_buffer(CMD_REQ))
    
    def req(self, buffer, **kargs):
        return self.rsp(buffer)
    
    def rsp(self, buffer, **kargs):
        idc.Message("Handling a rebase command from the rsp!\n")
        result = True
        #try:
        addr = buffer.read_string()
        #idc.Message("In rebase call: " +str(addr))
        rebase_to_addr = IdabridgeUtils.convert_str_to_numval(addr)
        current_ea = idc.ScreenEA()
        c_base_addr = idc.FirstSeg()
        r_base_diff = rebase_to_addr - c_base_addr
        idc.Message("instanceof(rebase_to_addr, str) == %s rebase_to_addr: %s Got: %s)"%(isinstance(rebase_to_addr, str), rebase_to_addr, addr))
        idaapi.rebase_program(r_base_diff, idc.MSF_FIXONCE)
        idc.AnalyseArea(idc.MinEA(),idc.MaxEA())
        new_ea = rebase_to_addr + ( current_ea - c_base_addr)
        idc.Jump(new_ea)
        result = True
        #except:
        #    pass
        return self.return_data(result)
        
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
        #print "In pycmd handler"
        if len(string) == 0:
            return self.return_data(False)
        cmd = string.split()[0]
        args = ""
        if len(string.split()) > 0:
            args = " ".join(string.split()[1:])
        buffer = self.create_base_buffer(CMD_REQ, "pycmd")
        buffer.write_string(cmd)
        buffer.write_string(args)
        return self.return_data(buffer)
        
    def req(self, buffer, **kargs):
        cmd = buffer.read_string()
        args = buffer.read_string()
        code = "%s(%s)"%(cmd,args)
        results = self.parent.platformEvalString(code)
        buffer = self.create_base_buffer(CMD_RSP, "pycmd")
        buffer.write_string(code)
        buffer.write_string(str(results))
        return self.return_data(buffer)
        
    def rsp(self, buffer, **kargs):
        cmd = buffer.read_string()
        result = buffer.read_string()
        self.parent.platformPrintResult(result, cmd)
        return self.return_data(True)
        
# broken neeeds repair.  not sure why commands
# are execed but inaccessible after being execed
# may have something to do with name spaces... worked before :(
class pyadd(Handler):
    def __post_init__(self):
        self.aliases = ['add_pycmd','pyadd']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        if len(string) == 0:
            return self.return_data(False)
        cmd = string.split()[0]
        args = " ".join(string.split()[1:])
        result = self.parent.platformExecString(args)
        idc.Message(args)
        if result:
            idc.Message("Adding the following cmd: "+cmd+"\n")
            self.parent.add_pycmd_alias(cmd, cmd)
        return self.return_data(result)
        
    def req(self, buffer, **kargs):
        cmd = buffer.read_string()
        args = buffer.read_string()
        result = self.parent.platformExecString(args)
        if result:
            self.parent.add_pycmd_alias(cmd, cmd)
        buffer = self.create_base_buffer(CMD_RSP, "pyadd")
        buffer.write_string(cmd)
        buffer.write_string(str(result))
        return self.return_data(buffer)
       
# TODO: Not tested.  
class python(Handler):
    def __post_init__(self):
        self.aliases = ['python']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def execute_python(self, code):
        result = False
        try:
            exec(code)
            result = True
        except:
            pass
        return result    
    
    def cli(self, string, **kargs):
        code = string
        return self.parent.platformExecString(code)
        
    def req(self, buffer, **kargs):
        code = buffer.read_string()
        result = self.parent.platformExecString(code)
        buffer = self.create_base_buffer(CMD_RES, "python")
        buffer.write_string(str(result))
        return self.return_data(buffer)
        
        


class breakc(Handler):
    def __post_init__(self):
        self.aliases = ['bphit','break','stop','b','br']
        # break is a python keyword, so i need to work around that
        self.parent.unregister_cmd(self)
        self.cmd_name = "break"
        self.parent.register_cmd(self)
        self.parent.add_aliases(self.cmd_name, self.aliases)
           
    def cli(self, string, **kargs):
        tid = self.get_tid(string)
        buffer = self.create_base_buffer(CMD_REQ, "break")
        buffer.write_string("0x%08x"%tid)
        return self.return_data(buffer)
    
    def req(self, buffer, **kargs):
        addr = buffer.read_string()
        kargs['regs'] = self.parent.getRegs()
        addr = IdabridgeUtils.guess_addr_by_name_expression(addr, **kargs)
        print "Handled a break command: %s"%str(addr)
        if addr:
            #print "Handled a break command: %s"%str(addr)
            return self.parent.setCurrentAddress(addr)
        return self.return_data(False)
        
    def rsp(self, buffer, **kargs):
        return self.req(buffer)

#class bphit(Handler):
#    def __post_init__(self):
#        # break is a python keyword, so i need to work around that
#        self.aliases = ['bphit']
#        self.cmd_name = "bphit"
#        self.parent.register_cmd(self)
#        self.parent.add_aliases(self.cmd_name, self.aliases)
#                
#    def req(self, buffer, **kargs):
#        addr = buffer.read_string()
#        addr = IdabridgeUtils.convert_str_to_numval(addr)
#        print "Handled a break command: %s"%str(addr)
#        if addr:
#            return self.parent.setCurrentAddress(addr)
#        return self.return_data(False)
#        
#    def rsp(self, buffer, **kargs):
#        return self.req(buffer)

        
class resume(Handler):
    def __post_init__(self):
        self.aliases = ['resume','continue','go','g']
        # break is a python keyword, so i need to work around that
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def cli(self, string, **kargs):
        tid = self.get_tid(string)
        idc.Message("Tid value is : 0x%08x"%tid)
        buffer = self.create_base_buffer(CMD_REQ)
        buffer.write_string("0x%08x"%tid)
        return self.return_data(buffer)
        
            
class rabp(Handler):
    def __post_init__(self):
        self.aliases = ['rabp']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)  
    
    def cli(self, string, **kargs):
        if len(string.strip()) == 0:
            return
        kargs = {'regs':self.parent.getRegs()}
        addr_val = IdabridgeUtils.guess_addr_by_name_expression(string.strip(), **kargs)
        if addr_val == idc.BADADDR:
            self.parent.platformPrintResult("Unable to resolve: %s"%string)
            return self.return_data(False)
        buffer = self.create_base_buffer(CMD_RES)
        buffer.write_string(string.strip())
        buffer.write_string("0x%08x"%addr_val)
        return self.return_data(buffer)
            
    def req(self, buffer, **kargs):
        name = buffer.read_string()
        kargs = {'regs':self.parent.getRegs()}
        addr_val = IdabridgeUtils.guess_addr_by_name_expression(name.strip(), **kargs)
        buf = Buffer()
        buffer = self.create_base_buffer(CMD_RES)
        buffer.write_string(name.strip())
        buffer.write_string("0x%08x"%addr_val)
        return self.return_data(buffer)
        
        
class writemem(Handler):
    def __post_init__(self):
        self.aliases = ['writemem','write_mem','wm']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
        
    def cli(self, string):
        buffer = self.create_base_buffer(CMD_REQ)
        buffer_args = ""
        if len(string.split(" ")) < 2:
            idc.Message("writemem: <addr> <string>, ex: wm _main \\x90\\x90AAAA\n or wm _main '''1010'''*8\n")
            return self.return_data(False)
        
        addr = string.split(" ")[0]
        kargs = {'regs':self.parent.getRegs()}
        addr_val = IdabridgeUtils.guess_addr_by_name_expression(addr, **kargs)
        
        data = " ".join(string.split(" ")[1:])
        # if the byte is '''<string>''' * <repeat>
        if data.find('\'\'\'') == 0 and \
            data.find('\'\'\'',3) > 3 and \
            data.find("*", data.find('\'\'\'',3)) > data.find('\'\'\'',3):
            data = eval(data)
        #idc.Message("addr_val: 0x%08x\n"%(addr_val))
        #idc.Message("data: %s len(data): %d hexlified: %s\n"%(repr(data), len(data), hexlify(data)))
        #toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
        #do any pre-processing on the args
        buffer.write_string("0x%08x"%addr_val)
        buffer.write_string(data)
        return self.return_data(buffer)
        
    def req(self, buffer):
        print "got a writemem req\n"
        # Byte ea,
        print "buffer str = %s" % buffer.read_string()
        return self.return_data(True)

    def rsp(self, buffer):
        return self.return_data(True)
    
class readmem(Handler):
    def __post_init__(self):
        self.aliases = ['readmem','read_mem','rem']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string):
        #do any pre-processing on the args
        if len(string.strip()) == 0:
            return self.return_data(False)
        cnt = '1'
        addr = string.strip().split()[0]
        if len(string.strip().split()) > 1 and cnt.isdigit():
            cnt = string.strip().split()[1]
        kargs = {'regs':self.parent.platformGetRegisters()}
        addr_val = IdabridgeUtils.guess_addr_by_name_expression(addr, **kargs)
        buffer = self.create_base_buffer(CMD_REQ)
        
        if addr_val != idc.BADADDR:
            addr = "0x%08x"%addr_val
        
        buffer.write_string(addr)
        buffer.write_string(cnt)
        return self.return_data(buffer)
        
    def req(self, buffer):
        addr = buffer.read_string()
        cnt = buffer.read_string()
        
        result = "error bad values"
        buffer = self.create_base_buffer(CMD_RES)
        
        kargs = {'regs':self.parent.platformGetRegisters()}
        addr_val = IdabridgeUtils.guess_addr_by_name_expression(addr.strip(), **kargs)
        
        if addr_val is None or addr_val > idc.MaxEA() or addr_val < idc.MinEA():
            buffer.write_string(addr)
            buffer.write_string(result)
            return self.return_data(buffer)
        else:
            addr = "0x%08x"%addr_val
            
        cnt = IdabridgeUtils.convert_str_to_numval(cnt)
        if cnt is None:
            cnt = 1
        result = []
        for i in xrange(0,cnt):
            result.append(chr(idc.Byte(addr_val+i)))
        result = "".join(result)
        t = "%f"%time.time()
        
        buffer.write_string(addr)
        buffer.write_string(result)
        buffer.write_string(t)
        return self.return_data(buffer)

    def rsp(self, buffer):
        kargs = {}
        addr = buffer.read_string()
        data = buffer.read_string()
        t = buffer.read_string()
        if addr is None:
            return self.return_data(False)
        if data is None:
            return self.return_data(False)
        if not t is None:
            kargs['time'] = t
        kargs['regs'] = self.parent.platformGetRegisters()
        addr_val = IdabridgeUtils.guess_addr_by_name_expression(string.strip(), **kargs)
        self.platformAddMemoryBlock(addr_val, data, **kargs)
        return self.return_data(True)
        
        
# TODO: Not tested.          
class getbps(Handler):
    
    def __post_init__(self):
        self.aliases = ['getbps','gbps']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "getbps")
        return self.return_data(buffer)
        
    def req(self, buffer, **kargs):
        bp_str = ",".join(self.parent.platformGetBreakpoints())
        buf = self.create_base_buffer(CMD_REQ, "setbps")
        buf.write_string(bp_str)
        return self.return_data(buf)
            
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
        return self.return_data(buffer)
        
    def req(self, buffer, **kargs):
        idc.Message("Handling a setbps REQ.\n")
        breakpoints = buffer.read_string()
        bp_list = [bp for bp in breakpoints.split(',')]
        #self.parent.platformClearBreakpoints()
        # ignore the names provided by the debugger at the moment
        for bp in bp_list:
            if bp.strip() == "":
                continue
            bpaddr = bp.split(":")[0]
            idc.Message("Bp str val: %s\n"%bpaddr)
            self.parent.platformAddBreakpoint(bpaddr)
        return self.return_data(True)
    
class getregs(Handler):
    def __post_init__(self):
        self.aliases = ['getregs','gr','gregs']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "getregs")
        return self.return_data(buffer)
                
    def req(self, buffer, **kargs):
        regs = self.parent.platformGetRegisters()
        regs_str = ""
        if not regs is None:
            regs_str = ",".join(["%s:0x%08x"%(reg,regs[reg]) for reg in regs])
        buffer = self.create_base_buffer(CMD_RSP, "getregs")
        buffer.write_string(regs_str)
        return self.return_data(buffer)
            


class setregs(Handler):
    def __post_init__(self):
        self.aliases = ['setregs','sr','sregs']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        buffer = self.create_base_buffer(CMD_REQ, "setregs")
        regs = self.parent.platformGetRegisters()
        regs_str = ""
        if not regs is None:
            regs_str = ",".join(["%s:0x%08x"%(reg,regs[reg]) for reg in regs])
        buffer.write_string(regs_str)
        return self.return_data(buffer)
                
    def req(self,buffer):
        regs_str = buffer.read_string()
        regs = {}
        for reg_val in regs_str.strip().split(','):
            #idc.Message("handling regs_str: %s\n"%str(reg_val))
            if reg_val.strip() == "":
                continue
            reg,val = reg_val.strip().split(":")
            #idc.Message("reg: %s val: %s"%(reg, val))
            ival = IdabridgeUtils.convert_str_to_numval(val)
            if ival is None:
                regs[reg] = 0
            else:
                regs[reg] = ival
        self.parent.platformSetRegisters(regs)
        return self.return_data(True)            
