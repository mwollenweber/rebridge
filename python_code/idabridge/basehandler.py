from buffer import *
import threading

CMD_REQ = 0
CMD_RES = 1    
CMD_RSP = 1    
CMD_CLI = 2
CMD_EVT = 3

BADADDR = 0xFFFFFFFF


    
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
    

class EventThread(threading.Thread):
    def __init__(self, parent, cmd, *args, **kargs):
        threading.Thread.__init__(self)
        self.parent = parent
        self.cmd = cmd
        self.args = args
        self.kargs = kargs
        self.start()
        
    def run(self):
        self.parent.handle_evt(self.cmd, *self.args, **self.kargs)

class CmdThread(threading.Thread):
    def __init__(self, parent, cmd_type, data, **kargs):
        threading.Thread.__init__(self)
        self.parent = parent
        self.data = data
        self.cmd_type = cmd_type
        self.kargs = kargs

        
    def run(self):
        cmd_type = self.cmd_type 
        if cmd_type == CMD_REQ:
            return self.req(data, **kargs)
        elif  cmd_type == CMD_RSP:
            return self.rsp(data, **kargs)
        elif  cmd_type == CMD_CLI:
            return self.cli(data, **kargs)
        elif  cmd_type == CMD_EVT:
            return self.evt(data, **kargs)

        
        self.parent.handle_evt(self.cmd, self.args, **self.kargs)        
        
class Handler:
    def __init__(self, *arg, **kargs):
        self.parent = kargs.get("parent", None)
        if self.parent is None:
            raise Exception("Handler needs a parent to be instantiated!")
        
        self.cmd_name = self.get_classname()
        self.parent.register_cmd(self)
        self.__post_init__()
    
    def __post_init__(self):
        # sub-classes will implement this 
        pass
    
    def requirements(self):
        # base fucntion rval
        return True


    def get_tid(self, string):
        tidv = int("0xFFFFFFFF",16)
        if len(string) > 0:
            tid = string.split()[0]
            tidv = self.convert_str_to_numval(tid)
            if tidv is None:
                tidv = 0xFFFFFFFF
        return tidv
    
    def convert_str_to_numval(self, val):
        if isinstance(val, int) or\
            isinstance(val, long):
             return val
        try:
            if val.strip().find("0x") > -1 and val.strip().find("0x") < 2:
                return int(val.replace("h",'').strip(),16)
            elif (val.strip()[-1] == "h" and len(val.strip()) > 1):
                return int(val.strip()[:-1],16)
            elif val.strip().isdigit():
                return int(val.strip())
            elif(val.strip()[-1] == 'd' and (val.strip()[:-1]).isdigit() and len(len(val.strip()) > 1)):
                return int(val.strip()[:-1])
        except:
            pass
        return None
    

        
    def get_name(self):
        return self.cmd_name
    
    def get_classname(self):
        name = str(self.__class__).split(".")[-1]
        name = name.split()[0]
        return name
    
    def create_base_buffer(self, cmd_type, cmd_name=None):
        if cmd_name is None:
            cmd_name = self.cmd_name
        buffer = Buffer()
        buffer.write_int(cmd_type)
        buffer.write_string(cmd_name)
        return buffer

    def handle_cli(self, args, **kargs):
        cmd = args.split()[0]
        data = " ".join(args.split()[1:])
        return self.handle(CMD_CLI, args, **kargs)
    # data may be a string (cli), buffer (net msg), or evt, trace (evt)
    def handle(self, cmd_type, data, **kargs):
        # TODO enable and test this threading to see if it will work
        # currently it will not work for idabridge, because
        # the result is passed back through C++, but it should 
        # work in python
        #executing_events.append(CmdThread(self, cmd_type, **kargs))
        if cmd_type == CMD_REQ:
            return self.req(data, **kargs)
        elif  cmd_type == CMD_RSP:
            return self.rsp(data, **kargs)
        elif  cmd_type == CMD_CLI:
            return self.cli(data, **kargs)
        elif  cmd_type == CMD_EVT:
            return self.evt(data, **kargs)
        else:
            Exception("Bad command type...naughty man mr. seinfeld")
        
    def cli(self, buffer, **kargs):
        return True
    
    
    def rsp(self, buffer, **kargs):
        return True
    
    def req(self, buffer, **kargs):
        return True
	
    def evt(self, evt, **kargs):
        return True
    
    def build_pc_addr_buf(self, cmd_type, cmd_name=None):
        if cmd_name is None:
            cmd_name = self.cmd_name
        buffer = self.create_base_buffer(cmd_type, cmd_name)
        addr = 0x0
        #TODO: implement self.parent.platformGetImageBaseAddress()
        addr = self.parent.platformGetImageBaseAddress()
        buffer.write_string(hex(addr))
        return buffer
    
    def return_data(self, data):
        if isinstance(data, Buffer):
            return "<BUFFER>:"+data.get_buf()
        return str(data)
    
    
    def send_error_buf(self, cmd_type, cmd_name=None, error=0):
        if cmd_name is None:
            cmd_name = self.cmd_name
        buffer = self.create_base_buffer(cmd_type, cmd_name)
        buffer.write_string(str(error))
        return buffer
        
    def build_cmd_call_str(self, cmd, args):
        string = "%s(%s)"%(cmd,args)
        idc.Message("Performing the following call: "+string+"\n")
        return self.execute_python_eval(string)
        

class fail(Handler):
    
    def __post_init__(self):
        self.aliases = ['fail']
        #print self.aliases
        self.parent.add_aliases(self.cmd_name, self.aliases)
    
    def cli(self, string, **kargs):
        return self.return_data(kargs.get("reason", "Failed: reason unknown."))
        
        