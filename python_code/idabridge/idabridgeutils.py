#from buffer import Buffer
from buffer import *
from basehandler import *
from idapython_aliases import *

try:
    import idc
    import idaapi
    import idautils
    import pywraps
except:
    print "unable to load the ida modules"
    
    
class IdabridgeUtils:
    def __init__(self):
        pass
    
    @classmethod
    def guess_addr_by_name_expression(cls, value, **kargs):
        if kargs is None:
            kargs = {}
        if value.find('+') > -1:
            values = [(i, kargs) for i in value.split('+')]
            results = map(cls.guess_addr_val, values)
            if idc.BADADDR in set(results):
                return idc.BADADDR
            return sum(results)
        return cls.guess_addr_val((value, kargs))
            
    
    @classmethod
    def guess_addr_val(cls, value):
        '''
        value MUST be a tuple with a (str, dict)
        the dict should contain registers
        
        Note: could not get kargs to implant into a tuple
        '''
        kargs = value[1]
        value = value[0]

        # guess #0 is the value a register?
        regs = kargs.get('regs', {})
        if value in regs:
            num_value = regs[value]
        seg_names = set([idc.SegName(i) for i in idautils.Segments()])
        num_val = None
        _val = value
        # guess #1 is the name representative of a segment:address
        if value.find(":") > 0 and value.split(":")[0] in seg_names:
            num_val = cls.convert_str_to_numval(value.split(":")[1]+"h")
            if num_val is None:
                return idc.BADADDR
            return num_val
        # adding the 'h' on the end will not harm resolution
        # but its necessary, because IDA GetFuncOffset does not 
        # distinguish b/n hex or dec
        elif value[-1] != 'd' and value.find('0x') == -1 and value.find('h') == -1:
            _val = _val+'h'
        # guess #2 is it a hex or decimal 
        num_val = cls.convert_str_to_numval(_val)
        # if we got a number, add it, other wise fail
        if not num_val is None and num_val != idc.BADADDR:
            return num_val
        # guess final guess see if it is a name that can be resolved
        # there is also a bug in idc.LocByName where it may not report names in segments other than .text
        return idc.LocByName(value)
    
    @classmethod
    def convert_str_to_numval(cls, val):
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
    
    
    @classmethod
    def guess_name(cls, addr, **kargs):
        '''
        trys to get the named value by function and offset
        other wise return %segment%:addr
        '''
        addr = cls.convert_str_to_numval(addr)
        name = ""
        try:
            name = idc.GetFuncOffset(addr)
        except:
            name = None
        if not name is None and name != "":
            return name
        try:
            name = idc.SegName(addr)
        except:
            name = None            
        if not name is None and name != "":
            return name+":%08x"%addr
        return "0x%08x"%addr