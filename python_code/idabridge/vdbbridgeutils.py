#from buffer import Buffer
from buffer import *
from basehandler import *
from idapython_aliases import *

BADADDR = 0xFFFFFFFF
    
class VdbbridgeUtils:
    def __init__(self):
        pass
    
    @classmethod
    def guess_addr_by_name_expression(cls, value, **kargs):
        if kargs is None:
            kargs = {}
        if value.find('+') > -1:
            values = [(i, kargs) for i in value.split('+')]
            results = map(cls.guess_addr_val, values)
            if BADADDR in set(results):
                return BADADDR
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
        trace = kargs.get('trace', None)
        regs = kargs.get('regs', None)
        num_val = None
        _val = value

        if not trace is None and regs is None:
            regs = trace.getRegisters()
        if value in regs:
            num_value = regs[value]
        # add a name resolution layer
        
        # adding the 'h' on the end will not harm resolution
        # but its necessary, because IDA GetFuncOffset does not 
        # distinguish b/n hex or dec
        if value[-1] != 'd' and value.find('0x') == -1 and value.find('h') == -1:
            _val = _val+'h'
        # guess #2 is it a hex or decimal 
        num_val = cls.convert_str_to_numval(_val)
        # if we got a number, add it, other wise fail
        if not num_val is None and num_val != BADADDR:
            return num_val
        # guess final guess see if it is a name that can be resolved
        try:
            return trace.parseExpression(value)
        except:
            pass
        return BADADDR
        
    
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
    def guess_name(cls, addr):
        '''
        trys to get the named value by function and offset
        other wise return %segment%:addr
        '''
        addr = cls.convert_str_to_numval(addr)
        name = ""
        try:
            name = trace.getSymNameDeltaByAddr(addr)
        except:
            name = None
        return "0x%08x"%addr