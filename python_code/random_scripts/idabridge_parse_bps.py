import idc
import idaapi
import idautils

idabridge_bps = []
idabridge_regs = {}

def parse_idabridge_bps(bplist):
    nbplist = []
    for i in bplist:
        if isinstance(i, int):
            nbplist.append(hex(i))
        else:
            if idc.LocByName(i) != idc.BADADDR:
                nbplist.append(hex(idc.LocByName(i)))
    return nbplist
    
def parse_bps():
    global idabridge_bps 
    return parse_idabridge_bps(idabridge_bps)