import sys
import idabridge


# minor hack for 64 bit win7, _socket does not properly load, grrr
#Python26_32bit_dir = "Python26_32bit"
#Python26_64bit_dir = "Python26"
#found_32bit_dir = False
#new_path = []
#for i in sys.path:
#    s = set(i.split("\\"))
#    if Python26_32bit_dir in s:
#        found_32bit_dir = True
#    if Python26_64bit_dir in s:
#        continue
#    new_path.append(i)
#if found_32bit_dir:
#    pass
#    sys.path = new_path
#print sys.path

__all__ = ['buffer','idacomms','idahandlers','idabridge','idabridgeutils']

# make this available in the idapython namespace
ib = idabridge.Idabridge()
idabridge.init_idabridge_cmds(ib)
idabridge = ib