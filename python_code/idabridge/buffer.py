'''
Buffer class based on  Chris Eagle's buffer class 

Author: Adam Pridgen <adam.pridgen@ [praetorian.com || thecoverofnight.com]>
'''

import sys
import struct
from binascii import hexlify,unhexlify

get_signed_long = lambda x: struct.unpack(">q",struct.pack(">Q", x))[0]
get_unsigned_long = lambda x: struct.unpack(">Q",struct.pack(">q", x))[0]

get_signed_int = lambda x: struct.unpack(">i",struct.pack(">I", x))[0]
get_unsigned_int = lambda x: struct.unpack(">I",struct.pack(">i", x))[0]

get_signed_short = lambda x: struct.unpack(">h",struct.pack(">H", x))[0]
get_unsigned_short = lambda x: struct.unpack(">H",struct.pack(">h", x))[0]

get_signed_byte = lambda x: struct.unpack(">b",struct.pack(">B", x))[0]
get_unsigned_byte = lambda x: struct.unpack(">B",struct.pack(">b", x))[0]


unpack_signed_long = lambda x: struct.unpack(">q",x)[0]
unpack_unsigned_long = lambda x: struct.unpack(">Q",x)[0]

unpack_signed_int = lambda x: struct.unpack(">i",x)[0]
unpack_unsigned_int = lambda x: struct.unpack(">I",x)[0]

unpack_signed_short = lambda x: struct.unpack(">h",x)[0]
unpack_unsigned_short = lambda x: struct.unpack(">H",x)[0]

unpack_signed_byte = lambda x: struct.unpack(">b",x)[0]
unpack_unsigned_byte = lambda x: struct.unpack(">B",x)[0]


class IParser:
    def __init__(self):
        pass
    def parse_message(self, buffer):
        pass
    def build_message(self, buffer):
        pass


        
class Buffer:
    def __init__(self, data=None,hexlified=False):
        self.data = ""
        # rptr is required, 
        # so we can track reading
        self.rptr = 0
        # wptr is not necessary, 
        # buffer can be dynamic
        #self.wptr = 0
        # added this for passing from c++ to here
        if data and hexlified:
            #print data
            data = unhexlify(data)
            #print repr(data)
            
        if data:
            self.append(data)
            
    def __len__(self):
        return len(self.get_buf())
    
    def __plus__(self, data):
        self.append(str(data))
    
    def unload_module(self):
        del sys.modules['Buffer']
    
    def append(self, data):
        self.data += data
    
    def read(self, length):
        s = None
        if self.rptr+length <= len(self.data):
            s = self.data[self.rptr:self.rptr+length]
            self.rptr += length
        return s
    
    def read_long(self):
        long_val = None
        if self.rptr+8 <= len(self.data):
            long_val = struct.unpack(">Q",self.data[self.rptr:self.rptr+8])[0]
            self.rptr += 8
        return long_val
    
    def read_int(self):
        int_val = None
        if self.rptr+4 <= len(self.data):
            int_val = struct.unpack(">I",self.data[self.rptr:self.rptr+4])[0]
            self.rptr += 4
        return int_val
    
    def read_short(self):
        short_val = None
        if self.rptr+2 <= len(self.data):
            short_val = struct.unpack(">H",self.data[self.rptr:self.rptr+2])[0]
            self.rptr += 2
        return short_val
        
    def read_byte(self):
        byte_val = None
        if self.rptr+1 <= len(self.data):
            byte_val = struct.unpack(">B",self.data[self.rptr:self.rptr+1])[0]
            self.rptr += 1
        return byte_val
        
    def read_float(self):
        float_val = None
        if self.rptr+4 <= len(self.data):
            float_val = struct.pack('>f',self.data[self.rptr:self.rptr+4])[0]
            self.rptr += 4
        return float_val
        
    
    def read_string(self):
        sz = self.read_int()
        return self.read(sz)
        
    def rewind(self, rew):
        # todo make sure this 
        # matches up
        if rew <= self.rptr:
            self.rptr -= rew
            return True
        return False
        
    def reset(self):
        self.data = ""
        self.rptr = 0
    
    def write(self, data, length=None):
        if length is None or length > len(data):
            self.data += data
            return True
        if length <= len(data):
            self.data += data[0:length]
            return True
        return False
    
    def write_long(self, data):
        if not isinstance( data, long):
            return False
        if data < 0:
            # cant pack unsigned values, so we force it
            data = struct.pack(">q",data)
            data = struct.unpack(">Q",data)[0]
        self.data += struct.pack(">Q",data)
        return True
    
    def write_int(self, data):
        if not isinstance( data, int):
            return False
        if data < 0:
            # cant pack unsigned values, so we force it
            data = struct.pack(">i",data)
            data = struct.unpack(">i",data)[0]
        self.data += struct.pack(">I",data)
        return True
    
    def write_short(self, data):
        if not isinstance( data, int):
            return False
        if data < 0:
            # cant pack unsigned values, so we force it
            data = struct.pack(">h",data)
            data = struct.unpack(">H",data)[0]
        self.data += struct.pack(">H",data)
        return True
    
    def write_byte(self, data):
        if not isinstance( data, int):
            return False
        if len(data) < 0:
            # cant pack unsigned values, so we force it
            data = struct.pack(">b",data)
            data = struct.unpack(">B",data)[0]
        self.data += struct.pack(">B",data)
        return True
    
    def read_float(self, data):
        if isinstance(data, float):
            self.data += struct.pack('>f',data)
            return True
        return False
        
    def write_string(self, string):
        self.write_int(len(string))
        return self.write(string)
        
    def make_buffer_sendable(self):
        data = self.data
        self.reset()
        self.write_int(len(data)+4)
        self.append(data)
        
    def get_buf(self):
        return self.data

    def get_hexlified_buf(self):
        return hexlify(self.data)
    
    def set_hexlified_buf(self):
        return self.append(unhexlify(data))
        
    def set_buf(self, data):
        self.append(data)
        
    def get_size(self):
        return len(self.data)

    def __str__(self):
        return self.get_buf()