"""
A file full of bit twidling helpers
"""

import struct

MAX_WORD = 8 # Dont have any more than 64 bit archs

# Masks to use for unsigned anding to size
u_maxes = [ (2 ** (8*i)) - 1 for i in range(MAX_WORD+1) ]
u_maxes[0] = 0 # powers of 0 are 1, but we need 0

# Masks of just the sign bit for different sizes
sign_bits = [ (2 ** (8*i)) >> 1 for i in range(MAX_WORD+1) ]
sign_bits[0] = 0 # powers of 0 are 1, but we need 0

# Max *signed* masks (all but top bit )
s_maxes = [ u_maxes[i] ^ sign_bits[i] for i in range(len(u_maxes))]
s_maxes[0] = 0

# bit width masks 
b_masks = [ (2**i)-1 for i in range(MAX_WORD*8) ]
b_masks[0] = 0

def unsigned(value, size):
    """
    Make a value unsigned based on it's size.
    """
    # In python "&" will do abs value
    return value & u_maxes[size]

def signed(value, size):
    """
    Make a value signed based on it's size.
    """
    x = unsigned(value, size)
    if x & sign_bits[size]:
        x = (x - u_maxes[size]) - 1
    return x

def is_signed(value, size):
    x = unsigned(value, size)
    return bool(x & sign_bits[size])

def sign_extend(value, cursize, newsize):
    """
    Take a value and extend it's size filling
    in the space with the value of the high 
    order bit.
    """
    x = unsigned(value, cursize)
    if cursize != newsize:
        # Test for signed w/o the call
        if x & sign_bits[cursize]:
            delta = newsize - cursize
            highbits = u_maxes[delta]
            x |= highbits << (8*cursize)
    return x

def is_parity(val):
    s = 0
    while val:
        s ^= val & 1
        val = val >> 1
    return (not s)

parity_table = []
for i in range(256):
    parity_table.append(is_parity(i))

def is_parity_byte(bval):
    """
    An "optimized" parity checker that looks up the index.
    """
    return parity_table[bval & 0xff]

def lsb(value):
    return value & 0x1

def msb(value, size):
    if value & sign_bits[size]:
        return 1
    return 0

def is_signed_overflow(value, size):
    max = s_maxes[size]
    if value > max:
        return True
    if value < -max:
        return True
    return False

def is_unsigned_carry(value, size):
    umax = u_maxes[size]
    if value > umax:
        return True
    elif value < 0:
        return True
    return False

def is_aux_carry(src, dst):
    # FIXME this is only how to do it for add...
    dst = dst & 0xf
    src = src & 0xf
    if (dst + src) > 15:
        return True
    return False

le_fmt_chars = (None,"B","<H",None,"<L",None,None,None,"<Q")
be_fmt_chars = (None,"B",">H",None,">L",None,None,None,">Q")
def parsebytes(bytes, offset, size, sign=False, bigend=False):
    """
    Mostly for pulling immediates out of strings...
    """
    if size > 8:
        return slowparsebytes(bytes, offset, size, sign=sign, bigend=bigend)
    if bigend:
        f = be_fmt_chars[size]
    else:
        f = le_fmt_chars[size]
    if f == None:
        return slowparsebytes(bytes, offset, size, sign=sign, bigend=bigend)
    d = bytes[offset:offset+size]
    x = struct.unpack(f, d)[0]
    if sign:
        x = signed(x, size)
    return x

def slowparsebytes(bytes, offset, size, sign=False, bigend=False):
    if bigend:
        begin = offset
        inc = 1
    else:
        begin = offset + (size-1)
        inc = -1

    ret = 0
    ioff = 0
    for x in range(size):
        ret = ret << 8
        ret |= ord(bytes[begin+ioff])
        ioff += inc
    if sign:
        ret = signed(ret, size)
    return ret

def buildbytes(value, size, bigend=False):
    if bigend:
        f = be_fmt_chars[size]
    else:
        f = le_fmt_chars[size]
    if f == None:
        raise Exception("envi.bits.buildbytes needs slowbuildbytes")
    return struct.pack(f, value)

def byteswap(value, size):
    ret = 0
    for i in range(size):
        ret |= (value >> (8*i)) & 0xff
        ret = ret << 8
    return ret

hex_fmt = {
    1:"0x%.2x",
    2:"0x%.4x",
    4:"0x%.8x",
    8:"0x%.16x",
}

def hex(value, size):
    return hex_fmt.get(size) % value

def binary(binstr):
    '''
    Decode a binary string of 1/0's into a python number
    '''
    x = 0
    for c in binstr:
        x = (x << 1) + int(c)
    return x

