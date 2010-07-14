"""
Home of the i386 module's register specs/code.
"""
import envi.registers as e_reg

# Eflags bit masks
EFLAGS_CF = 1 << 0
EFLAGS_PF = 1 << 2
EFLAGS_AF = 1 << 4
EFLAGS_ZF = 1 << 6
EFLAGS_SF = 1 << 7
EFLAGS_TF = 1 << 8
EFLAGS_IF = 1 << 9
EFLAGS_DF = 1 << 10
EFLAGS_OF = 1 << 11

i386regs = [
    ("eax",32),("ecx",32),("edx",32),("ebx",32),("esp",32),("ebp",32),("esi",32),("edi",32),
    #FIXME are these 64?
    ("mm0",64),("mm1",64), ("mm2",64), ("mm3",64), ("mm4",64), ("mm5",64), ("mm6",64), ("mm7",64),
    # SIMD registers
    ("xmm0",128),("xmm1",128),("xmm2",128),("xmm3",128),("xmm4",128),("xmm5",128),("xmm6",128),("xmm7",128),
    # Debug registers
    ("debug0",32),("debug1",32),("debug2",32),("debug3",32),("debug4",32),("debug5",32),("debug6",32),("debug7",32),
    # Control registers
    ("ctrl0",32),("ctrl1",32),("ctrl2",32),("ctrl3",32),("ctrl4",32),("ctrl5",32),("ctrl6",32),("ctrl7",32),
    # Test registers
    ("test0", 32),("test1", 32),("test2", 32),("test3", 32),("test4", 32),("test5", 32),("test6", 32),("test7", 32),
    # Segment registers
    ("es", 16),("cs",16),("ss",16),("ds",16),("fs",16),("gs",16),
    # FPU Registers
    ("st0", 128),("st1", 128),("st2", 128),("st3", 128),("st4", 128),("st5", 128),("st6", 128),("st7", 128),
    # Leftovers ;)
    ("eflags", 32), ("eip", 32),
]

def getRegOffset(regs, regname):
    # NOTE: dynamically calculate this on import so we are less
    # likely to fuck it up...
    for i,(name,width) in enumerate(regs):
        if name == regname:
            return i
    raise Exception("getRegOffset doesn't know about: %s" % regname)

# Setup REG_EAX and the like in our module
l = locals()
e_reg.addLocalEnums(l, i386regs)

i386meta = [
    ("ax", REG_EAX, 0, 16),
    ("cx", REG_ECX, 0, 16),
    ("dx", REG_EDX, 0, 16),
    ("bx", REG_EBX, 0, 16),
    ("sp", REG_ESP, 0, 16),
    ("bp", REG_EBP, 0, 16),
    ("si", REG_ESI, 0, 16),
    ("di", REG_EDI, 0, 16),

    ("al", REG_EAX, 0, 8),
    ("cl", REG_ECX, 0, 8),
    ("dl", REG_EDX, 0, 8),
    ("bl", REG_EBX, 0, 8),

    ("ah", REG_EAX, 8, 8),
    ("ch", REG_ECX, 8, 8),
    ("dh", REG_EDX, 8, 8),
    ("bh", REG_EBX, 8, 8),

    # FIXME more flags... (here and amd64)
    ("TF", REG_EFLAGS, 8, 1),
]

e_reg.addLocalMetas(l, i386meta)


class i386RegisterContext(e_reg.RegisterContext):
    def __init__(self):
        e_reg.RegisterContext.__init__(self)
        self.loadRegDef(i386regs)
        self.loadRegMetas(i386meta)
        self.setRegisterIndexes(REG_EIP, REG_ESP)

