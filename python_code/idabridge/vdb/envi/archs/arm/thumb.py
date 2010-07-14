
import envi.bits as e_bits
import envi.bintree as e_btree

import envi.archs.arm.disasm as arm_dis
import envi.archs.arm.regs as arm_reg

thumb_32 = [
        binary('11101'),
        binary('11110'),
        binary('11111'),
]

class oper:


class imm:
    def __init__(self, width, shift):
        self.width = width
        self.shift = shift

class reg:
    def __init__(self, width, shift):

O_REG = 0
O_IMM = 1

def shmaskval(value, shval, mask)
    return (value >> shval) & mask

class simpleops:
    def __init__(self, *operdef):
        self.operdef = operdef

    def __call__(self, va, value):
        ret = []
        for otype, shval, mask in self.operdef:
            oval = shmaskval(value, shval, mask)

            ret.append( (value >> shval)

imm5_rm_rd  = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_IMM, 6, 0x1f))
rm_rn_rd    = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_REG, 6, 0x7))
imm3_rn_rd  = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_IMM, 6, 0x7))
imm8_rd     = simpleops((O_REG, 8, 0x7), (O_IMM, 0, 0xff))
rm_rd       = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7))
rn_rdm      = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7))
rm_rdn      = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7))
rm_rd_imm0  = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_IMM, 0, 0))
rm4_shift3  = simpleops((O_REG, 3, 0xf))
rm_rn_rt    = simpleops((O_REG, 0, 0x7), (O_REG, 3, 0x7), (O_REG, 6, 0x7))

sh4_imm1    = simpleops((O_IMM, 3, 0x1))

def d1_rm4_rd3(va, value):
    # 0 1 0 0 0 1 0 0 DN(1) Rm(4) Rdn(3)
    rdbit = shmaskval(value, 4, 0x8)
    rd = shmaskval(value, 0, 0x7) + rdbit
    rm = shmaskval(value, 3, 0xf)
    return ArmRegOper(rd),ArmRegOper(rn)

def rm_rn_rt(va, value):
    rt = shmask(value, 0, 0x7) # target
    rn = shmask(value, 3, 0x7) # base
    rm = shmask(value, 6, 0x7) # offset
    oper0 = arm_dis.ArmRegOper(rt)
    oper1 = arm_dis.ArmRegOffsetOper(rn, rm, va)
    return oper0,oper1

def imm5_rn_rt(va, value):
    imm = shmask(value, 6, 0x1f)
    rn = shmask(value, 3, 0x7)
    rt = shmask(value, 0, 0x7)
    oper0 = arm_dis.ArmRegOper(rt)
    oper1 = arm_dis.ArmImmOffsetOper(rn, imm, va)
    return oper0,oper1

def rd_pc_imm8(va, value):
    rd = shmask(value, 8, 0x7)
    imm = shmask(value, 0, 0xff)
    oper0 = arm_dis.ArmRegOper(rd)
    # pre-compute PC relative addr
    oper1 = arm_dis.ArmImmOper(va+imm)
    return oper0,oper1

def rt_pc_imm8(va, value):
    rt = shmask(value, 8, 0x7)
    imm = shmask(value, 0, 0xff)
    oper0 = arm_dis.ArmRegOper(rt)
    oper1 = arm_dis.ArmImmOffsetOper() # FIXME offset from PC


# opinfo is:
# ( <mnem>, <operdef>, <flags> )
# operdef is:
# ( (otype, oshift, omask), ...)
thumb_table = [
    ('00000',       ('lsl',     imm5_rm_rd, 0)), # LSL<c> <Rd>,<Rm>,#<imm5>
    ('00001',       ('lsr',     imm5_rm_rd, 0)), # LSR<c> <Rd>,<Rm>,#<imm>
    ('00010',       ('asr',     imm5_rm_rd, 0)), # ASR<c> <Rd>,<Rm>,#<imm>
    ('0001100',     ('add',     rm_rn_rd,   0)), # ADD<c> <Rd>,<Rn>,<Rm>
    ('0001101',     ('sub',     rm_rn_rd,   0)), # SUB<c> <Rd>,<Rn>,<Rm>
    ('0001110',     ('add',     imm3_rn_rd, 0)), # ADD<c> <Rd>,<Rn>,#<imm3>
    ('0001111',     ('sub',     imm3_rn_rd, 0)), # SUB<c> <Rd>,<Rn>,#<imm3>
    ('00100',       ('mov',     imm8_rd,    0)), # MOV<c> <Rd>,#<imm8>
    ('00101',       ('cmp',     imm8_rd,    0)), # CMP<c> <Rn>,#<imm8>
    ('00110',       ('add',     imm8_rd,    0)), # ADD<c> <Rdn>,#<imm8>
    ('00111',       ('sub',     imm8_rd,    0)), # SUB<c> <Rdn>,#<imm8>
    # Data processing instructions
    ('0100000000',  ('and',     rm_rdn,     0)), # AND<c> <Rdn>,<Rm>
    ('0100000001',  ('eor',     rm_rdn,     0)), # EOR<c> <Rdn>,<Rm>
    ('0100000010',  ('lsl',     rm_rdn,     0)), # LSL<c> <Rdn>,<Rm>
    ('0100000011',  ('lsr',     rm_rdn,     0)), # LSR<c> <Rdn>,<Rm>
    ('0100000100',  ('asr',     rm_rdn,     0)), # ASR<c> <Rdn>,<Rm>
    ('0100000101',  ('adc',     rm_rdn,     0)), # ADC<c> <Rdn>,<Rm>
    ('0100000110',  ('sbc',     rm_rdn,     0)), # SBC<c> <Rdn>,<Rm>
    ('0100000111',  ('ror',     rm_rdn,     0)), # ROR<c> <Rdn>,<Rm>
    ('0100001000',  ('tst',     rm_rd,      0)), # TST<c> <Rn>,<Rm>
    ('0100001001',  ('rsb',     rm_rd_imm0, 0)), # RSB<c> <Rd>,<Rn>,#0
    ('0100001010',  ('cmp',     rm_rd,      0)), # CMP<c> <Rn>,<Rm>
    ('0100001011',  ('cmn',     rm_rd,      0)), # CMN<c> <Rn>,<Rm>
    ('0100001100',  ('orr',     rm_rdn,     0)), # ORR<c> <Rdn>,<Rm>
    ('0100001101',  ('mul',     rn_rdm,     0)), # MUL<c> <Rdm>,<Rn>,<Rdm>
    ('0100001110',  ('bic',     rm_rdn,     0)), # BIC<c> <Rdn>,<Rm>
    ('0100001111',  ('mvn',     rm_rd,      0)), # MVN<c> <Rd>,<Rm>
    # Special data instructions and branch and exchange
    ('0100010000',  ('add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('0100010001',  ('add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('010001001',   ('add',     d1_rm4_rd3, 0)), # ADD<c> <Rdn>,<Rm>
    ('0100010101',  ('cmp',     d1_rm4_rd3, 0)), # CMP<c> <Rn>,<Rm>
    ('010001011',   ('cmp',     d1_rm4_rd3, 0)), # CMP<c> <Rn>,<Rm>
    ('0100011000',  ('mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('0100011001',  ('mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('0100011010',  ('mov',     d1_rm4_rd3, 0)), # MOV<c> <Rd>,<Rm>
    ('010001110',   ('bx',      rm4_shift3, 0)), # BX<c> <Rm>
    ('010001111',   ('blx',     rm4_shift3, 0)), # BLX<c> <Rm>
    # Load from Literal Pool
    ('01001',       ('ldr',     rt_pc_imm8, 0)), # LDR<c> <Rt>,<label>
    # Load/Stor single data item
    ('0101000',     ('str',     rm_rn_rt,   0)), # STR<c> <Rt>,[<Rn>,<Rm>]
    ('0101001',     ('strh',    rm_rn_rt,   0)), # STRH<c> <Rt>,[<Rn>,<Rm>]
    ('0101010',     ('strb',    rm_rn_rt,   0)), # STRB<c> <Rt>,[<Rn>,<Rm>]
    ('0101011',     ('ldrsb',   rm_rn_rt,   0)), # LDRSB<c> <Rt>,[<Rn>,<Rm>]
    ('0101100',     ('ldr',     rm_rn_rt,   0)), # LDR<c> <Rt>,[<Rn>,<Rm>]
    ('0101101',     ('ldrh',    rm_rn_rt,   0)), # LDRH<c> <Rt>,[<Rn>,<Rm>]
    ('0101110',     ('ldrb',    rm_rn_rt,   0)), # LDRB<c> <Rt>,[<Rn>,<Rm>]
    ('0101111',     ('ldrsh',   rm_rn_rt,   0)), # LDRSH<c> <Rt>,[<Rn>,<Rm>]
    ('01100',       ('str',     imm5_rn_rt, 0)), # STR<c> <Rt>, [<Rn>{,#<imm5>}]
    ('01101',       ('ldr',     imm5_rn_rt, 0)), # LDR<c> <Rt>, [<Rn>{,#<imm5>}]
    ('01110',       ('strb',    imm5_rn_rt, 0)), # STRB<c> <Rt>,[<Rn>,#<imm5>]
    ('01111',       ('ldrb',    imm5_rn_rt, 0)), # LDRB<c> <Rt>,[<Rn>{,#<imm5>}]
    ('10000',       ('strh',    imm5_rn_rt, 0)), # STRH<c> <Rt>,[<Rn>{,#<imm>}]
    ('10001',       ('ldrh',    imm5_rn_rt, 0)), # LDRH<c> <Rt>,[<Rn>{,#<imm>}]
    ('10010',       ('str',     imm5_rn_rt, 0)), # STR<c> <Rt>, [<Rn>{,#<imm>}]
    ('10011',       ('ldr',     imm5_rn_rt, 0)), # LDR<c> <Rt>, [<Rn>{,#<imm>}]
    # Generate PC relative address
    ('10100',       ('adr',     rd_pc_imm8, 0)), # ADR<c> <Rd>,<label>
    # Generate SP relative address
    ('10101',       ('add',     rd_sp_imm8, 0)), # ADD<c> <Rd>,SP,#<imm>
    # Miscellaneous instructions
    ('10110110010', ('setend',  sh4_imm1,   0)), # SETEND <endian_specifier>
    ('10110110011', ('cps',     simpleops(),0)), # CPS<effect> <iflags> FIXME
    ('101100000',   ('add',     sp_sp_imm7, 0)), # ADD<c> SP,SP,#<imm>
    ('101100001',   ('sub',     sp_sp_imm7, 0)), # SUB<c> SP,SP,#<imm>
    ('10110001',    ('cbz',     
]

def sp_sp_imm7(va, value):
    imm = shmask(value, 0, 0x7f)
    o0 = arm_dis.ArmRegOper(arm_reg.REG_SP)
    o1 = arm_dis.ArmRegOper(arm_reg.REG_SP)
    o2 = arm_dis.ArmImmOper(imm)
    return o0,o1,o2

ttree = e_btree.BinaryTree()
for binstr, opinfo in thumb_table:
    ttree.addBinstr(binstr, opinfo)

thumb32mask = binary('11111')
thumb32min  = binary('11100')

def thumb16_arithmetic(opval):

def thumb16_dataprocess():
    pass
def thumb16_specialdata():
    pass
def thumb16_loadliteral():
    pass
def thumb16_loadstorsingle():
    pass
def thumb16_genpcreladdr():
    pass
def thumb16_genspreladdr():
    pass
def thumb16_misc():
    pass
def thumb16_stormultireg():
    pass
def thumb16_loadmultireg():
    pass
def thumb16_condbranch():
    pass
def thumb16_uncondbranch():
    pass
def thumb16_goto32():
    pass

def thumb16row(binstr, func):
    bin = e_bits.binary(binstr)
    shift = 6 - len(binstr)
    return bin, shift, func

def addtotree(binstr, opinfo):
    node = thumbtree
    while binstr:
        choice = int(binstr[0], 2)
        if node[choice] == None:
            node[choice] = [None, None, None]
        node = node[choice]
    node[2] = opinfo

thumbtree = [None, None, None]

thumb16table = [
    thumb16row('00',     thumb16_arithmetic),
    thumb16row('010000', thumb16_dataprocess),
    thumb16row('010001', thumb16_specialdata),
    thumb16row('01001',  thumb16_loadliteral),
    thumb16row('0101',   thumb16_loadstorsingle),
    thumb16row('011',    thumb16_loadstorsingle),
    thumb16row('100',    thumb16_loadstorsingle),
    thumb16row('10100',  thumb16_genpcreladdr),
    thumb16row('10101',  thumb16_genspreladdr),
    thumb16row('1011',   thumb16_misc),
    thumb16row('11000',  thumb16_stormultireg),
    thumb16row('11001',  thumb16_loadmultireg),
    thumb16row('1101',   thumb16_condbranch),
    thumb16row('11100',  thumb16_uncondbranch),
    thumb16row('11101',  thumb16_goto32),
    thumb16row('11110',  thumb16_goto32),
    thumb16row('11111',  thumb16_goto32),
]

def is_thumb32(val):
    '''
    Take a 16 bit integer (opcode) value and determine
    if it is really the first 16 bits of a 32 bit
    instruction.
    '''
    bval = val >> 11
    return (bval & thumb32mask) > thumb32min

