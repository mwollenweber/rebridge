import sys
import struct
import traceback

import envi
import envi.bits as e_bits
from envi.bits import binary

from envi.archs.arm.const import *
#from envi.archs.arm import *
from envi.archs.arm.regs import *

# Universal opcode things:
# len
# mode

#FIXME: TODO
#   * Thumb Extension Parser
#   * Jazelle Extension Parser
#   * Emulators

####################################################################
# Parsers for the multiply family of instruction encodings

def chopmul(opcode):
    op1 = (opcode >> 20) & 0xff
    a = (opcode >> 16) & 0xf
    b = (opcode >> 12) & 0xf
    c = (opcode >> 8)  & 0xf
    d = (opcode >> 4)  & 0xf
    e = opcode & 0xf
    return (op1<<4)+d,(a,b,c,d,e)

# FIXME this seems to be universal...
def addrToName(mcanv, va):
    sym = mcanv.syms.getSymByAddr(va)
    if sym != None:
        return repr(sym)
    return "0x%.8x" % va

# The keys in this table are made of the
# concat of bits 27-21 and 7-4 (only when
# ienc == mul!
iencmul_codes = {
    # Basic multiplication opcodes
    binary("000000001001"): ("mul",(0,4,2), 0),
    binary("000000011001"): ("mul",(0,4,2), IF_PSR_S),
    binary("000000101001"): ("mla",(0,4,2,1), 0),
    binary("000000111001"): ("mla",(0,4,2,1), IF_PSR_S),
    binary("000001001001"): ("umaal",(1,0,4,2), 0),
    binary("000010001001"): ("umull",(1,0,4,2), 0),
    binary("000010011001"): ("umull",(1,0,4,2), IF_PSR_S),
    binary("000010101001"): ("umlal",(1,0,4,2), 0),
    binary("000010111001"): ("umlal",(1,0,4,2), IF_PSR_S),
    binary("000011001001"): ("smull",(1,0,4,2), 0),
    binary("000011011001"): ("smull",(1,0,4,2), IF_PSR_S),
    binary("000011101001"): ("smlal",(1,0,4,2), 0),
    binary("000011111001"): ("smlal",(1,0,4,2), IF_PSR_S),

    # multiplys with <x><y>
    # "B"
    binary("000100001000"): ("smlabb", (0,4,2,1), 0),
    binary("000100001010"): ("smlatb", (0,4,2,1), 0),
    binary("000100001100"): ("smlabt", (0,4,2,1), 0),
    binary("000100001110"): ("smlatt", (0,4,2,1), 0),
    binary("000100101010"): ("smulwb", (0,4,2), 0),
    binary("000100101110"): ("smulwt", (0,4,2), 0),
    binary("000100101000"): ("smlawb", (0,4,2), 0),
    binary("000100101100"): ("smlawt", (0,4,2), 0),
    binary("000101001000"): ("smlalbb", (1,0,4,2), 0),
    binary("000101001010"): ("smlaltb", (1,0,4,2), 0),
    binary("000101001100"): ("smlalbt", (1,0,4,2), 0),
    binary("000101001110"): ("smlaltt", (1,0,4,2), 0),
    binary("000101101000"): ("smulbb", (0,4,2), 0),
    binary("000101101010"): ("smultb", (0,4,2), 0),
    binary("000101101100"): ("smulbt", (0,4,2), 0),
    binary("000101101110"): ("smultt", (0,4,2), 0),

    # type 2 multiplys

    binary("011100000001"): ("smuad", (0,4,2), 0),
    binary("011100000011"): ("smuadx", (0,4,2), 0),
    binary("011100000101"): ("smusd", (0,4,2), 0),
    binary("011100000111"): ("smusdx", (0,4,2), 0),
    binary("011100000001"): ("smlad", (0,4,2), 0),
    binary("011100000011"): ("smladx", (0,4,2), 0),
    binary("011100000101"): ("smlsd", (0,4,2), 0),
    binary("011100000111"): ("smlsdx", (0,4,2), 0),
    binary("011101000001"): ("smlald", (0,4,2), 0),
    binary("011101000011"): ("smlaldx", (0,4,2), 0),
    binary("011101000101"): ("smlsld", (0,4,2), 0),
    binary("011101000111"): ("smlsldx", (0,4,2), 0),
    binary("011101010001"): ("smmla", (0,4,2,1), 0),
    binary("011101010011"): ("smmlar", (0,4,2,1), 0),
    binary("011101011101"): ("smmls", (0,4,2,1), 0),
    binary("011101011111"): ("smmlsr", (0,4,2,1), 0),
    binary("011101010001"): ("smmul", (0,4,2), 0),
    binary("011101010011"): ("smmulr", (0,4,2), 0),
}

####################################################################
# Mnemonic tables for opcode based mnemonic lookup

# Dataprocessing mnemonics
dp_mnem = ("and","eor","sub","rsb","add","adc","sbc","rsc","tst","teq","cmp","cmn","orr","mov","bic","mvn",)

# FIXME: THIS IS FUGLY
dp_noRn = (13,15)
dp_noRd = (8,9,10,11)

# FIXME: !!! Don't make SBZ and SBO's part of the list of opers !!!
#  first parm SBZ:   mov,mvn
#  second parm SBZ:  tst,teq,cmp,cmn,
def dpbase(opval):
    """
    Parse and return opcode,sflag,Rn,Rd for a standard
    dataprocessing instruction.
    """
    ocode = (opval >> 21) & 0xf
    sflag = (opval >> 20) & 0x1
    Rn = (opval >> 16) & 0xf
    Rd = (opval >> 12) & 0xf
    #print "DPBASE:",ocode,sflag,Rn,Rd
    return ocode,sflag,Rn,Rd

####################################################################
# Parser functions for each of the instruction encodings

def p_dp_imm_shift(opval, va):
    ocode,sflag,Rn,Rd = dpbase(opval)
    Rm = opval & 0xf
    shtype = (opval >> 5) & 0x3
    shval = (opval >> 6) & 0x1f     #CHECKME: is this correctly done?

    if ocode in dp_noRn:# FIXME: FUGLY (and slow...)
        olist = (
            ArmRegOper(Rd),
            ArmRegShiftImmOper(Rm, shtype, shval),
        )
    elif ocode in dp_noRd:
        olist = (
            ArmRegOper(Rn),
            ArmRegShiftImmOper(Rm, shtype, shval),
        )
    else:
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rn),
            ArmRegShiftImmOper(Rm, shtype, shval),
        )

    opcode = (IENC_DP_IMM_SHIFT << 16) + ocode
    # FIXME @las we are losing sflag everywhere. Do we need it?
    return (opcode, dp_mnem[ocode], olist, 0)

# specialized mnemonics for p_misc
qop_mnem = ('qadd','qsub','qdadd','qdsub')
smla_mnem = ('smlabb','smlabt','smlatb','smlatt',)
smlal_mnem = ('smlalbb','smlalbt','smlaltb','smlaltt',)
smul_mnem = ('smulbb','smulbt','smultb','smultt',)
smlaw_mnem = ('smlawb','smlawt',)
smlaw_mnem = ('smulwb','smulwt',)

def p_misc(opval, va):  # 0x0f900000 = 0x01000000 or 0x01000010 (misc and misc1 are both parsed at the same time.  see the footnote [2] on dp instructions in the Atmel AT91SAM7 docs
    if   opval & 0x0fc00000 == 0x01000000:
        opcode = (IENC_MISC << 16) + 1
        mnem = 'mrs'
        r = (opval>>22) & 1
        Rd = (opval>>12) & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmPgmStatRegOper(r),
        )
    elif opval & 0x0fc000f0 == 0x01200000:
        opcode = (IENC_MISC << 16) + 2
        mnem = 'msr'
        r = (opval>>22) & 1
        Rd = (opval>>12) & 0xf
        olist = (
            ArmPgmStatRegOper(r),
            ArmRegOper(Rd),
        )
    elif opval & 0x0fc000f0 == 0x01200010:
        opcode = (IENC_MISC << 16) + 3
        mnem = 'bx'
        Rm = opval & 0xf
        olist = ( ArmRegOper(Rm) )
        
    elif opval & 0x0ff000f0 == 0x01600010:  #FIXME: collapse 0x0ff000f0's into one value
        opcode = (IENC_MISC << 16) + 4
        mnem = 'clz'
        Rd = (opval>>12) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
        )
    elif opval & 0x0ff000f0 == 0x01200020:
        opcode = (IENC_MISC << 16) + 5
        mnem = 'bxj'
        Rm = opval & 0xf
        olist = ( ArmRegOper(Rm) )
        
    elif opval & 0x0ff000f0 == 0x01200030:
        opcode = (IENC_MISC << 16) + 6
        mnem = 'blx'
        Rm = opval & 0xf
        olist = ( ArmRegOper(Rm) )
        
    elif opval & 0x0f9000f0 == 0x01000050:  #all qadd/qsub's
        opcode = (IENC_MISC << 16) + 7
        qop = (opval>>21)&3
        mnem = qop_mnem[qop]
        Rn = (opval>>16) & 0xf
        Rd = (opval>>12) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rn),
        )
        
    elif opval & 0x0ff000f0 == 0x01200070:
        opcode = (IENC_MISC << 16) + 8
        mnem = 'bkpt'
        immed = ((opval>>4)&0xfff0) + (opval&0xf)
        olist = ( ArmImmOper(immed), )

    elif opval & 0x0ff00090 == 0x01000080:
        opcode = (IENC_MISC << 16) + 9
        xy = (opval>>5)&3
        mnem = smla_mnem[xy]
        Rd = (opval>>16) & 0xf
        Rn = (opval>>12) & 0xf 
        Rs = (opval>>8) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rs),
            ArmRegOper(Rn),
        )
    elif opval & 0x0ff000b0 == 0x01200080:
        opcode = (IENC_MISC << 16) + 10
        y = (opval>>6)&1
        mnem = smlaw_mnem[y]
        Rd = (opval>>16) & 0xf
        Rn = (opval>>12) & 0xf 
        Rs = (opval>>8) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rs),
            ArmRegOper(Rn),
        )
    elif opval & 0x0ff000b0 == 0x012000a0:
        opcode = (IENC_MISC << 16) + 11
        y = (opval>>6)&1
        mnem = smulw_mnem[y]
        Rd = (opval>>16) & 0xf
        Rs = (opval>>8) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rs),
        )
    elif opval & 0x0ff00090 == 0x01400080:
        opcode = (IENC_MISC << 16) + 12
        xy = (opval>>5)&3
        mnem = smlal_mnem[xy]
        Rdhi = (opval>>16) & 0xf
        Rdlo = (opval>>12) & 0xf 
        Rs = (opval>>8) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rdlo),
            ArmRegOper(Rdhi),
            ArmRegOper(Rs),
            ArmRegOper(Rn),
        )
    elif opval & 0x0ff00090 == 0x01600080:
        opcode = (IENC_MISC << 16) + 13
        xy = (opval>>5)&3
        mnem = smulxy_mnem[xy]
        Rd = (opval>>16) & 0xf
        Rs = (opval>>8) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rs),
        )
        mnem = 'smul'   #xy
    #elif opval & 0x0fc00000 == 0x03200000:
        #mnem = 'msr'
    else:
        opcode = IENC_UNDEF
        mnem = "undefined instruction"
        olist = ()
        
    return (opcode, mnem, olist, 0)


misc1_mnem = ("pkhbt", "pkhtb", "rev", "rev16", "revsh", "sel", "ssat", "ssat16", "usat", "usat16", )

#FIXME: Actually do p_misc1
def p_misc1(opval, va): # 
    R = (opval>>22) & 1
    Rn = (opval>>16) & 0xf
    Rd = (opval>>12) & 0xf
    rot_imm = (opval>>8) & 0xf
    imm = opval & 0xff
    Rm = opval & 0xf



swap_mnem = ("swp","swpb",)
strex_mnem = ("strex","ldrex",)
strh_mnem = ("strh","ldrh",)
ldrs_mnem = ("ldrsh","ldrsb",)
ldrd_mnem = ("ldrd","strd",)
def p_extra_load_store(opval, va):
    pubwl = (opval>>20) & 0x1f
    Rn = (opval>>16) & 0xf
    Rd = (opval>>12) & 0xf
    Rs = (opval>>8) & 0xf
    op1 = (opval>>5) & 0x3
    Rm = opval & 0xf

    if opval&0x0fb000f0==0x01000090:# swap/swapb
        idx = (pubwl>>2)&1
        opcode = (IENC_EXTRA_LOAD << 16) + idx
        mnem = swap_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmRegOper(Rm),
        )
    elif opval&0x0fe000f0==0x01800090:# strex/ldrex
        idx = (pubwl>>2)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 2 + idx
        mnem = strex_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
        )
    elif opval&0x0e4000f0==0x000000b0:# strh/ldrh regoffset
        idx = (pubwl>>2)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 4 + idx
        mnem = strh_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmRegOper(Rm),
        )
    elif opval&0x0e4000f0==0x004000b0:# strh/ldrh immoffset
        idx = (pubwl>>2)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 6 + idx
        mnem = strh_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmOffsetOper((Rs<<4)+Rm, va),
        )
    elif opval&0x0e4000d0==0x004000b0:# ldrsh/b immoffset
        idx = (pubwl>>4)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 8 + idx
        mnem = ldrs_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmOffsetOper((Rs<<4)+Rm, va),
        )
    elif opval&0x0e4000d0==0x000000b0:# ldrsh/b regoffset
        idx = (opval>>5)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 10 + idx
        mnem = ldrs_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmRegOper(Rm),
        )
    elif opval&0x0e5000d0==0x000000b0:# ldrd/strd regoffset
        idx = (opval>>5)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 12 + idx
        mnem = ldrd_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmRegOper(Rm),
        )
    elif opval&0x0e5000d0==0x004000b0:# ldrd/strd immoffset
        idx = (opval>>5)&1
        opcode = (IENC_EXTRA_LOAD << 16) + 14 + idx
        mnem = ldrd_mnem[idx]
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rd),
            ArmOffsetOper((Rs<<4)+Rm, va),
        )
    else:
        print >>sys.stderr,("extra_load_store: No Valid Opcode: WTF, should never get here...")
        return p_undef(opval, va)

    return (opcode, mnem, olist, 0)


def p_dp_reg_shift(opval, va):
    ocode,sflag,Rn,Rd = dpbase(opval)
    Rm = opval & 0xf
    shtype = (opval >> 5) & 0x3
    Rs = (opval >> 8) & 0xf

    if ocode in dp_noRn:# FIXME: FUGLY
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm, shtype, Rs),
        )
    elif ocode in dp_noRd:
        olist = (
            ArmRegOper(Rn),
            ArmRegOper(Rm, shtype, Rs),
        )
    else:
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rn),
            ArmRegShiftRegOper(Rm, shtype, Rs),
        )

    opcode = (IENC_DP_REG_SHIFT << 16) + ocode
    return (opcode, dp_mnem[ocode], olist, 0)


def p_mult(opval, va):
    ocode, vals = chopmul(opval)
                             
    mnem, opindexes, flags = iencmul_codes.get(ocode)

    olist = []
    for i in opindexes:
        olist.append(ArmRegOper(vals[i]))

    opcode = (IENC_MULT << 16) + ocode
    return (opcode, mnem, olist, flags)

def p_dp_imm(opval, va):
    ocode,sflag,Rn,Rd = dpbase(opval)
    imm = opval & 0xff
    rot = (opval >> 8) & 0xf
    
    immed = (imm>>rot) + ((imm<<rot) & 0xffffffff)

    if ocode in dp_noRn:# FIXME: FUGLY
        olist = (
            ArmRegOper(Rd),
            ArmImmOper(immed),
        )
    elif ocode in dp_noRd:
        olist = (
            ArmRegOper(Rn),
            ArmImmOper(immed),
        )
    else:
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rn),
            ArmImmOper(immed),
        )

    opcode = (IENC_DP_IMM << 16) + ocode
    return (opcode, dp_mnem[ocode], olist, 0)

def p_undef(opval, va):
    opcode = IENC_UNDEF
    mnem = "undefined instruction"
    olist = (
        ArmImmOper(opval),
    )
        
    return (opcode, mnem, olist, 0)

def p_mov_imm_stat(opval, va):      # only one instruction: "msr"
    imm = opval & 0xff
    rot = (opval>>8) & 0xf
    r = (opval>>22) & 1
    mask = (opval>>16) & 0xf
    
    immed = (imm>>rot) + ((imm<<rot) & 0xffffffff)
    
    olist = (
        ArmPgmStatRegOper(mask),
        ArmImmOper(rotate(immed)),
    )
    
    opcode = (IENC_MOV_IMM_STAT << 16)
    return (opcode, "msr", olist, 0)
    
ldr_mnem = ("str", "ldr")
tsizes = (4, 1,)
def p_load_imm_off(opval, va):
    pubwl = (opval>>20) & 0x1f
    Rn = (opval>>16) & 0xf
    Rd = (opval>>12) & 0xf
    imm = opval & 0xfff
    
    olist = (
        ArmRegOper(Rd),
        ArmImmOffsetOper(Rn, imm, va, pubwl=pubwl<<2)    # u=-/+, b=word/byte
    )
    
    opcode = (IENC_LOAD_IMM_OFF << 16)
    # FIXME @las ditched flags==pubwl<<2
    return (opcode, ldr_mnem[pubwl&1], olist, 0)

def p_load_reg_off(opval, va):
    pubwl = (opval>>20) & 0x1f
    Rd = (opval>>12) & 0xf
    Rn = (opval>>16) & 0xf
    Rm = opval & 0xf
    shtype = (opval>>5) & 0x3
    shval = (opval>>7) & 0x1f

    olist = (
        ArmRegOper(Rd),
        ArmScaledOffsetOper(Rn, Rm, shtype, shval, va, pubwl<<2),  # u=-/+, b=word/byte
    )
    
    opcode = (IENC_LOAD_REG_OFF << 16) 
    # FIXME @las ditched flags==pubwl
    return (opcode, ldr_mnem[pubwl&1], olist, 0)

    
def p_media(opval, va):
    """
    27:20, 7:4
    """
    # media is a parent for the following:
    #  parallel add/sub                         01100
    #  pkh, ssat, ssat16, usat, usat16, sel     01101
    #  rev, rev16, revsh                        01101
    #  smlad, smlsd, smlald, smusd              01110
    #  usad8, usada8                            01111
    definer = (opval>>23) & 0x1f
    if   definer == 0xc:
        return p_media_parallel(opval, va)
    elif definer == 0xd:
        return p_media_pack_sat_rev_extend(opval, va)
    elif definer == 0xe:
        return p_media_smul(opval, va)
    else:
        return p_media_usada8(opval, va)

#generate mnemonics for parallel instructions (could do manually like last time...)
parallel_mnem = []
par_suffixes = ("add16", "addsubx", "subaddx", "sub16", "add8", "sub8", "", "")
par_prefixes = ("","s","q","sh","","u","uq","uh")
for pre in par_prefixes:
    for suf in par_suffixes:
        parallel_mnem.append(pre+suf)

parallel_mnem = tuple(parallel_mnem)

def p_media_parallel(opval, va):
    
    opc1 = (opval>>17) & 0x38
    Rn = (opval>>16) & 0xf
    Rd = (opval>>12) & 0xf
    opc1 += (opval>>5) & 7
    Rm = opval & 0xf
    mnem = parallel_mnem[opc1]
    
    olist = (
        ArmRegOper(Rd),
        ArmRegOper(Rn),
        ArmRegOper(Rm),
    )
    opcode = IENC_MEDIA_PARALLEL + opc1
    return (opcode, mnem, olist, 0)


xtnd_mnem = []
xtnd_suffixes = ("xtab16","xtab","xtah","xtb16","xtb","xth",)
xtnd_prefixes = ("s","u")
for pre in xtnd_prefixes:
    for suf in xtnd_suffixes:
        xtnd_mnem.append(pre+suf)
        
xtnd_mnem = tuple(xtnd_mnem)

pkh_mnem = ('pkhbt', 'pkhtb',)
sat_mnem = ('ssat','usat')
sat16_mnem = ('ssat16','usat16')    
rev_mnem = ('rev','rev16',None,'revsh',)

def p_media_pack_sat_rev_extend(opval, va):
    ## part of p_media
    #pkh
    opc1 = (opval>>20) & 7
    opc2 = (opval>>4) & 0xf
    opc25 = opc2 & 3
    opcode = 0
    
    if opc1 == 0 and opc25 == 1:   #pkh
        mnem = pkh_mnem[(opval>>6)&1]
        Rn = (opval>>16) & 0xf
        Rd = (opval>>12) & 0xf
        shift_imm = (opval>>7) & 0x1f
        Rm = opval & 0xf

        print 'FIXME WHAT WAS OPCODE SUPPOSED TO BE HERE @las?'
        
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rn),
            ArmRegShiftImmOper(Rm, S_LSL, shift_imm),
        )

    elif (opc1 & 2) and opc25 == 1: #word sat
        opidx = (opval>>22)&1
        sat_imm = 1 + (opval>>16) & 0xf
        Rd = (opval>>12) & 0xf
        Rm = opval & 0xf
        if opc1 & 0x10: # ?sat16
            mnem = sat16_mnem[opidx]
            olist = (
                ArmRegOper(Rd),
                ArmImmOper(sat_imm),
                ArmRegOper(Rm),
            )
            opcode = IENC_MEDIA_SAT + opidx
        else:
            mnem = sat_mnem[opidx]
            shift_imm = (opval>>7) & 0x1f
            sh = (opval>>5) & 2
            olist = (
                ArmRegOper(Rd),
                ArmImmOper(sat_imm),
                ArmRegShiftImmOper(Rm, sh, shift_imm),
            )
            opcode = IENC_MEDIA_SAT + 2 + opidx
            
    elif (opc1 & 3) == 2 and opc2 == 3:     #parallel half-word sat
        raise Exception("WTF! Parallel Half-Word Saturate...  what is that instruction?")
    
    elif (opc1 > 0) and (opc2 & 7) == 3:           # byte rev word
        opidx = ((opval>>21) & 2) + ((opval>>7) & 1)
        mnem = rev_mnem[opidx]
        Rd = (opval>>12) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
        )
        opcode = IENC_MEDIA_REV + opidx
    #elif opc1 == 3 and opc2 == 0xb:         # byte rev pkt halfword
    #elif opc1 == 7 and opc2 == 0xb:         # byte rev signed halfword
    elif opc1 == 0 and opc2 == 0xb:         # select bytes
        mnem = "sel"
        Rn = (opval>>16) & 0xf
        Rd = (opval>>12) & 0xf
        Rm = opval & 0xf
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rn),
            ArmRegOper(Rm),
        )
        opcode = IENC_MEDIA_SEL
    elif opc2 == 7:                         # sign extend
        mnem = 'FIXME @las'
        Rn = (opval>>16) & 0xf
        Rd = (opval>>12) & 0xf
        rotate = (opval>>10) & 3
        Rm = opval & 0xf
        
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rn),
            ArmRegShiftImmOper(Rm, S_ROR, rotate),
        )
        opcode = IENV_MEDIA_EXTEND + opc1
    else:
        print 'FIXME UNDEFINED1'
        return p_undef(opval, va)

    return (opcode, mnem, olist, 0)

#smult3_mnem = ('smlad','smlsd',,,'smlald')
def p_media_smul(opval, va):
    raise Exception("Should not reach here.  If we reach here, we'll have to implement MEDIA_SMUL extended multiplication (type 3)")
    # hmmm, is this already handled?
    
def p_media_usada(opval, va):
    Rd = (opval>>16) & 0xf
    Rn = (opval>>12) & 0xf
    Rs = (opval>>8) & 0xf
    Rm = opval & 0xf
    
    if Rn == 0xf:
        mnem = "usad8"
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rs),
        )
        opcode = IENC_MEDIA_USAD8
    else:
        mnem = "usada8"
        olist = (
            ArmRegOper(Rd),
            ArmRegOper(Rm),
            ArmRegOper(Rs),
            ArmRegOper(Rn),
        )
        opcode = IENC_MEDIA_USADA8

    return (opcode, mnem, olist, 0)

def p_arch_undef(opval, va):
    #print >>sys.stderr,("implementme: p_arch_undef")
    return (IENC_ARCH_UNDEF, 'arch undefined', (ArmImm(opval),), 0)

ldm_mnem = ("stm", "ldm")

def p_load_mult(opval, va):
    puswl = (opval>>20) & 0x1f
    mnem = ldm_mnem[(puswl&1)]
    flags = ((puswl<<10) & 0x3000) + IF_DA
    Rn = (opval>>16) & 0xf
    reg_list = opval & 0xffff
    
    olist = (
        ArmRegOper(Rn),
        ArmRegListOper(reg_list, puswl),
    )
    
    opcode = (IENC_LOAD_MULT << 16)
    return (opcode, mnem, olist, flags)

def instrenc(encoding, index):
    return (encoding << 16) + index

INS_B       = instrenc(IENC_BRANCH, 0)
INS_BL      = instrenc(IENC_BRANCH, 1)

b_mnem = ("b", "bl",)
def p_branch(opval, va):        # primary branch encoding.  others were added later in the media section
    off = e_bits.signed(opval, 3)
    off <<= 2
    link = (opval>>24) & 1

    #FIXME this assumes A1 branch encoding.
    
    olist = ( ArmOffsetOper(off, va),)
    if link:
        flags = envi.IF_CALL
    else:
        flags = envi.IF_BRANCH
    
    opcode = (IENC_BRANCH << 16) + link
    return (opcode, b_mnem[link], olist, flags)

ldc_mnem = ("stc", "ldc",)
def p_coproc_load(opval, va):       #FIXME: MRRC,  MCRR encoded here.
    punwl = (opval>>20) & 0x1f
    Rn = (opval>>16) & 0xf
    CRd = (opval>>12) & 0xf
    cp_num = (opval>>8) & 0xf
    offset = opval & 0xff

    olist = (
        ArmCoprocOper(cp_num),
        ArmCoprocRegOper(CRd),
        ArmImmOffsetOper(Rn, offset*4, va, pubwl=punwl),
    )
    
    opcode = (IENC_COPROC_LOAD << 16)
    return (opcode, ldc_mnem[punwl&1], olist, punwl)

mcrr_mnem = ("mcrr", "mrrc")
def p_coproc_dbl_reg_xfer(opval, va):
    Rn = (opval>>16) & 0xf
    Rd = (opval>>12) & 0xf
    cp_num = (opval>>8) & 0xf
    opcode = (opval>>4) & 0xf
    CRm = opval & 0xf
    mnem = mcrr_mnem[(opval>>20) & 1]
    
    olist = (
        ArmCoprocOper(cp_num),
        ArmCoprocOpcodeOper(opcode),
        ArmRegOper(Rd),
        ArmRegOper(Rn),
        ArmCoprocRegOper(CRm),
    )
    opcode = IENC_COPROC_RREG_XFER<<16
    return (opcode, mnem, olist, 0)
    
cdp_mnem = ["cdp" for x in range(15)]
cdp_mnem.append("cdp2")

def p_coproc_dp(opval, va):
    opcode1 = (opval>>20) & 0xf
    CRn = (opval>>16) & 0xf
    CRd = (opval>>12) & 0xf
    cp_num = (opval>>8) & 0xf
    opcode2 = (opval>>5) & 0x7
    CRm = opval & 0xf
    mnem = cdp_mnem[opval>>28]

    olist = (
        ArmCoprocOper(cp_num),
        ArmCoprocOpcodeOper(opcode1),
        ArmCoprocRegOper(CRd),
        ArmCoprocRegOper(CRn),
        ArmCoprocRegOper(CRm),
        ArmCoprocOpcodeOper(opcode2),
    )
    
    opcode = (IENC_COPROC_DP << 16)
    return (opcode, mnem, olist, 0)       #FIXME: CDP2 (cond = 0b1111) also needs handling.

mcr_mnem = ("mcr", "mrc")
def p_coproc_reg_xfer(opval, va):
    opcode1 = (opval>>21) & 0x7
    load = (opval>>20) & 1
    CRn = (opval>>16) & 0xf
    Rd = (opval>>12) & 0xf
    cp_num = (opval>>8) & 0xf
    opcode2 = (opval>>5) & 0x7
    CRm = opval & 0xf

    olist = (
        ArmCoprocOper(cp_num),
        ArmCoprocOpcodeOper(opcode1),
        ArmRegOper(Rd),
        ArmCoprocRegOper(CRn),
        ArmCoprocRegOper(CRm),
        ArmCoprocOpcodeOper(opcode2),
    )
    
    opcode = (IENC_COPROC_REG_XFER << 16)
    return (opcode, mcr_mnem[load], olist, 0)

def p_swint(opval, va):
    swint = opval & 0xffffff
    
    olist = ( ArmImmOper(swint), )
    opcode = IENC_SWINT
    return (opcode, "swint", olist, 0)


def p_uncond(opval, va):
    optop = (opval>>26) & 0x3
    if optop == 0:
        if (opval & 0xfff10020) == 0xf1000000:
            #cps
            imod = (opval>>18)&3
            mmod = (opval>>17)&1
            aif = (opval>>5)&7
            mode = opval&0x1f
            mnem = cps_mnem[imod]
            
            if imod & 2:
                olist = [
                    ArmCPSFlagsOper(aif)    # if mode is set...
                ]
            else:
                olist = []
            if mmod:
                olist.append(ArmImmOper(mode))
            
            opcode = IENC_UNCOND_CPS + imod
            return (opcode, mnem, olist, 0)
        elif (opval & 0xffff00f0) == 0xf1010000:
            #setend
            e = (opval>>9) & 1
            mnem = "setend"
            olist = ( ArmEndianOper(e) )
            opcode = IENC_UNCOND_SETEND
            return (opcode, mnem, olist, 0)
        else:
            raise Exception("I FOOBARed in p_uncond optop=0")
    elif optop == 1:
        if (opval & 0xf570f000) == 0xf550f000:
            #cache preload
            mnem = "pld"
            I = (opval>>25) & 1     # what the freak am i supposed to do with "i"???
            Rn = (opval>>16) & 0xf
            U = (opval>>23) & 1
            opcode = IENC_UNCOND_PLD
            if I:
                immoffset = opval & 0xfff
                olist = (ArmImmOffsetOper(Rn, immoffset, va, U<<5))
            else:
                Rm = opval & 0xf
                shtype = (opval>>5) & 3
                shval = (opval>>7) & 0x1f
                olist = (ArmScaledOffsetOper(Rn, Rm, shtype, shval, va, pubwl<<2), )
            return (opcode, mnem, olist, 0)
        else:
            raise Exception("I FOOBARed in p_uncond optop=1")
    elif optop == 2:
        if (opval & 0xfe5f0f00) == 0xf84d0500:
            #save return state
            pu_w = (opval>>21) & 0xf
            mnem = "srs"
            flags = ((pu_w<<10) & 0x3000) + IF_DA
            mode = opval & 0xf
            
            olist = (
                ArmModeOper(mode, pu_w&1),
            )
            opcode = IENC_UNCOND_SRS
            return (opcode, mnem, olist, flags)
        elif (opval & 0xfe500f00) == 0xf8100a00:
            #rfe
            pu = (opval>>23) & 3
            mnem = "rfe"
            flags = (pu<<12)  + IF_DA
            Rn = (opval>>16) & 0xf
            
            olist = (
                ArmRegOper(Rn),
            )
            opcode = IENC_UNCOND_RFE
            return (opcode, mnem, olist, flags)

        elif (opval & 0xfe000000) == 0xfa000000:
            #blx
            mnem = "blx"
            h = (opval>>23) & 2
            # FIXME @las CAN THIS BE NEGATIVE? e_bits.signed(opval, 3)
            imm_offset = (opval&0xffffff) + h
            
            olist = (
                ArmOffsetOper(imm_offset, va),
            )
            
            opcode = IENC_BLX           #should this be IENC_UNCOND_BLX?
            return (opcode, mnem, olist, 0)
        else:
            raise Exception("I FOOBARed in p_uncond optop=2")
    else:
        if (opval & 0xffe00000) == 0xfc400000:
            #MRCC2/MRRC2
            raise Exception("MCRR2/MRRC2")
            
            
        elif (opval & 0xfe000000) == 0xfc000000:
            #stc2/ldc2
            raise Exception("stc2/ldc2")
        elif (opval & 0xff000010) == 0xfe000000:
            #coproc dp (cdp2)
            return p_coproc_dp(opval)
        elif (opval & 0xff000010) == 0xfe000010:
            #mcr2/mrc2
            raise Exception("MCR2/MRC2")
        else:
            raise Exception("I FOOBARed in p_uncond optop=3")
    
####################################################################
# Table of the parser functions
ienc_parsers_tmp = [None for x in range(21)]

ienc_parsers_tmp[IENC_DP_IMM_SHIFT] =  p_dp_imm_shift
ienc_parsers_tmp[IENC_MISC] =   p_misc
ienc_parsers_tmp[IENC_MISC1] =   p_misc1
ienc_parsers_tmp[IENC_EXTRA_LOAD] =   p_extra_load_store
ienc_parsers_tmp[IENC_DP_REG_SHIFT] =   p_dp_reg_shift
ienc_parsers_tmp[IENC_MULT] =   p_mult
ienc_parsers_tmp[IENC_UNDEF] =   p_undef
ienc_parsers_tmp[IENC_MOV_IMM_STAT] =   p_mov_imm_stat
ienc_parsers_tmp[IENC_DP_IMM] =   p_dp_imm
ienc_parsers_tmp[IENC_LOAD_IMM_OFF] =   p_load_imm_off
ienc_parsers_tmp[IENC_LOAD_REG_OFF] =   p_load_reg_off
ienc_parsers_tmp[IENC_ARCH_UNDEF] =   p_arch_undef
ienc_parsers_tmp[IENC_MEDIA] =   p_media
ienc_parsers_tmp[IENC_LOAD_MULT] =   p_load_mult
ienc_parsers_tmp[IENC_BRANCH] =   p_branch
ienc_parsers_tmp[IENC_COPROC_RREG_XFER] = p_coproc_dbl_reg_xfer
ienc_parsers_tmp[IENC_COPROC_LOAD] =   p_coproc_load
ienc_parsers_tmp[IENC_COPROC_DP] =   p_coproc_dp
ienc_parsers_tmp[IENC_COPROC_REG_XFER] =   p_coproc_reg_xfer
ienc_parsers_tmp[IENC_SWINT] =    p_swint
ienc_parsers_tmp[IENC_UNCOND] = p_uncond

ienc_parsers = tuple(ienc_parsers_tmp)

####################################################################

# the primary table is index'd by the 3 bits following the
# conditional and are structured as follows:
# ( ENC, nexttable )
# If ENC != None, those 3 bits were enough for us to know the
# encoding type, otherwise move on to the second table.

# The secondary tables have the format:
# (mask, value, ENC).  If the opcode is masked with "mask"
# resulting in "value" we have found the instruction encoding.
# NOTE: All entries in these tables *must* be from most specific
# to least!

# Table for initial 3 bit == 0
s_0_table = (
    # Order is critical here...
    (binary("00000000000000000000000000010000"), binary("00000000000000000000000000000000"), IENC_DP_IMM_SHIFT),
    (binary("00000001100100000000000000010000"), binary("00000001000000000000000000000000"), IENC_MISC),
    (binary("00000001100100000000000010010000"), binary("00000001000000000000000000010000"), IENC_MISC),
    (binary("00000001000000000000000010010000"), binary("00000000000000000000000010010000"), IENC_MULT),
    (binary("00000000000000000000000010010000"), binary("00000000000000000000000010010000"), IENC_EXTRA_LOAD),
    (binary("00000000000000000000000010010000"), binary("00000000000000000000000000010000"), IENC_DP_REG_SHIFT),
    (0,0, IENC_UNDEF),   #catch-all
)

s_1_table = (
    (binary("00000001100110000000000000000000"), binary("00000001000000000000000000000000"), IENC_UNDEF),
    (binary("00000001100110000000000000000000"), binary("00000001001000000000000000000000"), IENC_MOV_IMM_STAT),
    (0,0, IENC_DP_IMM),
)

s_3_table = (
    (binary("00000001111100000000000011110000"),binary("00000001111100000000000011110000"), IENC_ARCH_UNDEF),
    (binary("00000000000000000000000000010000"),binary("00000000000000000000000000010000"), IENC_MEDIA),
    (0,0, IENC_LOAD_REG_OFF),
)

s_6_table = (
    (binary("00001111111000000000000000000000"),binary("00001100010000000000000000000000"), IENC_COPROC_RREG_XFER),
    (binary("00001110000000000000000000000000"),binary("00001100000000000000000000000000"), IENC_COPROC_LOAD),
)

s_7_table = (
    (binary("00000001000000000000000000000000"),binary("00000001000000000000000000000000"), IENC_SWINT),
    (binary("00000001000000000000000000010000"),binary("00000000000000000000000000010000"), IENC_COPROC_REG_XFER),
    (0, 0, IENC_COPROC_DP),
)

# Initial 3 (non conditional) primary table
inittable = [
    (None, s_0_table),
    (None, s_1_table),
    (IENC_LOAD_IMM_OFF, None), # Load or store an immediate
    (None, s_3_table),
    (IENC_LOAD_MULT, None),
    (IENC_BRANCH, None),
    (None, s_6_table),
    (None, s_7_table),
    (IENC_UNCOND, None),
]

# FIXME for emulation...
#def s_lsl(val, shval):
    #pass

#def s_lsr(val, shval):
    #pass

# These are indexed by the 2 bit "shift" value in some DP encodings
#shift_handlers = (
    #s_lsl,
    #s_lsr,
    #s_asr,
    #s_ror,
#)

endian_names = ("le","be")

#FIXME IF_NOFALL (and other envi flags)

class ArmOpcode(envi.Opcode):

    def __hash__(self):
        return int(hash(self.mnem) ^ (self.size << 4))

    def __len__(self):
        return int(self.size)

    def getBranches(self, emu=None):
        """
        Return a list of tuples.  Each tuple contains the target VA of the
        branch, and a possible set of flags showing what type of branch it is.

        See the BR_FOO types for all the supported envi branch flags....
        Example: for bva,bflags in op.getBranches():
        """
        ret = []

        if not self.iflags & envi.IF_NOFALL:
            ret.append((self.va + self.size, envi.BR_FALL))

        # FIXME if this is a move to PC god help us...
        flags = 0
        if self.prefixes != COND_AL:
            flags |= envi.BR_COND
        if self.opcode == INS_B:
            oper = self.opers[0]
            ret.append((oper.getOperValue(self), flags))
        elif self.opcode == INS_BL:
            oper = self.opers[0]
            ret.append((oper.getOperValue(self), flags | envi.BR_PROC))
        return ret

    def render(self, mcanv):
        """
        Render this opcode to the specified memory canvas
        """
        mcanv.addNameText(self.mnem, typename="mnemonic")
        mcanv.addText(" ")

        # Allow each of our operands to render
        imax = len(self.opers)
        lasti = imax - 1
        for i in xrange(imax):
            oper = self.opers[i]
            oper.render(mcanv, self, i)
            if i != lasti:
                mcanv.addText(",")
        #mcanv.addText('; %s' % repr(self))

    def __repr__(self):
        mnem = self.mnem
        # FIXME put in S flag! -- scratch that... optimize and preload a list of these combos!

        # FIXME actually all these are broke... (iflags)
        # FIXME handle these in parsing too!
        if self.iflags & IF_PSR_S:
            mnem += 's'
        if self.iflags & IF_B:
            mnem += 'b'
        if self.iflags & IF_H:
            mnem += 'h'
        if self.iflags & 0x800:
            idx = (self.iflags>>12) & 3
            mnem += daib[idx]
        
        x = [mnem,]
        
        for o in self.opers:
            x.append(o.repr(self))
        return " ".join(x)

class ArmRegOper(envi.Operand):
    def __init__(self, reg):
        self.reg = reg

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.reg != oper.reg:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        rname = arm_regnames[self.reg]
        mcanv.addNameText(rname, typename='registers')

    def repr(self, op):
        return arm_regnames[self.reg]

class ArmRegShiftRegOper(envi.Operand):

    def __init__(self, reg, shtype, shreg):
        self.reg = reg
        self.shtype = shtype
        self.shreg = shreg

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.reg != oper.reg:
            return False
        if self.shtype != oper.shtype:
            return False
        if self.shreg != oper.shreg:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        rname = arm_regnames[self.reg]
        mcanv.addNameText(rname, typename='registers')
        mcanv.addText(' ')
        mcanv.addNameText(shift_names[self.shtype])
        mcanv.addText(' ')
        mcanv.addNameText(arm_regnames[self.shreg], typename='registers')

    def repr(self, op):
        rname = arm_regnames[self.reg]
        return '%s %s %s' % (rname, shift_names[self.shtype], arm_regnames[self.shreg])

class ArmRegShiftImmOper(envi.Operand):

    def __init__(self, reg, shtype, shimm):
        self.reg = reg
        self.shtype = shtype
        self.shimm = shimm

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.reg != oper.reg:
            return False
        if self.shtype != oper.shtype:
            return False
        if self.shimm != oper.shimm:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        rname = arm_regnames[self.reg]
        mcanv.addNameText(rname, typename='registers')
        if self.shimm:
            mcanv.addText(' ')
            mcanv.addNameText(shift_names[self.shtype])
            mcanv.addText(' ')
            mcanv.addNameText('#%d' % self.shimm)

    def repr(self, op):
        rname = arm_regnames[self.reg]
        return '%s %s #%d' % (rname, shift_names[self.shtype], self.shimm)

class ArmImmOper(envi.Operand):

    def __init__(self, val):
        self.val = val

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        mcanv.addNameText('#%d' % self.val)

    def repr(self, op):
        return '#%d' % self.val

class ArmScaledOffsetOper(envi.Operand):
    def __init__(self, base_reg, offset_reg, shtype, shval, va, pubwl=0):
        self.base_reg = base_reg
        self.offset_reg = offset_reg
        self.shtype = shtype
        self.shval = shval
        self.pubwl = pubwl

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.base_reg != oper.base_reg:
            return False
        if self.offset_reg != oper.offset_reg:
            return False
        if self.shtype != oper.shtype:
            return False
        if self.shval != oper.shval:
            return False
        if self.pubwl != oper.pubwl:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        pom = ('-','')[(self.pubwl>>5)&1]
        idxing = self.pubwl & 0x12
        basereg = arm_regnames[self.base_reg]
        offreg = arm_regnames[self.offset_reg]
        shname = shift_names[self.shtype]

        mcanv.addText('[')
        mcanv.addNameText(basereg, typename='registers')
        if idxing == 0:
            mcanv.addText('], ')
        else:
            mcanv.addText(', ')
        mcanv.addText(pom)
        mcanv.addNameText(offreg, typename='registers')
        mcanv.addText(' ')
        mcanv.addNameText(shname)
        mcanv.addText(' ')
        mcanv.addNameText('#%d' % self.shval)
        if idxing == 0x10:
            mcanv.addText(']')
        elif idxing != 0:
            mcanv.addText(']!')

    def repr(self, op):
        pom = ('-','')[(self.pubwl>>5)&1]
        idxing = self.pubwl & 0x12
        basereg = arm_regnames[self.base_reg]
        offreg = arm_regnames[self.offset_reg]
        shname = shift_names[self.shtype]
        if idxing == 0:         # post-indexed
            tname = '[%s], %s%s %s #%d' % (basereg, pom, offreg, shname, self.shval)
        elif idxing == 0x10:
            tname = '[%s, %s%s %s #%d]' % (basereg, pom, offreg, shname, self.shval)
        else:               # pre-indexed
            tname = '[%s, %s%s %s #%d]!' % (basereg, pom, offreg, shname, self.shval)
        return tname

class ArmRegOffsetOper(envi.Operand):
    def __init__(self, base_reg, offset_reg, va, pubwl=0):
        self.base_reg = base_reg
        self.offset_reg = offset_reg
        self.pubwl = pubwl

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.base_reg != oper.base_reg:
            return False
        if self.offset_reg != oper.offset_reg:
            return False
        if self.pubwl != oper.pubwl:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        pom = ('-','')[(self.pubwl>>5)&1]
        idxing = self.pubwl & 0x12
        basereg = arm_regnames[self.base_reg]
        offreg = arm_regnames[self.offset_reg]

        mcanv.addText('[')
        mcanv.addNameText(basereg, typename='registers')
        if idxing == 0:
            mcanv.addText('] ')
        else:
            mcanv.addText(', ')
        mcanv.addText(pom)
        mcanv.addNameText(offreg, typename='registers')
        if idxing == 0x10:
            mcanv.addText(']')
        elif idxing != 0:
            mcanv.addText(']!')

    def repr(self, op):
        pom = ('-','')[(self.pubwl>>5)&1]
        idxing = self.pubwl & 0x12
        basereg = arm_regnames[self.base_reg]
        offreg = arm_regnames[self.offset_reg]
        if idxing == 0:         # post-indexed
            tname = '[%s] %s%s' % (basereg, pom, offreg)
        elif idxing == 0x10:  # offset addressing, not updated
            tname = '[%s, %s%s]' % (basereg, pom, offreg)
        else:               # pre-indexed
            tname = '[%s, %s%s]!' % (basereg, pom, offreg)
        return tname

class ArmImmOffsetOper(envi.Operand):
    def __init__(self, base_reg, offset, va, pubwl=0x80):
        self.base_reg = base_reg
        self.offset = offset
        self.pubwl = pubwl

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.base_reg != oper.base_reg:
            return False
        if self.offset != oper.offset:
            return False
        if self.pubwl != oper.pubwl:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def render(self, mcanv, op, idx):
        pom = ('-','')[(self.pubwl>>5)&1]
        idxing = self.pubwl & 0x12
        basereg = arm_regnames[self.base_reg]
        mcanv.addText('[')
        mcanv.addNameText(basereg, typename='registers')
        if self.offset == 0:
            mcanv.addText(']')
        else:
            if idxing == 0:
                mcanv.addText('] ')
            else:
                mcanv.addText(', ')
            mcanv.addNameText('#%s%d' % (pom,self.offset))
            if idxing == 0x10:
                mcanv.addText(']')
            elif idxing != 0:
                mcanv.addText(']!')

    def repr(self, op):
        pom = ('-','')[(self.pubwl>>5)&1]
        idxing = (self.pubwl>>2) & 0x12
        basereg = arm_regnames[self.base_reg]
        if self.offset == 0:
            tname = '[%s]' % basereg
        elif idxing == 0:         # post-indexed
            tname = '[%s] #%s%d' % (basereg, pom, self.offset)
        else:
            if idxing == 0x10:  # offset addressing, not updated
                tname = '[%s, #%s%s]' % (basereg,pom,self.offset)
            else:               # pre-indexed
                tname = '[%s, #%s%s]!' % (basereg,pom,self.offset)
        return tname

class ArmOffsetOper(envi.Operand):        # ArmImmOper but for Branches
    def __init__(self, val, va):
        self.val = val # depending on mode, this is reg/imm
        self.va = va

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        if self.va != oper.va:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return self.va + self.val + op.size + 4 # FIXME WTF?

    def render(self, mcanv, op, idx):
        value = self.getOperValue(op)
        if mcanv.mem.isValidPointer(value):
            name = addrToName(mcanv, value)
            mcanv.addVaText(name, value)
        else:
            mcanv.addVaText('0x%.8x' % value, value)

    def repr(self, op):
        targ = self.getOperValue(op)
        tname = "&0x%.8x" % targ
        return tname

class ArmPgmStatRegOper(envi.Operand):
    # FIXME @las Why do we need this?
    def __init__(self, val):
        self.val = val # depending on mode, this is reg/imm

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def repr(self, op):
        s = ["PSR_",psr_fields[self.val]]
        return "".join(s)
    
class ArmEndianOper(ArmImmOper):
    def repr(self, op):
        return endian_names[self.val]

class ArmRegListOper(envi.Operand):
    def __init__(self, val, puswl):
        self.val = val
        self.puswl = puswl

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        if self.puswl != oper.puswl:
            return False
        return True

    def render(self, mcanv, op, idx):
        mcanv.addText('[')
        for l in xrange(16):
            if self.val & 1<<l:
                mcanv.addNameText(arm_regnames[l], typename='registers')
                mcanv.addText(', ')
        mcanv.addText(']')

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def repr(self, op):
            s = [ "[" ]
            for l in xrange(16):
                if (self.val & (1<<l)):
                    s.append(arm_regnames[l])
            s.append(']')
            return " ".join(s)
    
aif_flags = (None, 'f','i','if','a','af','ai','aif')
class ArmPSRFlagsOper(envi.Operand):
    def __init__(self, flags):
        self.flags = flags

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.flags != oper.flags:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def repr(self, op):
        return aif_flags[self.flags]

class ArmCoprocOpcodeOper(envi.Operand):
    def __init__(self, val):
        self.val = val
        
    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def repr(self, op):
        return "%d"%self.val

class ArmCoprocOper(envi.Operand):
    def __init__(self, val):
        self.val = val
        
    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def repr(self, op):
        return "p%d"%self.val

class ArmCoprocRegOper(envi.Operand):
    def __init__(self, val, shtype=None, shval=None):
        self.val = val # depending on mode, this is reg/imm
        self.shval = shval
        self.shtype = shtype

    def __eq__(self, oper):
        if not isinstance(oper, self.__class__):
            return False
        if self.val != oper.val:
            return False
        if self.shval != oper.shval:
            return False
        if self.shtype != oper.shtype:
            return False
        return True

    def getOperValue(self, op, emu=None):
        return None # FIXME

    def repr(self, op):
        return "c%d"%self.val


MODE_ARM        = 0
MODE_THUMB      = 1
MODE_JAZELLE    = 2

class ArmDisasm:
    def __init__(self):
        self._disasm = None
        self._disasms = (
            ArmStdDisasm(),
            ArmThumbDisasm(),
            ArmJazDisasm(),
        )
        
        self.setMode(MODE_ARM)
        
    def setMode(self, mode_num):
        self._disasm = self._disasms[mode_num]
    
    def disasm(self, bytes, offset, va):
        return self._disasm.disasm(bytes, offset, va)
    
class ArmStdDisasm:
    def __init__(self):
        # any speedy stuff here
        self._dis_regctx = ArmRegisterContext()


    def disasm(self, bytes, offset, va):
        """
        Parse a sequence of bytes out into an envi.Opcode instance.
        """
        opbytes = bytes[offset:offset+4]
        opval, = struct.unpack("<L", opbytes)
        
        #if opint > 0xF000:
            ## Special Condition Code 0b1111

        cond = opval >> 28

        # Begin the table lookup sequence with the first 3 non-cond bits
        encfam = (opval >> 25) & 0x7
        if cond == COND_EXTENDED:
            enc = 8
        else:
            enc,nexttab = inittable[encfam]
            if nexttab != None: # we have to sub-parse...
                for mask,val,penc in nexttab:
                    if (opval & mask) == val:
                        enc = penc
                        break

        # If we don't know the encoding by here, we never will ;)
        if enc == None:
            raise InvalidInstruction("omg")

        #print "ENCFAM",encfam
        #print "COND",cond
        #print "ENCODING",enc

        opcode, mnem, olist, flags = ienc_parsers[enc](opval, va)
        mnem += cond_codes.get(cond)
        # Ok...  if we're a non-conditional branch, *or* we manipulate PC unconditionally,
        # lets call ourself envi.IF_NOFALL
        if cond == COND_AL:
            if opcode == INS_B:
                flags |= envi.IF_NOFALL
            elif (  len(olist) and 
                    isinstance(olist[0], ArmRegOper) and
                    olist[0].reg == REG_PC ):
                flags |= envi.IF_NOFALL

        # FIXME conditionals are currently plumbed as "prefixes".  Perhaps normalize to that...
        op = ArmOpcode(va, opcode, mnem, cond, 4, olist, flags)

        return op
        
class ArmJazDisasm:
    def __init__(self):
        # any speedy stuff here
        self._dis_regctx = ArmRegisterContext()


    def disasm(self, bytes, offset, va):
        pass
    
class ArmThumbDisasm:
    def __init__(self):
        # any speedy stuff here
        self._dis_regctx = ArmRegisterContext()


    def disasm(self, bytes, offset, va):
        pass

