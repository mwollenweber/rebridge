
import envi.registers as e_reg

reg_table = []
arm_regnames = ("r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","sl","fp","ip","sp","lr","pc","cpsr")
reg_base = ("r0_","r1_","r2_","r3_","r4_","r5_","r6_","r7_","r8_","r9_","r10_","r11_","r12_","r13_","r14_","error-r15_","SPSR_")
modes = ("user","fiq","irq","svc","abt","und")
mode_defs = {   # ( Arm_regs, 
    "user": ( 15, ),  # user mode
    "fiq":  ( 8, ),
    "irq":  ( 13, ),
    "svc":  ( 13, ),
    "abt":  ( 13, ),
    "und":  ( 13, ),
}

for midx in range(len(modes)):
    mode = modes[midx]
    creg_count = mode_defs[mode][0]
    for x in range(creg_count):
        # (reg_name, bitsize, regidx_for_emulation)
        reg_table.append((arm_regnames[x], 32, x))
    
    for x in range(creg_count, 16):
        reg_table.append((reg_base[x] + mode, 32, (midx * 17)+x))
    
    reg_table.append(("pc", 32, 16))
    
    reg_table.append((reg_base[x] + mode, 32, (midx * 17)+x))
    #reg_table.append((reg_base + mode, 32, (midx * 17)+x))
    
#FIXME: What to do with CPSR...  hack... "hey yall check this out!"
reg_table.append(("cpsr", 32, None))    # CPSR needs to access some other SPSR_, most often SPSR_user

REG_OFFSET_FIQ = 17
REG_OFFSET_IRQ = 17 * 1
REG_OFFSET_SVC = 17 * 2
REG_OFFSET_ABT = 17 * 3
REG_OFFSET_UND = 17 * 4
REG_OFFSET_CPSR = 17 * 5

REG_PC = 0x10
REG_SP = 0xe
REG_BP = None
REG_PSR = REG_OFFSET_CPSR
REG_FLAGS = REG_OFFSET_CPSR    #same location, backward-compat name

PSR_N = 31  # negative
PSR_Z = 30  # zero
PSR_C = 29  # carry
PSR_V = 28  # oVerflow
PSR_Q = 27
PSR_J = 24
PSR_GE = 16
PSR_E = 9
PSR_A = 8
PSR_I = 7
PSR_F = 6
PSR_T = 5
PSR_M = 0

psr_fields = [None for x in xrange(32)]
psr_fields[PSR_M] = "M"
psr_fields[PSR_T] = "T"
psr_fields[PSR_F] = "F"
psr_fields[PSR_I] = "I"
psr_fields[PSR_A] = "A"
psr_fields[PSR_E] = "E"
psr_fields[PSR_GE] = "GE"
psr_fields[PSR_J] = "J"
psr_fields[PSR_Q] = "Q"
psr_fields[PSR_V] = "V"
psr_fields[PSR_C] = "C"
psr_fields[PSR_Z] = "Z"
psr_fields[PSR_N] = "N"

ArmRegs = [reg_table[x][:2] for x in xrange(REG_OFFSET_CPSR)]
ArmMeta =tuple([("N", REG_FLAGS, PSR_N, 1),
                ("Z", REG_FLAGS, PSR_Z, 1),
                ("C", REG_FLAGS, PSR_C, 1),
                ("V", REG_FLAGS, PSR_V, 1),
                ("Q", REG_FLAGS, PSR_Q, 1),
                ("J", REG_FLAGS, PSR_J, 1),
                ("GE",REG_FLAGS, PSR_GE, 4),
                ("E", REG_FLAGS, PSR_E, 1),
                ("A", REG_FLAGS, PSR_A, 1),
                ("I", REG_FLAGS, PSR_I, 1),
                ("F", REG_FLAGS, PSR_F, 1),
                ("T", REG_FLAGS, PSR_T, 1),
                ("M", REG_FLAGS, PSR_M, 5),
                ])


class ArmRegisterContext(e_reg.RegisterContext):
    def __init__(self):
        e_reg.RegisterContext.__init__(self)
        self.loadRegDef(ArmRegs)
        self.loadRegMetas(ArmMeta)
        self.setRegisterIndexes(REG_PC, REG_SP)

