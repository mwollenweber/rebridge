
"""
The initial arm module.
"""

import struct

import envi
from envi.archs.arm import *
from envi.archs.arm.regs import *



# CPU state (memory, regs)
# CPU mode  (User, FIQ, IRQ, supervisor, Abort, Undefined, System)
# banked registers (an array of arrays of registers)
# 