"""
Similar to the memory subsystem, this is a unified way to
access information about objects which contain registers
"""

import envi.bits as e_bits

class InvalidRegisterName(Exception):
    pass

class RegisterContext:

    def __init__(self, regdef=(), metas=(), pcindex=None, spindex=None):
        """
        Hand in a register definition which consists of
        a list of (<name>, <width>) tuples.
        """
        self.loadRegDef(regdef)
        self.loadRegMetas(metas)
        self.setRegisterIndexes(pcindex, spindex)

        self._rctx_dirty = False

    def getRegisterSnap(self):
        """
        Use this to bulk save off the register state.
        """
        return list(self._rctx_vals)

    def setRegisterSnap(self, snap):
        """
        Use this to bulk restore the register state.

        NOTE: This may only be used under the assumption that the
              RegisterContext has been initialized the same way
              (like context switches in tracers, or emulaction snaps)
        """
        self._rctx_vals = snap

    def isDirty(self):
        """
        Returns true if registers in this context have been modififed
        since their import.
        """
        return self._rctx_dirty

    def setRegisterIndexes(self, pcindex, spindex):
        self._rctx_pcindex = pcindex
        self._rctx_spindex = spindex

    def loadRegDef(self, regdef):
        """
        Load a register definition.  A register definition consists
        of a list of tuples with the following format:
        (regname, regwidth)

        NOTE: All widths in envi RegisterContexts are in bits.
        """
        self._rctx_regdef = regdef # Save this for 
        self._rctx_names = {}
        self._rctx_ids = {}
        self._rctx_widths = []
        self._rctx_vals  = []
        self._rctx_masks = []

        for i,(name,width) in enumerate(regdef):
            self._rctx_names[name] = i
            self._rctx_ids[i] = name
            self._rctx_widths.append(width)
            self._rctx_masks.append((2**width)-1)
            self._rctx_vals.append(0)

    def loadRegMetas(self, metas):
        """
        Load a set of defined "meta" registers for this architecture.  Meta
        registers are defined as registers who exist as a subset of the bits
        in some other "real" register. The argument metas is a list of tuples
        with the following format:
        (regname, reg_shift_offset, reg_width)
        The given example is for the AX register in the i386 subsystem
        regname: "ax"
        reg_shift_offset: 0
        reg_width: 16
        """
        self._rctx_regmetas = metas
        for name,idx,offset,width in metas:
            self.addMetaRegister(name,idx, offset, width)

    def addMetaRegister(self, name, idx, offset, width):
        """
        Meta registers are registers which are really just directly
        addressable parts of already existing registers (eax -> al).

        To add a meta register, you give the name, the idx of the *real*
        register, the width of the meta reg, and it's left shifted (in bits)
        offset into the real register value.  The RegisterContext will take
        care of accesses after that.
        """
        newidx = (offset << 24) + (width << 16) + idx
        self._rctx_names[name] = newidx
        self._rctx_ids[newidx] = name

    def isMetaRegister(self, index):
        return (index & 0xffff) == index

    def _rctx_Import(self, sobj):
        """
        Given an object with attributes with the same names as
        registers in our context, populate our values from it.

        NOTE: This also clears the dirty flag
        """
        # On import from a structure, we are clean again.
        self._rctx_dirty = False
        for name,idx in self._rctx_names.items():
            # Skip meta registers
            if (idx & 0xffff) != idx:
                continue
            x = getattr(sobj, name, None)
            if x != None:
                self._rctx_vals[idx] = x

    def _rctx_Export(self, sobj):
        """
        Given an object with attributes with the same names as
        registers in our context, set the ones he has to match
        our values.
        """
        for name,idx in self._rctx_names.items():
            # Skip meta registers
            if (idx & 0xffff) != idx:
                continue
            if hasattr(sobj, name):
                setattr(sobj, name, self._rctx_vals[idx])

    def reprRegister(self, idx):
        """
        This may be used to allow a register context to provide
        extended repr (flags breakouts, etc) info about a register.
        """
        width = self._rctx_widths.get(idx)
        reg = self.getRegisger(idx)
        return e_bits.hex(reg, width/8)

    def getRegisterInfo(self, meta=False):
        """
        Return an object which can be stored off, and restored
        to re-initialize a register context.  (much like snapshot
        but it takes the definitions with it)
        """
        regdef = self._rctx_regdef
        regmeta = self._rctx_regmetas
        pcindex = self._rctx_pcindex
        spindex = self._rctx_spindex
        snap = self.getRegisterSnap()

        return (regdef, regmeta, pcindex, spindex, snap)

    def setRegisterInfo(self, info):
        """
        Import the exported data from 
        """
        regdef, regmeta, pcindex, spindex, snap = info
        self.loadRegDef(regdef)
        self.loadRegMetas(regmeta)
        self.setRegisterIndexes(pcindex, spindex)
        self.setRegisterSnap(snap)

    def getRegisterName(self, index):
        return self._rctx_ids.get(index,"REG%.8x" % index)

    def getProgramCounter(self):
        """
        Get the value of the program counter for this register
        context.
        """
        return self.getRegister(self._rctx_pcindex)

    def setProgramCounter(self, value):
        """
        Set the value of the program counter for this register
        contex.
        """
        self.setRegister(self._rctx_pcindex, value)

    def getStackCounter(self):
        return self.getRegister(self._rctx_spindex)

    def setStackCounter(self, value):
        self.setRegister(self._rctx_spindex, value)

    def getRegisterByName(self, name):
        idx = self._rctx_names.get(name)
        if idx == None:
            raise InvalidRegisterName("Unknown Register: %s" % name)
        return self.getRegister(idx)

    def setRegisterByName(self, name, value):
        idx = self._rctx_names.get(name)
        if idx == None:
            raise InvalidRegisterName("Unknown Register: %s" % name)
        self.setRegister(idx, value)

    def getRegisterNames(self):
        """
        This is *not* the same as the envi.ArchitectureModule API for this
        because we may be talking about a particular subset of the register space.
        """
        return self._rctx_names.keys()

    def getRegisters(self):
        """
        Get all the *real* registers from this context as a dictionary of name
        value pairs.
        """
        ret = {}
        for name,idx in self._rctx_names.items():
            if (idx & 0xffff) != idx:
                continue
            ret[name] = self.getRegister(idx)
        return ret

    def setRegisters(self, regdict):
        """
        For any name value pairs in the specified dictionary, set the current
        register values in this context.
        """
        for name,value in regdict.items():
            self.setRegisterByName(name, value)

    def getRegisterIndex(self, name):
        """
        Get a register index by name.
        (faster to use the index multiple times)
        """
        return self._rctx_names.get(name)

    def getRegisterWidth(self, index):
        """
        Return the width of the register which lives at the specified
        index (width is always in bits).
        """
        ridx = index & 0xffff
        if ridx == index:
            return self._rctx_widths[index]
        width  = (index >> 16) & 0xff
        return width

    def getRegister(self, index):
        """
        Return the current value of the specified register index.
        """
        ridx = index & 0xffff
        if ridx == index:
            return self._rctx_vals[ridx]

        offset = (index >> 24) & 0xff
        width  = (index >> 16) & 0xff

        mask = (2**width)-1
        return (self._rctx_vals[ridx] >> offset) & mask

    def setRegister(self, index, value):
        """
        Set a register value by index.
        """
        self._rctx_dirty = True

        ridx = index & 0xffff
        if ridx == index:
            self._rctx_vals[ridx] = (value & self._rctx_masks[ridx])
            return

        # If we get here, it's a meta register index.
        # NOTE: offset/width are in bits...
        offset = (index >> 24) & 0xff
        width  = (index >> 16) & 0xff

        #FIXME is it faster to generate or look thses up?
        mask = (2**width)-1
        mask = mask << offset

        # NOTE: basewidth is in *bits*
        basewidth = self._rctx_widths[ridx]
        basemask  = (2**basewidth)-1

        # cut a whole in basemask at the size/offset of mask
        finalmask = basemask ^ mask

        curval = self._rctx_vals[ridx]

        self._rctx_vals[ridx] = (curval & finalmask) | (value << offset)

def addLocalEnums(l, regdef):
    """
    Update a dictionary (or module locals) with REG_FOO index
    values for all the base registers defined in regdef.
    """
    for i,(rname,width) in enumerate(regdef):
        l["REG_%s" % rname.upper()] = i

def addLocalMetas(l, metas):
    """
    Update a dictionary (or module locals) with REG_FOO index
    values for all meta registers defined in metas.
    """
    for name,idx,offset,width in metas:
        l["REG_%s" % name.upper()] = (offset << 24) | (width << 16) | idx

