"""
Watchpoint Objects
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
from vtrace import *
from vtrace.breakpoints import *

class Watchpoint(Breakpoint):
    """
    The basic "break on access" watchpoint.  Extended from 
    Breakpoints and handled almost exactly the same way...
    """
    def __init__(self, addr, expression=None, size=4, perms="rw"):
        Breakpoint.__init__(self, addr, expression=expression)
        self.wpsize = size
        self.wpperms = perms

    def getName(self):
        bname = Breakpoint.getName(self)
        return "%s (%s %d bytes)" % (bname, self.wpperms, self.wpsize)

    def activate(self, trace):
        trace.requireAttached()
        if not self.active:
            if self.address != None:
                trace.archAddWatchpoint(self.address, size=self.wpsize, perms=self.wpperms)
                self.active = True
        return self.active

    def deactivate(self, trace):
        trace.requireAttached()
        if self.active:
            trace.archRemWatchpoint(self.address)
            self.active = False
        return self.active

class PageWatchpoint(Watchpoint):
    """
    A special "watchpoint" that uses memory permissions to
    watch for accesses to whole memory maps.  This *requires* OS
    help and only works on platforms which support:
    * platformProtectMemory()
    * signal/exceptions which denote the fault address on SEGV

    NOTE: These *must* be added page aligned
    """
    def __init__(self, addr, expression=None, size=4, perms="rw"):
        Watchpoint.__init__(self, addr, expression=expression, size=size, perms=perms)
        self.perms = None

    def activate(self, trace):
        trace.requireNotRunning()
        if not self.active:
            if self.perms == None:
                map = trace.getMemoryMap(self.address)
                self.perms = map[2]
            trace.protectMemory(self.address, self.wpsize, e_mem.MM_READ)
            self.active = True
        return self.active

    def deactivate(self, trace):
        trace.requireNotRunning()
        if self.active:
            trace.protectMemory(self.address, self.wpsize, self.perms)
            self.active = False
        return self.active

