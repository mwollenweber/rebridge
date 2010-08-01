"""
Linux Platform Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import struct
import signal
import traceback
import platform

import envi.memory as e_mem
import envi.registers as e_reg

import vtrace
import vtrace.platforms.base as v_base
import vtrace.platforms.posix as v_posix
import vtrace.archs.i386 as v_i386
import vtrace.archs.amd64 as v_amd64

from ctypes import *
import ctypes.util as cutil

libc = CDLL(cutil.find_library("c"))

libc.lseek64.restype = c_ulonglong
libc.lseek64.argtypes = [c_uint, c_ulonglong, c_uint]
libc.read.restype = c_long
libc.read.argtypes = [c_uint, c_void_p, c_long]
libc.write.restype = c_long
libc.write.argtypes = [c_uint, c_void_p, c_long]

O_RDWR = 2
O_LARGEFILE = 0x8000

MAP_ANONYMOUS = 0x20
MAP_PRIVATE = 0x02

# Linux specific ptrace extensions
PT_GETREGS = 12
PT_SETREGS = 13
PT_GETFPREGS = 14
PT_SETFPREGS = 15
PT_ATTACH = 16
PT_DETACH = 17
PT_GETFPXREGS = 18
PT_SETFPXREGS = 19
PT_SYSCALL = 24
PT_SETOPTIONS = 0x4200
PT_GETEVENTMSG = 0x4201
PT_GETSIGINFO = 0x4202
PT_SETSIGINFO = 0x4203
# PT set options stuff.  ONLY TRACESYSGOOD may be used in 2.4...
PT_O_TRACESYSGOOD   = 0x00000001 # add 0x80 to TRAP when generated by syscall
# For each of the options below, the stop signal is (TRAP | PT_EVENT_FOO << 8)
PT_O_TRACEFORK      = 0x00000002 # Cause a trap at fork
PT_O_TRACEVFORK     = 0x00000004 # Cause a trap at vfork
PT_O_TRACECLONE     = 0x00000008 # Cause a trap at clone
PT_O_TRACEEXEC      = 0x00000010 # Cause a trap at exec
PT_O_TRACEVFORKDONE = 0x00000020 # Cause a trap when vfork done
PT_O_TRACEEXIT      = 0x00000040 # Cause a trap on exit
PT_O_MASK           = 0x0000007f
# Ptrace event types (TRAP | PT_EVENT_FOO << 8) means that type
# when using GETEVENTMSG for most of these, the new pid is the data
PT_EVENT_FORK       = 1
PT_EVENT_VFORK      = 2
PT_EVENT_CLONE      = 3
PT_EVENT_EXEC       = 4
PT_EVENT_VFORK_DONE = 5
PT_EVENT_EXIT       = 6

# Used to tell some of the additional events apart
SIG_LINUX_SYSCALL = signal.SIGTRAP | 0x80
SIG_LINUX_CLONE = signal.SIGTRAP | (PT_EVENT_CLONE << 8)

class user_regs_i386(Structure):
    _fields_ = (
        ("ebx",  c_ulong),
        ("ecx",  c_ulong),
        ("edx",  c_ulong),
        ("esi",  c_ulong),
        ("edi",  c_ulong),
        ("ebp",  c_ulong),
        ("eax",  c_ulong),
        ("ds",   c_ushort),
        ("__ds", c_ushort),
        ("es",   c_ushort),
        ("__es", c_ushort),
        ("fs",   c_ushort),
        ("__fs", c_ushort),
        ("gs",   c_ushort),
        ("__gs", c_ushort),
        ("orig_eax", c_ulong),
        ("eip",  c_ulong),
        ("cs",   c_ushort),
        ("__cs", c_ushort),
        ("eflags", c_ulong),
        ("esp",  c_ulong),
        ("ss",   c_ushort),
        ("__ss", c_ushort),
    )


class USER_i386(Structure):
    _fields_ = (
        # NOTE: Expand out the user regs struct so
        #       we can make one call to _rctx_Import
        ("regs",       user_regs_i386),
        ("u_fpvalid",  c_ulong),
        ("u_tsize",    c_ulong),
        ("u_dsize",    c_ulong),
        ("u_ssize",    c_ulong),
        ("start_code", c_ulong),
        ("start_stack",c_ulong),
        ("signal",     c_ulong),
        ("reserved",   c_ulong),
        ("u_ar0",      c_void_p),
        ("u_fpstate",  c_void_p),
        ("magic",      c_ulong),
        ("u_comm",     c_char*32),
        ("debug0",     c_ulong),
        ("debug1",     c_ulong),
        ("debug2",     c_ulong),
        ("debug3",     c_ulong),
        ("debug4",     c_ulong),
        ("debug5",     c_ulong),
        ("debug6",     c_ulong),
        ("debug7",     c_ulong),
    )

class user_regs_amd64(Structure):
    _fields_ = [
        ('r15',      c_uint64),
        ('r14',      c_uint64),
        ('r13',      c_uint64),
        ('r12',      c_uint64),
        ('rbp',      c_uint64),
        ('rbx',      c_uint64),
        ('r11',      c_uint64),
        ('r10',      c_uint64),
        ('r9',       c_uint64),
        ('r8',       c_uint64),
        ('rax',      c_uint64),
        ('rcx',      c_uint64),
        ('rdx',      c_uint64),
        ('rsi',      c_uint64),
        ('rdi',      c_uint64),
        ('orig_rax', c_uint64),
        ('rip',      c_uint64),
        ('cs',       c_uint64),
        ('eflags',   c_uint64),
        ('rsp',      c_uint64),
        ('ss',       c_uint64),
        ('fs_base',  c_uint64),
        ('gs_base',  c_uint64),
        ('ds',       c_uint64),
        ('es',       c_uint64),
        ('fs',       c_uint64),
        ('gs',       c_uint64),
    ]

# Modern linux only lets us write to these...
dbgregs = (0,1,2,3,6,7)

class LinuxMixin(v_posix.PtraceMixin, v_posix.PosixMixin):
    """
    The mixin to take care of linux specific platform traits.
    (mostly proc)
    """

    def __init__(self):
        # Wrap reads from proc in our worker thread
        v_posix.PtraceMixin.__init__(self)
        v_posix.PosixMixin.__init__(self)
        self.pthreads = [] # FIXME perhaps make this posix-wide not just linux eventually...
        self.threadWrap("platformAllocateMemory", self.platformAllocateMemory)
        self.threadWrap("getPtraceEvent", self.getPtraceEvent)
        self.threadWrap("platformReadMemory", self.platformReadMemory)
        self.threadWrap("platformWriteMemory", self.platformWriteMemory)
        if platform.release().startswith("2.4"):
            self.threadWrap("platformWait", self.platformWait)
        self.threadWrap("doAttachThread", self.doAttachThread)
        self.nptlinit = False
        self.memfd = None

        self.initMode("Syscall", False, "Break On Syscalls")

    def platformExec(self, cmdline):
        pid = v_posix.PtraceMixin.platformExec(self, cmdline)
        self.pthreads = [pid,]
        self.setMeta("ExeName",self._findExe(pid))
        return pid

    def setupMemFile(self, offset):
        """
        A utility to open (if necissary) and seek the memfile
        """
        if self.memfd == None:
            self.memfd = libc.open("/proc/%d/mem" % self.pid, O_RDWR | O_LARGEFILE, 0755)

	x = libc.lseek64(self.memfd, offset, 0)

    #FIXME this is intel specific and should probably go in with the regs
    def platformAllocateMemory(self, size, perms=e_mem.MM_RWX, suggestaddr=0):
        sp = self.getStackCounter()
        pc = self.getProgramCounter()

        # Xlate perms (mmap is backward)
        realperm = 0
        if perms & e_mem.MM_READ:
            realperm |= 1
        if perms & e_mem.MM_WRITE:
            realperm |= 2
        if perms & e_mem.MM_EXEC:
            realperm |= 4

        #mma is struct of mmap args for linux syscall
        mma = struct.pack("<6L", suggestaddr, size, realperm, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0)

        regsave = self.getRegisters()

        stacksave = self.readMemory(sp, len(mma))
        ipsave = self.readMemory(pc, 2)

        SYS_mmap = 90

        self.writeMemory(sp, mma)
        self.writeMemory(pc, "\xcd\x80")
        self.setRegisterByName("eax", SYS_mmap)
        self.setRegisterByName("ebx", sp)
        self._syncRegs()

        try:
            # Step over our syscall instruction
            tid = self.getMeta("ThreadId", 0)
            self.platformStepi()
            os.waitpid(tid, 0)
            eax = self.getRegisterByName("eax")
            if eax & 0x80000000:
                raise Exception("Linux mmap syscall error: %d" % eax)
            return eax

        finally:
            # Clean up all our fux0ring
            self.writeMemory(sp, stacksave)
            self.writeMemory(pc, ipsave)
            self.setRegisters(regsave)

    def posixCreateThreadHack(self):
        for tid in self.threadsForPid(self.pid):
            if tid == self.pid:
                continue
            self.attachThread(tid)
        v_posix.PosixMixin.posixCreateThreadHack(self)

    def platformReadMemory(self, address, size):
        """
        A *much* faster way of reading memory that the 4 bytes
        per syscall allowed by ptrace
        """
        self.setupMemFile(address)
        # Use ctypes cause python implementation is teh ghey
        buf = create_string_buffer(size)
        x = libc.read(self.memfd, addressof(buf), size)
        if x != size:
            #libc.perror('libc.read %d (size: %d)' % (x,size))
            raise Exception("reading from invalid memory %s (%d returned)" % (hex(address), x))
        # We have to slice cause ctypes "helps" us by adding a null byte...
        return buf.raw

    def whynot_platformWriteMemory(self, address, data):
        """
        A *much* faster way of writting memory that the 4 bytes
        per syscall allowed by ptrace
        """
        self.setupMemFile(address)
        buf = create_string_buffer(data)
        size = len(data)
        x = libc.write(self.memfd, addressof(buf), size)
        if x != size:
            libc.perror('write mem failed: 0x%.8x (%d)' % (address, size))
            raise Exception("write memory failed: %d" % x)
        return x

    def _findExe(self, pid):
        exe = os.readlink("/proc/%d/exe" % pid)
        if "(deleted)" in exe:
            if "#prelink#" in exe:
                exe = exe.split(".#prelink#")[0]
            elif ";" in exe:
                exe = exe.split(";")[0]
            else:
                exe = exe.split("(deleted)")[0].strip()
        return exe

    def platformAttach(self, pid):
        self.pthreads = [pid,]
        self.setMeta("ThreadId", pid)
        if v_posix.ptrace(PT_ATTACH, pid, 0, 0) != 0:
            raise Exception("PT_ATTACH failed!")
        self.setupPtraceOptions(pid)
        self.setMeta("ExeName", self._findExe(pid))

    def platformPs(self):
        pslist = []
        for dname in os.listdir("/proc/"):
            try:
                if not dname.isdigit():
                    continue
                cmdline = file("/proc/%s/cmdline" % dname).read()
                cmdline = cmdline.replace("\x00"," ")
                if len(cmdline) > 0:
                    pslist.append((int(dname),cmdline))
            except:
                pass # Permissions...  quick process... whatev.
        return pslist

    def attachThread(self, tid, attached=False):
        self.doAttachThread(tid,attached=attached)
        self.setMeta("ThreadId", tid)
        self.fireNotifiers(vtrace.NOTIFY_CREATE_THREAD)

    def platformWait(self):
        # Blocking wait once...
        pid, status = os.waitpid(-1, 0x40000002)
        self.setMeta("ThreadId", pid)
        # Stop the rest of the threads... 
        # why is linux debugging so Ghetto?!?!
        if not self.stepping: # If we're stepping, only do the one
            for tid in self.pthreads:
                if tid == pid:
                    continue
                try:
                    os.kill(tid, signal.SIGTRAP)
                    os.waitpid(tid, 0x40000002)
                except Exception, e:
                    print "WARNING TID is invalid %d %s" % (tid,e)
        return status

    def platformContinue(self):
        cmd = v_posix.PT_CONTINUE
        if self.getMode("Syscall", False):
            cmd = PT_SYSCALL
        pid = self.getPid()
        sig = self.getMeta("PendingSignal", 0)
        # Only deliver signals to the main thread
        if v_posix.ptrace(cmd, pid, 0, sig) != 0:
            raise Exception("ERROR ptrace failed for tid %d" % pid)

        for tid in self.pthreads:
            if tid == pid:
                continue
            if v_posix.ptrace(cmd, tid, 0, 0) != 0:
                pass

    def platformStepi(self):
        self.stepping = True
        tid = self.getMeta("ThreadId", 0)
        if v_posix.ptrace(v_posix.PT_STEP, tid, 0, 0) != 0:
            raise Exception("ERROR ptrace failed!")

    def platformDetach(self):
        libc.close(self.memfd)
        for tid in self.pthreads:
            tid,v_posix.ptrace(PT_DETACH, tid, 0, 0)

    def doAttachThread(self, tid, attached=False):
        """
        Do the work for attaching a thread.  This must be *under*
        attachThread() so callers in notifiers may call it (because
        it's also gotta be thread wrapped).
        """
        if not attached:
            if v_posix.ptrace(PT_ATTACH, tid, 0, 0) != 0:
                raise Exception("ERROR ptrace attach failed for thread %d" % tid)
        os.waitpid(tid, 0x40000002)
        self.setupPtraceOptions(tid)
        self.pthreads.append(tid)

    def setupPtraceOptions(self, tid):
        """
        Called by doAttachThread to setup ptrace related options.
        """
        opts = PT_O_TRACESYSGOOD
        if platform.release().startswith("2.6"):
            opts |= PT_O_TRACECLONE
        x = v_posix.ptrace(PT_SETOPTIONS, tid, 0, opts)
        if x != 0:
            libc.perror('ptrace PT_SETOPTION failed for thread %d' % tid)
            #print "WARNING ptrace SETOPTIONS failed for thread %d (%d)" % (tid,x)

    def threadsForPid(self, pid):
        ret = []
        tpath = "/proc/%s/task" % pid
        if os.path.exists(tpath):
            for pidstr in os.listdir(tpath):
                ret.append(int(pidstr))
        return ret

    def platformProcessEvent(self, status):
        # Skim some linux specific events before passing to posix
        tid = self.getMeta("ThreadId", -1)
        if os.WIFSTOPPED(status):
            sig = status >> 8
            if sig == SIG_LINUX_SYSCALL:
                self.fireNotifiers(vtrace.NOTIFY_SYSCALL)

            elif sig == SIG_LINUX_CLONE:
                # Handle a new thread here!
                newtid = self.getPtraceEvent()
                self.attachThread(newtid, attached=True)

            #FIXME eventually implement child catching!
            else:
                self.handlePosixSignal(sig)

            return

        v_posix.PosixMixin.platformProcessEvent(self, status)

    def getPtraceEvent(self):
        """
        This *thread wrapped* function will get any pending GETEVENTMSG
        msgs.
        """
        p = c_ulong(0)
        tid = self.getMeta("ThreadId", -1)
        if v_posix.ptrace(PT_GETEVENTMSG, tid, 0, byref(p)) != 0:
            raise Exception("ptrace PT_GETEVENTMSG failed! %d" % x)
        return p.value

    def platformGetThreads(self):
        ret = {}
        for tid in self.pthreads:
            ret[tid] = tid #FIXME make this pthread struct or stackbase soon
        return ret

    def platformGetMaps(self):
        maps = []
        mapfile = file("/proc/%d/maps" % self.pid)
        for line in mapfile:

            perms = 0
            sline = line.split(" ")
            addrs = sline[0]
            permstr = sline[1]
            fname = sline[-1].strip()
            addrs = addrs.split("-")
            base = long(addrs[0],16)
            max = long(addrs[1],16)
            mlen = max-base

            if "r" in permstr:
                perms |= e_mem.MM_READ
            if "w" in permstr:
                perms |= e_mem.MM_WRITE
            if "x" in permstr:
                perms |= e_mem.MM_EXEC
            #if "p" in permstr:
                #pass

            maps.append((base,mlen,perms,fname))
        return maps

    def platformGetFds(self):
        fds = []
        for name in os.listdir("/proc/%d/fd/" % self.pid):
            try:
                fdnum = int(name)
                fdtype = vtrace.FD_UNKNOWN
                link = os.readlink("/proc/%d/fd/%s" % (self.pid,name))
                if "socket:" in link:
                    fdtype = vtrace.FD_SOCKET
                elif "pipe:" in link:
                    fdtype = vtrace.FD_PIPE
                elif "/" in link:
                    fdtype = vtrace.FD_FILE

                fds.append((fdnum,fdtype,link))
            except:
                traceback.print_exc()

        return fds

############################################################################
#
# NOTE: Both of these use class locals set by the i386/amd64 variants
#
    def platformGetRegCtx(self, tid):
        ctx = self.archGetRegCtx()
        u = self.user_reg_struct()
        if v_posix.ptrace(PT_GETREGS, tid, 0, addressof(u)) == -1:
            raise Exception("Error: ptrace(PT_GETREGS...) failed!")

        ctx._rctx_Import(u)

        for i in dbgregs:
            offset = self.user_dbg_offset + (self.psize * i)
            r = v_posix.ptrace(v_posix.PT_READ_U, tid, offset, 0)
            ctx.setRegister(self.dbgidx+i, r & self.reg_val_mask)

        return ctx

    def platformSetRegCtx(self, tid, ctx):
        u = self.user_reg_struct()
        # Populate the reg struct with the current values (to allow for
        # any regs in that struct that we don't track... *fs_base*ahem*
        if v_posix.ptrace(PT_GETREGS, tid, 0, addressof(u)) == -1:
            raise Exception("Error: ptrace(PT_GETREGS...) failed!")

        ctx._rctx_Export(u)
        if v_posix.ptrace(PT_SETREGS, tid, 0, addressof(u)) == -1:
            raise Exception("Error: ptrace(PT_SETREGS...) failed!")

        for i in dbgregs:
            val = ctx.getRegister(self.dbgidx + i)
            offset = self.user_dbg_offset + (self.psize * i)
            if v_posix.ptrace(v_posix.PT_WRITE_U, tid, offset, val) != 0:
                libc.perror('PT_WRITE_U failed for debug%d' % i)
                #raise Exception("PT_WRITE_U for debug%d failed!" % i)

class Linuxi386Trace(
        vtrace.Trace,
        LinuxMixin,
        v_i386.i386Mixin,
        v_posix.ElfMixin,
        v_base.TracerBase):


    user_reg_struct = user_regs_i386
    user_dbg_offset = 252
    reg_val_mask = 0xffffffff

    def __init__(self):
        vtrace.Trace.__init__(self)
        v_base.TracerBase.__init__(self)
        v_posix.ElfMixin.__init__(self)
        v_i386.i386Mixin.__init__(self)
        LinuxMixin.__init__(self)

        # Pre-calc the index of the debug regs
        self.dbgidx = self.archGetRegCtx().getRegisterIndex("debug0")

class LinuxAmd64Trace(
        vtrace.Trace,
        LinuxMixin,
        v_amd64.Amd64Mixin,
        v_posix.ElfMixin,
        v_base.TracerBase):

    user_reg_struct = user_regs_amd64
    user_dbg_offset = 848
    reg_val_mask = 0xffffffffffffffff

    def __init__(self):
        vtrace.Trace.__init__(self)
        v_base.TracerBase.__init__(self)
        v_posix.ElfMixin.__init__(self)
        v_amd64.Amd64Mixin.__init__(self)
        LinuxMixin.__init__(self)

        self.dbgidx = self.archGetRegCtx().getRegisterIndex("debug0")
