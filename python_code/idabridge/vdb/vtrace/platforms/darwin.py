"""
Darwin Platform Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import struct
import ctypes
import signal
import ctypes.util as c_util

import envi.memory as e_mem

import vtrace
import vtrace.archs.i386 as v_i386
import vtrace.platforms.base as v_base
import vtrace.platforms.posix as v_posix

addrof = ctypes.addressof

# The OSX ptrace defines...
PT_TRACE_ME     = 0    # child declares it's being traced
PT_READ_I       = 1    # read word in child's I space
PT_READ_D       = 2    # read word in child's D space
PT_READ_U       = 3    # read word in child's user structure
PT_WRITE_I      = 4    # write word in child's I space
PT_WRITE_D      = 5    # write word in child's D space
PT_WRITE_U      = 6    # write word in child's user structure
PT_CONTINUE     = 7    # continue the child
PT_KILL         = 8    # kill the child process
PT_STEP         = 9    # single step the child
PT_ATTACH       = 10   # trace some running process
PT_DETACH       = 11   # stop tracing a process
PT_SIGEXC       = 12   # signals as exceptions for current_proc
PT_THUPDATE     = 13   # signal for thread#
PT_ATTACHEXC    = 14   # attach to running process with signal exception
PT_FORCEQUOTA   = 30   # Enforce quota for root
PT_DENY_ATTACH  = 31

# Top-level identifiers
CTL_UNSPEC  = 0        # unused
CTL_KERN    = 1        # "high kernel": proc, limits
CTL_VM      = 2        # virtual memory
CTL_VFS     = 3        # file system, mount type is next
CTL_NET     = 4        # network, see socket.h
CTL_DEBUG   = 5        # debugging parameters
CTL_HW      = 6        # generic cpu/io
CTL_MACHDEP = 7        # machine dependent
CTL_USER    = 8        # user-level
CTL_MAXID   = 9        # number of valid top-level ids

KERN_OSTYPE          = 1    # string: system version
KERN_OSRELEASE       = 2    # string: system release
KERN_OSREV           = 3    # int: system revision
KERN_VERSION         = 4    # string: compile time info
KERN_MAXVNODES       = 5    # int: max vnodes
KERN_MAXPROC         = 6    # int: max processes
KERN_MAXFILES        = 7    # int: max open files
KERN_ARGMAX          = 8    # int: max arguments to exec
KERN_SECURELVL       = 9    # int: system security level
KERN_HOSTNAME        = 10    # string: hostname
KERN_HOSTID          = 11    # int: host identifier
KERN_CLOCKRATE       = 12    # struct: struct clockrate
KERN_VNODE           = 13    # struct: vnode structures
KERN_PROC            = 14    # struct: process entries
KERN_FILE            = 15    # struct: file entries
KERN_PROF            = 16    # node: kernel profiling info
KERN_POSIX1          = 17    # int: POSIX.1 version
KERN_NGROUPS         = 18    # int: # of supplemental group ids
KERN_JOB_CONTROL     = 19    # int: is job control available
KERN_SAVED_IDS       = 20    # int: saved set-user/group-ID
KERN_BOOTTIME        = 21    # struct: time kernel was booted
KERN_NISDOMAINNAME   = 22    # string: YP domain name
KERN_DOMAINNAME      = KERN_NISDOMAINNAME
KERN_MAXPARTITIONS   = 23    # int: number of partitions/disk
KERN_KDEBUG          = 24    # int: kernel trace points
KERN_UPDATEINTERVAL  = 25    # int: update process sleep time
KERN_OSRELDATE       = 26    # int: OS release date
KERN_NTP_PLL         = 27    # node: NTP PLL control
KERN_BOOTFILE        = 28    # string: name of booted kernel
KERN_MAXFILESPERPROC = 29    # int: max open files per proc
KERN_MAXPROCPERUID   = 30    # int: max processes per uid
KERN_DUMPDEV         = 31    # dev_t: device to dump on
KERN_IPC             = 32    # node: anything related to IPC
KERN_DUMMY           = 33    # unused
KERN_PS_STRINGS      = 34    # int: address of PS_STRINGS
KERN_USRSTACK32      = 35    # int: address of USRSTACK
KERN_LOGSIGEXIT      = 36    # int: do we log sigexit procs?
KERN_SYMFILE         = 37    # string: kernel symbol filename
KERN_PROCARGS        = 38
#/* 39 was KERN_PCSAMPLES... now deprecated
KERN_NETBOOT         = 40    # int: are we netbooted? 1=yes,0=no
KERN_PANICINFO       = 41    # node: panic UI information
KERN_SYSV            = 42    # node: System V IPC information
KERN_AFFINITY        = 43    # xxx
KERN_TRANSLATE       = 44    # xxx
KERN_CLASSIC         = KERN_TRANSLATE    # XXX backwards compat
KERN_EXEC            = 45    # xxx
KERN_CLASSICHANDLER  = KERN_EXEC # XXX backwards compatibility
KERN_AIOMAX          = 46    # int: max aio requests
KERN_AIOPROCMAX      = 47    # int: max aio requests per process
KERN_AIOTHREADS      = 48    # int: max aio worker threads
KERN_PROCARGS2       = 49
KERN_COREFILE        = 50    # string: corefile format string
KERN_COREDUMP        = 51    # int: whether to coredump at all
KERN_SUGID_COREDUMP  = 52    # int: whether to dump SUGID cores
KERN_PROCDELAYTERM   = 53    # int: set/reset current proc for delayed termination during shutdown
KERN_SHREG_PRIVATIZABLE = 54    # int: can shared regions be privatized ?
KERN_PROC_LOW_PRI_IO = 55    # int: set/reset current proc for low priority I/O
KERN_LOW_PRI_WINDOW  = 56    # int: set/reset throttle window - milliseconds
KERN_LOW_PRI_DELAY   = 57    # int: set/reset throttle delay - milliseconds
KERN_POSIX           = 58    # node: posix tunables
KERN_USRSTACK64      = 59    # LP64 user stack query
KERN_NX_PROTECTION   = 60    # int: whether no-execute protection is enabled
KERN_TFP             = 61    # Task for pid settings
KERN_PROCNAME        = 62    # setup process program  name(2*MAXCOMLEN)
KERN_THALTSTACK      = 63    # for compat with older x86 and does nothing
KERN_SPECULATIVE_READS  = 64    # int: whether speculative reads are disabled
KERN_OSVERSION       = 65    # for build number i.e. 9A127
KERN_SAFEBOOT        = 66    # are we booted safe?
KERN_LCTX            = 67    # node: login context
KERN_RAGEVNODE       = 68
KERN_TTY             = 69    # node: tty settings
KERN_CHECKOPENEVT    = 70      # spi: check the VOPENEVT flag on vnodes at open time
KERN_MAXID           = 71    # number of valid kern ids
# # KERN_RAGEVNODE types
KERN_RAGE_PROC       = 1
KERN_RAGE_THREAD     = 2
KERN_UNRAGE_PROC     = 3
KERN_UNRAGE_THREAD   = 4

# # KERN_OPENEVT types
KERN_OPENEVT_PROC    = 1
KERN_UNOPENEVT_PROC  = 2

# # KERN_TFP types
KERN_TFP_POLICY      = 1

# # KERN_TFP_POLICY values . All policies allow task port for self
KERN_TFP_POLICY_DENY    = 0     # Deny Mode: None allowed except privileged
KERN_TFP_POLICY_DEFAULT = 2    # Default  Mode: related ones allowed and upcall authentication

# # KERN_KDEBUG types
KERN_KDEFLAGS        = 1
KERN_KDDFLAGS        = 2
KERN_KDENABLE        = 3
KERN_KDSETBUF        = 4
KERN_KDGETBUF        = 5
KERN_KDSETUP         = 6
KERN_KDREMOVE        = 7
KERN_KDSETREG        = 8
KERN_KDGETREG        = 9
KERN_KDREADTR        = 10
KERN_KDPIDTR         = 11
KERN_KDTHRMAP        = 12
# # Don't use 13 as it is overloaded with KERN_VNODE
KERN_KDPIDEX         = 14
KERN_KDSETRTCDEC     = 15
KERN_KDGETENTROPY    = 16

# # KERN_PANICINFO types
KERN_PANICINFO_MAXSIZE  = 1    # quad: panic UI image size limit
KERN_PANICINFO_IMAGE    = 2    # panic UI in 8-bit kraw format

# * KERN_PROC subtypes
KERN_PROC_ALL        = 0    # everything
KERN_PROC_PID        = 1    # by process id
KERN_PROC_PGRP       = 2    # by process group id
KERN_PROC_SESSION    = 3    # by session of pid
KERN_PROC_TTY        = 4    # by controlling tty
KERN_PROC_UID        = 5    # by effective uid
KERN_PROC_RUID       = 6    # by real uid
KERN_PROC_LCID       = 7    # by login context id

# Stupid backwards perms defs...
VM_PROT_READ	= 1
VM_PROT_WRITE	= 2
VM_PROT_EXECUTE	= 4

# Thread status types...
x86_THREAD_STATE32    = 1
x86_FLOAT_STATE32     = 2
x86_EXCEPTION_STATE32 = 3
x86_THREAD_STATE64    = 4
x86_FLOAT_STATE64     = 5
x86_EXCEPTION_STATE64 = 6
x86_THREAD_STATE      = 7
x86_FLOAT_STATE       = 8
x86_EXCEPTION_STATE   = 9
x86_DEBUG_STATE32     = 10
x86_DEBUG_STATE64     = 11
x86_DEBUG_STATE       = 12
THREAD_STATE_NONE     = 13

class STRUCT_X86_THREAD_STATE32(ctypes.Structure):
    _fields_ = [
        ('eax', ctypes.c_uint32),
        ('ebx', ctypes.c_uint32),
        ('ecx', ctypes.c_uint32),
        ('edx', ctypes.c_uint32),
        ('edi', ctypes.c_uint32),
        ('esi', ctypes.c_uint32),
        ('ebp', ctypes.c_uint32),
        ('esp', ctypes.c_uint32),
        ('ss',  ctypes.c_uint32),
        ('eflags', ctypes.c_uint32),
        ('eip', ctypes.c_uint32),
        ('cs',  ctypes.c_uint32),
        ('ds',  ctypes.c_uint32),
        ('es',  ctypes.c_uint32),
        ('fs',  ctypes.c_uint32),
        ('gs',  ctypes.c_uint32),
    ]

class STRUCT_X86_EXCEPTION_STATE32(ctypes.Structure):
    _fields_ = [
        ('trapno',     ctypes.c_uint32),
        ('err',        ctypes.c_uint32),
        ('faultvaddr', ctypes.c_uint32),
    ]

class STRUCT_X86_DEBUG_STATE32(ctypes.Structure):
    _fields_ = [ ('debug%d', ctypes.c_uint32) for i in range(8) ]


###########################################################################
#
# mach port enumerations
#
MACH_PORT_NULL              = 0

#MACH_PORT_RIGHT_* definitions are used as arguments
MACH_PORT_RIGHT_SEND        = 0
MACH_PORT_RIGHT_RECEIVE     = 1
MACH_PORT_RIGHT_SEND_ONCE   = 2
MACH_PORT_RIGHT_PORT_SET    = 3
MACH_PORT_RIGHT_DEAD_NAME   = 4
MACH_PORT_RIGHT_LABELH      = 5
MACH_PORT_RIGHT_NUMBER      = 6

def MACH_PORT_TYPE(right):
    return 1 << (right + 16)

MACH_PORT_TYPE_SEND         = MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND)
MACH_PORT_TYPE_RECEIVE      = MACH_PORT_TYPE(MACH_PORT_RIGHT_RECEIVE)
MACH_PORT_TYPE_SEND_ONCE    = MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND_ONCE)
MACH_PORT_TYPE_PORT_SET     = MACH_PORT_TYPE(MACH_PORT_RIGHT_PORT_SET)
MACH_PORT_TYPE_DEAD_NAME    = MACH_PORT_TYPE(MACH_PORT_RIGHT_DEAD_NAME)
MACH_PORT_TYPE_LABELH       = MACH_PORT_TYPE(MACH_PORT_RIGHT_LABELH)

###########################################################################
#
# mach message types and structures
#
MACH_MSG_TIMEOUT_NONE = 0
MACH_MSG_OPTION_NONE  = 0

MACH_SEND_MSG       = 0x00000001
MACH_RCV_MSG        = 0x00000002
MACH_RCV_LARGE      = 0x00000004

MACH_SEND_TIMEOUT   = 0x00000010
MACH_SEND_INTERRUPT = 0x00000040  # libmach implements
MACH_SEND_CANCEL    = 0x00000080
MACH_SEND_ALWAYS    = 0x00010000  # internal use only
MACH_SEND_TRAILER   = 0x00020000  

MACH_RCV_TIMEOUT    = 0x00000100
MACH_RCV_NOTIFY     = 0x00000200
MACH_RCV_INTERRUPT  = 0x00000400  # libmach implements
MACH_RCV_OVERWRITE  = 0x00001000

# Return codes from mach_msg...
MACH_RCV_TIMED_OUT  = 0x10004003

MACH_MSG_TYPE_MOVE_RECEIVE   = 16    # Must hold receive rights
MACH_MSG_TYPE_MOVE_SEND      = 17    # Must hold send rights
MACH_MSG_TYPE_MOVE_SEND_ONCE = 18    # Must hold sendonce rights
MACH_MSG_TYPE_COPY_SEND      = 19    # Must hold send rights
MACH_MSG_TYPE_MAKE_SEND      = 20    # Must hold receive rights
MACH_MSG_TYPE_MAKE_SEND_ONCE = 21    # Must hold receive rights
MACH_MSG_TYPE_COPY_RECEIVE   = 22    # Must hold receive rights

mach_port_t     = ctypes.c_uint32
mach_msg_size_t = ctypes.c_uint32
mach_msg_bits_t = ctypes.c_uint32
mach_msg_id_t   = ctypes.c_uint32

class mach_msg_header_t(ctypes.Structure):
    _fields_ = [
      ('msgh_bits',        mach_msg_bits_t),
      ('msgh_size',        mach_msg_size_t),
      ('msgh_remote_port', mach_port_t),
      ('msgh_local_port',  mach_port_t),
      ('msgh_reserved',    mach_msg_size_t),
      ('msgh_id',          mach_msg_id_t),
    ]

class mach_msg_body_t(ctypes.Structure):
    _fields_ = [
        ('msgh_descriptor_count', ctypes.c_uint32),
    ]

class mach_msg_port_descriptor_t(ctypes.Structure):
    _fields_ = [
        ('name',        mach_port_t),
        ('pad1',        mach_msg_size_t),
        ('pad2',        ctypes.c_uint32),
    ]

class NDR_record_t(ctypes.Structure):
    _fields_ = [
        ('mig_vers',     ctypes.c_uint8),
        ('if_vers',      ctypes.c_uint8),
        ('reserved',     ctypes.c_uint8),
        ('mig_encoding', ctypes.c_uint8),
        ('int_rep',      ctypes.c_uint8),
        ('char_rep',     ctypes.c_uint8),
        ('float_rep',    ctypes.c_uint8),
        ('reserved2',    ctypes.c_uint8),
    ]

exception_type_t        = ctypes.c_uint32
mach_msg_type_number_t  = ctypes.c_uint32
exception_data_t        = ctypes.POINTER(ctypes.c_uint32)

# the message type we receive from the kernel for exceptions
class exc_msg(ctypes.Structure):
    _fields_ = [
        ('Head',    mach_msg_header_t),
        ('body',    mach_msg_body_t),
        ('thread',  mach_msg_port_descriptor_t),
        ('task',    mach_msg_port_descriptor_t),
        ('NDR',     NDR_record_t),
        ('exception', exception_type_t),
        ('codeCnt',   mach_msg_type_number_t),
        ('codes',     ctypes.c_uint32 * 128),
        #('codes',     exception_data_t),
        #('pad',       ctypes.c_uint8 * 512)

    ]

# The response message we send back
class exc_rep_msg(ctypes.Structure):
    _fields_ = [
        ('Head',    mach_msg_header_t),
        ('NDR',     NDR_record_t),
        ('RetCode', ctypes.c_uint32)
    ]

##########################################################################
# mach generic exception codes
#
EXC_BAD_ACCESS            = 1
EXC_BAD_INSTRUCTION       = 2
EXC_ARITHMETIC            = 3
EXC_EMULATION             = 4
EXC_SOFTWARE              = 5
EXC_BREAKPOINT            = 6
EXC_SYSCALL               = 7
EXC_MACH_SYSCALL          = 8
EXC_RPC_ALERT             = 9
EXC_CRASH                 = 10

# EXC_SOFTWARE will have code[0] == EXC_SOFT_SIGNAL for posix sigs
EXC_SOFT_SIGNAL           = 0x10003 # Unix signal exceptions

EXC_MASK_MACHINE            = 0
EXC_MASK_BAD_ACCESS         = 1 << EXC_BAD_ACCESS
EXC_MASK_BAD_INSTRUCTION    = 1 << EXC_BAD_INSTRUCTION
EXC_MASK_ARITHMETIC         = 1 << EXC_ARITHMETIC
EXC_MASK_EMULATION          = 1 << EXC_EMULATION
EXC_MASK_SOFTWARE           = 1 << EXC_SOFTWARE
EXC_MASK_BREAKPOINT         = 1 << EXC_BREAKPOINT
EXC_MASK_SYSCALL            = 1 << EXC_SYSCALL
EXC_MASK_MACH_SYSCALL       = 1 << EXC_MACH_SYSCALL
EXC_MASK_RPC_ALERT          = 1 << EXC_RPC_ALERT
EXC_MASK_CRASH              = 1 << EXC_CRASH

EXC_MASK_ALL = (EXC_MASK_BAD_ACCESS |
                EXC_MASK_BAD_INSTRUCTION |
                EXC_MASK_ARITHMETIC |
                EXC_MASK_EMULATION |
                EXC_MASK_SOFTWARE |
                EXC_MASK_BREAKPOINT |
                EXC_MASK_SYSCALL |
                EXC_MASK_MACH_SYSCALL |
                EXC_MASK_RPC_ALERT |
                EXC_MASK_CRASH |
                EXC_MASK_MACHINE)

EXCEPTION_DEFAULT        = 1 # Send a catch_exception_raise message including the identity.
EXCEPTION_STATE          = 2 # Send a catch_exception_raise_state message including the thread state.
EXCEPTION_STATE_IDENTITY = 3 # Send a catch_exception_raise_state_identity message including the thread identity and state.
MACH_EXCEPTION_CODES     = 0x80000000 # Send 64-bit code and subcode in the exception header


class SysctlType(ctypes.Structure):
    _fields_ = [
        ('one',  ctypes.c_uint32),
        ('two', ctypes.c_uint32),
        ('three', ctypes.c_uint32),
    ]

class pcred(ctypes.Structure):
    _fields_ = [
        ('pc_lock', ctypes.c_byte * 72),       # /* opaque content
        ('pc_ucred', ctypes.c_void_p),  # struct ucred *
        ('p_ruid', ctypes.c_ulong),     # /* Real user id.
        ('p_svuid', ctypes.c_ulong),    # /* Saved effective user id.
        ('p_rgid',ctypes.c_ulong),      # /* Real group id.
        ('p_svgid', ctypes.c_ulong),    # /* Saved effective group id.
        ('p_refcnt', ctypes.c_ulong),   # /* Number of references.
    ]

print 'pcred',ctypes.sizeof(pcred())

class ucred(ctypes.Structure):
    _fields_ = [
        ('cr_ref', ctypes.c_ulong),         # /* reference count
        ('cr_uid', ctypes.c_ulong),         # /* effective user id
        ('cr_ngroups', ctypes.c_ushort),    # /* number of groups
        ('cr_groups', ctypes.c_ulong * 16),  # Actually c_ulong * ngroups...
    ]

print 'ucred',ctypes.sizeof(ucred())

class vmspace(ctypes.Structure):
    _fields_ = [
        ('dummy',  ctypes.c_uint32),
        ('dummy2', ctypes.c_uint32),      # FIXME caddr_t
        ('dummy3', ctypes.c_uint32 * 5),
        ('dummy4', ctypes.c_uint32 * 3),  # FIXME caddr_t
    ]

print 'vmspace',ctypes.sizeof(vmspace())

WMESGLEN            = 7
MAXCOMLEN           = 16
COMAPT_MAXLOGNAME   = 12

class eproc(ctypes.Structure):
    _fields_ = [
        ('e_paddr',     ctypes.c_void_p), # struct proc *
        ('e_sess',      ctypes.c_void_p), # struct session
        ('e_pcred',     pcred),
        ('e_ucred',     ucred),
        ('e_vm',        vmspace),
        ('e_ppid',      ctypes.c_uint32), #/* parent process id (pid_t)
        ('e_pgid',      ctypes.c_uint32), #/* process group id (pid_t)
        ('e_jobc',      ctypes.c_short),  #/* job control counter
        ('e_tdev',      ctypes.c_uint32), #/* controlling tty dev (dev_t)
        ('e_tpgid',     ctypes.c_uint32), #/* tty process group id
        ('e_tsess',     ctypes.c_void_p), #/* tty session pointer (struct session *)
        ('e_wmesg',     ctypes.c_byte * (WMESGLEN+1)), #/* wchan message
        ('e_xsize',     ctypes.c_uint32), #/* text size (segsz_t)
        ('e_xrssize',   ctypes.c_short),  #/* text rss
        ('e_xccount',   ctypes.c_short),  #/* text references
        ('e_xswrss',    ctypes.c_short),
        ('e_flag',      ctypes.c_uint32),
        ('e_login',     ctypes.c_byte * COMAPT_MAXLOGNAME), #/* short setlogin() name
        ('e_spare',     ctypes.c_uint32 * 4),
   ]

print 'eproc',ctypes.sizeof(eproc())

class  timeval(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_uint32),
        ('tv_usec',ctypes.c_uint32),
    ]

class itimerval(ctypes.Structure):
    _fields_ = [
        ('it_interval', timeval),
        ('it_value',    timeval),
    ]

class pst1(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_void_p),
        ('tv_usec',ctypes.c_void_p),
    ]

boolean_t = ctypes.c_uint32
pid_t     = ctypes.c_uint32
u_int     = ctypes.c_uint32
pvoid     = ctypes.c_void_p
fixpt_t   = ctypes.c_uint32
u_quad_t  = ctypes.c_ulonglong
sigset_t  = ctypes.c_uint32
thread_t  = ctypes.c_uint32

class extern_proc(ctypes.Structure):
    _fields_ = [
        ('p_un', pst1),
        ('p_vmspace',   pvoid),
        ('p_sigacts',   pvoid),
        ('p_flag',      u_int),
        ('p_stat',      ctypes.c_ubyte),
        ('p_pid',       u_int),
        ('p_oppid',     u_int),
        ('p_dupfd',     u_int),
        ('user_stack',  pvoid),
        ('exit_thread', pvoid),
        ('p_debugger',  u_int),
        ('sigwait',     boolean_t),
        ('p_estcpu',    u_int),
        ('p_cpticks',   u_int),
        ('p_pctcpu',    fixpt_t),
        ('p_wchan',     pvoid),
        ('p_wmesg',     pvoid),
        ('p_swtime',    u_int),
        ('p_slptime',   u_int),
        ('p_realtimer', itimerval),
        ('p_rtime',     timeval),
        ('p_uticks',    u_quad_t),
        ('p_sticks',    u_quad_t),
        ('p_iticks',    u_quad_t),
        ('p_traceflag', u_int),
        ('p_tracep',    pvoid),
        ('p_siglist',   u_int),
        ('p_textvp',    pvoid),
        ('p_holdcnt',   u_int),
        ('p_sigmask',   sigset_t),
        ('p_sigignore', sigset_t),
        ('p_sigcatch',  sigset_t),
        ('p_priority',  ctypes.c_ubyte),
        ('p_usrpri',    ctypes.c_ubyte),
        ('p_nice',      ctypes.c_char),
        ('p_comm',      ctypes.c_char * (MAXCOMLEN+1)),
        ('p_pgrp',      pvoid),
        ('p_addr',      pvoid),
        ('p_xstat',     ctypes.c_ushort),
        ('p_acflag',    ctypes.c_ushort),
        ('p_ru',        pvoid),
    ]

print 'extern_proc',ctypes.sizeof(extern_proc())


class kinfo_proc(ctypes.Structure):
    _fields_ = [
        ('kp_proc', extern_proc),
        ('kp_eproc', eproc),
    ]

print 'kinfo_proc',ctypes.sizeof(kinfo_proc)

####################################################################
#
# mach VM related stuff....
#
vm_prot_t    = ctypes.c_uint32
vm_inherit_t = ctypes.c_uint32
vm_behavior_t = ctypes.c_uint32
memory_object_offset_t = ctypes.c_ulonglong

VM_REGION_BASIC_INFO_64    = 9

class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [
        ('protection',      vm_prot_t),
        ('max_protection',  vm_prot_t),
        ('inheritance',     vm_inherit_t),
        ('shared',          boolean_t),
        ('reserved',        boolean_t),
        ('offset',          memory_object_offset_t),
        ('behavior',        vm_behavior_t),
        ('user_wired_count',ctypes.c_ushort),
    ]

print 'vm_region_basic_info_64',ctypes.sizeof(vm_region_basic_info_64)
VM_REGION_BASIC_INFO_COUNT_64 = ctypes.sizeof(vm_region_basic_info_64) / 4

####################################################################
    
class DarwinMixin(v_posix.PosixMixin, v_posix.PtraceMixin):

    def __init__(self):
        v_posix.PosixMixin.__init__(self)
        v_posix.PtraceMixin.__init__(self)
        self.libc = ctypes.CDLL(c_util.find_library('c'))
        self.myport = self.libc.mach_task_self()
        self.portset = self.newMachPort(MACH_PORT_RIGHT_PORT_SET)
        self.excport = self.newMachRWPort()
        self.addPortToSet(self.excport)
        # We get most of the threadWrap we need from posix... but...
        #self.threadWrap("platformGetMaps", self.platformGetMaps)

    def platformPs(self):
        ctl = SysctlType()
        ctl.one = CTL_KERN
        ctl.two = KERN_PROC
        ctl.three = KERN_PROC_ALL

        size = ctypes.c_uint32()
        self.libc.sysctl(addrof(ctl), 3, None, addrof(size), None, 0)
        count = size.value / ctypes.sizeof(kinfo_proc)
        buf = (kinfo_proc * count)()
        self.libc.sysctl(addrof(ctl), 3, buf,  addrof(size), None, 0)
        ret = []
        for i in range(count):
            pid = buf[i].kp_proc.p_pid
            if pid == 0: # Skip the crazy kernel things...
                continue
            name = buf[i].kp_proc.p_comm
            ret.append((pid,name))
        ret.reverse()
        return ret

    def platformParseBinary(self, filename, baseaddr, normname):
        pass

    def platformGetFds(self):
        print "FIXME platformGetFds() no workie on darwin yet..."
        return []

    def platformExec(self, cmdline):
        pid = v_posix.PtraceMixin.platformExec(self, cmdline)
        self.task = self.taskForPid(pid)
        self.setExceptionPort()
        return pid

    def _getThreadPorts(self):
        count = ctypes.c_uint32()
        tlist = ctypes.POINTER(thread_t)()
        r = self.libc.task_threads(self.task, addrof(tlist), addrof(count))
        if r != 0:
            raise Exception('task_threads Failed: 0x%.8x' % r)

        ret = [ tlist[i] for i in range(count.value)]
        self.libc.vm_deallocate(self.task, tlist)
        return ret

    def platformSuspendThread(self, tid):
        self.libc.thread_suspend(tid)

    def platformResumeThread(self, tid):
        self.libc.thread_resume(tid)

    def platformGetThreads(self):
        ret = {}
        for tid in self._getThreadPorts():
            ret[tid] = tid
        return ret

    def platformGetMaps(self):
        maps = []
        address = ctypes.c_uint32(0) # FIXME 64bit
        mapsize = ctypes.c_uint32(0) # FIXME 64bit
        name    = ctypes.c_uint32(0) # FIXME 64bit
        count   = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
        info    = vm_region_basic_info_64()

        while True:
            r = self.libc.vm_region(self.task, addrof(address),
                                   addrof(mapsize), VM_REGION_BASIC_INFO_64,
                                   addrof(info), addrof(count),
                                   addrof(name))

            if r != 0:
                raise Exception('vm_region Failed for 0x%.8x: 0x%.8x' % (address.value,r))

            perms = 0
            p = info.protection
            if p & VM_PROT_READ:
                perms |= e_mem.MM_READ
            if p & VM_PROT_WRITE:
                perms |= e_mem.MM_WRITE
            if p & VM_PROT_EXECUTE:
                perms |= e_mem.MM_EXEC
            if info.shared:
                perms |= e_mem.MM_SHARED
            # If we got any perms, report the map
            if perms:
                maps.append((address.value, mapsize.value, perms, ''))

            address.value += mapsize.value
            # FIXME 64bit... only got to 0xc0000000 for now...
            if address.value >= 0xc0000000:
                break

        return maps
                                   
    def platformProcessEvent(self, exc):
        """
        Handle a mach exception message
        """
        # Set the thread that signaled.
        self.setMeta('ThreadId', exc.thread.name)
        self.setMeta('MachException', exc)

        excode = exc.exception
        if excode == EXC_SOFTWARE:
            if exc.codeCnt != 2:
                raise Exception('EXC_SOFTWARE with codeCnt != 2: %d' % exc.codeCnt)
            if exc.codes[0] != EXC_SOFT_SIGNAL:
                raise Exception('codes[0] != EXC_SOFT_SIGNAL: %.8x' % exc.codes[0])

            sig = exc.codes[1]
            if sig == signal.SIGTRAP:
                # FIXME I think we can catch these!
                # Traps on posix systems are a little complicated
                if self.stepping:
                    self.stepping = False
                    self.fireNotifiers(vtrace.NOTIFY_STEP)

                # FIXME and these too...
                elif self.checkBreakpoints():
                    # It was either a known BP or a sendBreak()
                    return

                elif self.execing:
                    self.execing = False
                    self.handleAttach()

                else:
                    self.setMeta("PendingSignal", sig)
                    self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

            elif sig == signal.SIGSTOP:
                self.handleAttach()

            else:
                self.setMeta("PendingSignal", sig)
                self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

        elif excode == EXC_BAD_ACCESS:
            print 'Bad Access:',repr([hex(x) for x in [exc.codes[i] for i in range(exc.codeCnt)]])
            self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

        elif excode == EXC_CRASH:
            print 'Crash:',repr([hex(x) for x in [exc.codes[i] for i in range(exc.codeCnt)]])
            self.setMeta('ExitCode', -1)
            self.fireNotifiers(vtrace.NOTIFY_EXIT)

        else:
            print 'Unprocessed Exception Type: %d' % excode
            self.fireNotifiers(vrtrace.NOTIFY_SIGNAL)

        return

    def platformAttach(self, pid):
        self.task = self.taskForPid(pid)
        self.setExceptionPort()
        if v_posix.ptrace(PT_ATTACHEXC, pid, 0, 0) != 0:
            #self.libc.perror('ptrace( PT_ATTACHEXC, %d, 0, 0) Failed' % (pid))
            raise Exception("PT_ATTACH failed!")
        #FIXME setMeta("ExeName", stuff)
        #self.setMeta("ExeName", self._findExe(pid))

    def taskForPid(self, pid):
        task = ctypes.c_uint32()
        ret = self.libc.task_for_pid(self.myport, pid, addrof(task))
        if ret != 0:
            raise Exception('task_for_pid failed: 0x%.8x\n' % ret)
        return task.value

    def newMachPort(self, right):
        port = ctypes.c_uint32()
        ret = self.libc.mach_port_allocate(self.myport, right, addrof(port))
        if ret != 0:
            raise Exception('mach_port_allocate (right: %d) failed: 0x%.8x' % (right, ret))
        return port.value

    def newMachRWPort(self):
        port = self.newMachPort(MACH_PORT_RIGHT_RECEIVE)
        r = self.libc.mach_port_insert_right(self.myport, port, port, MACH_MSG_TYPE_MAKE_SEND)
        if r != 0:
            raise Exception('mach_port_insert_right (MACH_PORT_RIGHT_RECEIVE) Failed: 0x%.8x' % r)
        return port

    def addPortToSet(self, port):
        r = self.libc.mach_port_move_member(self.myport, port, self.portset)
        if r != 0:
            raise Exception('mach_port_move_member for portset failed: 0x%.8x' % r)

    def setExceptionPort(self):
        # Set the target task's exception port to our excport
        r = self.libc.task_set_exception_ports(self.task, EXC_MASK_ALL, self.excport,
                                               EXCEPTION_DEFAULT, THREAD_STATE_NONE)
        if r != 0:
            raise Exception('task_set_exception_ports failed: 0x%.8x' % r)

    def _getNextExc(self, timeout=MACH_MSG_TIMEOUT_NONE):
        exc = exc_msg()
        r = self.libc.mach_msg(addrof(exc),
                           MACH_RCV_MSG|MACH_RCV_LARGE|MACH_RCV_TIMEOUT,
                           0,                   # Send size...
                           ctypes.sizeof(exc),  # Recv msg size
                           self.excport,
                           timeout,
                           MACH_PORT_NULL)
        if r == MACH_RCV_TIMED_OUT:
            return None
        if r != 0:
            raise Exception('mach_msg (RECV) failed: 0x%.8x' % r)

        #print 'BITS',hex(exc.Head.msgh_bits)
        #print 'ID',exc.Head.msgh_id
        #print 'EXCEPTION',exc.exception
        #print 'codeCnt',  exc.codeCnt
        #for i in range(exc.codeCnt):
            #print 'code: 0x%.16x' % exc.codes[i]

        return exc

    def platformWait(self):
        # Wait for a mach message on the exception port
        exc = self._getNextExc()
        #e2 = self._getNextExc(timeout=0)
        #if e2 != None:
        #print "ALSO GOT",e2

        # Suspend the task so reading etc is safe...
        self.libc.task_suspend(self.task)

        # Sometimes there are still posix signals anyway...
        while os.waitpid(-1, os.WNOHANG) != (0,0):
            pass

        res = self.buildExcResp(exc)

        x = self.libc.mach_msg(addrof(res), MACH_SEND_MSG, ctypes.sizeof(res),0,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)
        if x != 0:
            raise Exception('mach_msg MACH_SEND_MSG failed: 0x%.8x' % (x,))

        return exc

    def buildExcResp(self, exc):
        # This is from straight reversing exc_server from libc...
        res = exc_rep_msg()
        res.Head.msgh_bits = exc.Head.msgh_bits & 0xff
        res.Head.msgh_size = 0x24
        res.Head.msgh_remote_port = exc.Head.msgh_remote_port
        res.Head.msgh_local_port = 0
        res.Head.msgh_id = exc.Head.msgh_id + 0x64
        res.RetCode = 0
        return res


    def platformContinue(self):
        sig = self.getMeta("PendingSignal", 0)
        self.libc.task_resume(self.task)

    def platformDetach(self):
        #for tid in self.getThreads().keys():
            #self.libc.thread_resume(tid)
        self.libc.task_resume(self.task)
        v_posix.ptrace(PT_DETACH, self.pid, 0, 0)

    def platformReadMemory(self, address, size):
        pval = ctypes.c_void_p(0)
        sval = ctypes.c_uint32(0)
        r = self.libc.vm_read(self.task, address, size, addrof(pval), addrof(sval));
        if r != 0:
            raise Exception('vm_read failed at 0x%.8x: 0x%.8x' % (address,r))
        buf = ctypes.string_at(pval.value, sval.value)
        self.libc.vm_deallocate(self.task, pval, sval)
        return buf

    def platformWriteMemory(self, address, data):
        r = self.libc.vm_write(self.task, address, data, len(data))
        if r != 0:
            raise Exception('vm_write failed: 0x%.8x' % r)

    # FIXME use vm_allocate for allocate memory
    # FIXME use vm_protect

class Darwini386Trace(
            vtrace.Trace,
            DarwinMixin,
            v_i386.i386Mixin,
            v_base.TracerBase):

    def __init__(self):
        vtrace.Trace.__init__(self)
        v_base.TracerBase.__init__(self)
        v_i386.i386Mixin.__init__(self)
        DarwinMixin.__init__(self)

    def getThreadException(self, tid):
        # Each arch trace must implement this...
        state = STRUCT_X86_EXCEPTION_STATE32()
        scount = ctypes.c_uint32(ctypes.sizeof(state) / 4)
        ret = self.libc.thread_get_state(tid, x86_EXCEPTION_STATE32, addrof(state), addrof(scount));
        if ret != 0:
            raise Exception('thread_get_state failed: 0x%.8x' % ret)
        return state.trapno, state.err, state.faultvaddr

    def platformGetRegCtx(self, tid):
        ctx = self.archGetRegCtx()
        # NOTE: the tid *is* the port...

        state = STRUCT_X86_THREAD_STATE32()
        scount = ctypes.c_uint32(ctypes.sizeof(state) / 4)
        ret = self.libc.thread_get_state(tid, x86_THREAD_STATE32, addrof(state), addrof(scount));
        if ret != 0:
            raise Exception('thread_get_state (THREAD_STATE32) failed: 0x%.8x' % ret)
        ctx._rctx_Import(state)

        state = STRUCT_X86_DEBUG_STATE32()
        scount = ctypes.c_uint32(ctypes.sizeof(state) / 4)
        ret = self.libc.thread_get_state(tid, x86_DEBUG_STATE32, addrof(state), addrof(scount));
        if ret != 0:
            raise Exception('thread_get_state (DEBUG_STATE32) failed: 0x%.8x' % ret)
        ctx._rctx_Import(state)

        return ctx

    def platformSetRegCtx(self, tid, ctx):

        state = STRUCT_X86_THREAD_STATE32()

        # Sync up a struct first...
        scount = ctypes.c_uint32(ctypes.sizeof(state) / 4)
        ret = self.libc.thread_get_state(tid, x86_THREAD_STATE32, addrof(state), addrof(scount));
        if ret != 0:
            raise Exception('thread_get_state (THREAD_STATE32) failed: 0x%.8x' % ret)

        # Export our shit into it...
        ctx._rctx_Export(state)

        scount = ctypes.sizeof(state) / 4
        r = self.libc.thread_set_state(tid, x86_THREAD_STATE32, addrof(state), scount)
        if r != 0:
            raise Exception('thread_set_state (THREAD_STATE32) failed: 0x%.8x' % r)

        state = STRUCT_X86_DEBUG_STATE32()
        ctx._rctx_Export(state)
        scount = ctypes.sizeof(state) / 4
        r = self.libc.thread_set_state(tid, x86_DEBUG_STATE32, addrof(state), scount)
        if r != 0:
            raise Exception('thread_set_state (DEBUG_STATE32) failed: 0x%.8x' % r)

class DarwinMixinOLD:

    def initMixin(self):
        self.tdict = {}

    def platformGetMaps(self):
        return self.task.get_mmaps()

    def platformReadMemory(self, address, length):
        return self.task.vm_read(address, length)

    def platformWriteMemory(self, address, buffer):
        return self.task.vm_write(address, buffer)

    def currentMachThread(self):
        self.getThreads()
        return self.tdict[self.getMeta("ThreadId")]

    def platformGetRegs(self):
        """
        """
        thr = self.currentMachThread()
        regs = thr.get_state(self.thread_state)
        return regs + thr.get_state(self.debug_state)

    def platformSetRegs(self, regbuf):
        thr = self.currentMachThread()
        # XXX these 32 boundaries are wrong
        thr.set_state(self.thread_state, regbuf[:-32])
        thr.set_state(self.debug_state,  regbuf[-32:])

    def platformGetThreads(self):
        ret = {}
        self.tdict = {}
        spname = self.archGetSpName()
        for thread in self.task.threads():
            # We can't call platformGetRegs here... (loop, loop...)
            regbuf = thread.get_state(self.thread_state) + thread.get_state(self.debug_state)
            regdict = self.unpackRegisters(regbuf)
            sp = regdict.get(spname, 0)
            mapbase,maplen,mperm,mfile = self.getMemoryMap(sp)
            tid = mapbase + maplen # The TOP of the stack, so it doesn't grow down and change
            ret[tid] = tid
            self.tdict[tid] = thread
        self.setMeta("ThreadId", tid) #FIXME how can we know what thread caused an event?
        return ret

class DarwinIntel32Registers:
    """
    Mixin for the register format of Darwin on Intel 32
    """
    thread_state = 1
    debug_state = 10

    def getRegisterFormat(self):
        return "24L"

    def getRegisterNames(self):
        return ("eax","ebx","ecx","edx","edi",
                "esi","ebp","esp","ss","eflags",
                "eip","cs","ds","es","fs","gs",
                "debug0","debug1","debug2","debug3",
                "debug4","debug5","debug6","debug7")

class DarwinPpc32Registers:
    """
    Mixin for the register format of Darwin on PPC 32
    """
    thread_state = 4
    debug_state = 11

    def getRegisterFormat(self):
        return "40L"

    def getRegisterNames(self):
        mylist = []
        for i in range(40):
            mylist.append("r%d" % i)
        return mylist

