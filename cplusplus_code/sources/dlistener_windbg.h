#ifndef __DLISTENER__WINDBG_H__
#define __DLISTENER__WINDBG_H__
#include <vector>
#include <iostream>
#include <iomanip>
#include <string>
#include <windows.h>
#include <Dbgeng.h>
#include <map>


#include "cmd_translation.h"
#include "dlistener.h"
#include "dlistener_eventcb.h"
#include "dlistener_net.h"
#include "dlistener_windbg.h"


struct reg_info{
	char name[2048];
	DEBUG_VALUE value;
};
typedef reg_info rinfo_t;


void update_registers();
void get_registers(std::string &regs);
void get_breakpoints(std::string &bp_str);
void set_registers(std::map<std::string, std::string> &regs);




ULONG64 get_current_pc();
HRESULT test_handler(PDEBUG_CLIENT4 Client, PCSTR args);
HRESULT dlistener_handler(PDEBUG_CLIENT4 Client, PCSTR args);
HRESULT ida_handler(PDEBUG_CLIENT4 Client, PCSTR args);
//HRESULT collabreate_handler(PDEBUG_CLIENT4 Client, PCSTR args);
HRESULT dl_cmd_handler(PDEBUG_CLIENT4 Client, PCSTR args);
PDEBUG_REGISTERS get_register_interface();
PDEBUG_SYSTEM_OBJECTS get_sysobj_interface();
PDEBUG_CONTROL get_control_interface();
PDEBUG_DATA_SPACES4 get_dataspace_interface();
PDEBUG_CLIENT4 get_client_interface();
ULONG64 get_debuggee_baseoffset();
ULONG64 getBaseOfCode(ULONG64 addr);

bool check_convert_addr_val(std::string uinput, ULONG64 *addr);
bool get_register_value(char *reg, ULONG64 *value);

bool get_pvmemory_off_value(ULONG64 offset, ULONG64 *value);
bool get_pvmemory_off_values(ULONG cnt, ULONG64 offset, ULONG64 *value);

bool get_vmemory_off_value(ULONG64 offset, ULONG64 *value);
bool get_vmemory_off_values(ULONG64 offset, PVOID value, ULONG bufSize, ULONG *bytesRead);


bool set_vmemory_off_values(ULONG64 offset, PVOID value, ULONG bufSize, ULONG *bytesWrote=NULL);

bool get_images_by_names(std::vector<std::string> &image_names);



// Windows Structures Needed for Miscelaneous stuff
typedef CONST char *PCSZ;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;



typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID MemoryLocation;
	PVOID Reserved2;
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef
VOID
(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );



typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3;
	PVOID  ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;


#define DLISTENER_HELP_STRING "dlistener IDA Pro Bridge (!dlistener)\n" \
"!dlistener start [[ip] [port]] - starts the dlistener server defaults: Host: 127.0.0.1 Port: 8088\n" \
"!dlistener stop - stops the listener and terminates all client connections\n\n" \
"!ida help\n"

#define IDA_HELP_STRING  "IDA Interface (!ida)\n\n" \
"IDA Names and Comments:\n" \
"       Available commands:\n" \
"               ida (mn | makename) [addr] name -> Name the specified address or PC address\n" \
"               ida (mt | makecomment) [addr] comment -> Comment the specified address or PC address\n\n" \
"IDA Make Type Command Set\n" \
"       Available make type commands:\n" \
"               ida (make_string | ms) [0xaddr | reg] [0xaddr | reg] Note: first addr: start address Second Addr: end addr\n" \
"               ida (make_byte | mb) [0xaddr | reg] [length]\n" \
"               ida (make_word | mw) [0xaddr | reg] [length]\n" \
"               ida (make_dword | md) [0xaddr | reg] [length]\n" \
"               ida (make_qword | mq) [0xaddr | reg] [length]\n" \
"               ida (make_oword | mo) [0xaddr | reg] [length]\n" \
"               ida (make_double | mdbl) [0xaddr | reg] [length]\n" \
"               ida (make_float | mf) [0xaddr | reg] [length]\n" \
"               ida (make_string | ms) [0xaddr | reg] [length]\n" \
"               ida (make_code | mc) [0xaddr | reg] [length]\n" \
"               ida (make_name | mn) [0xaddr | reg] [length]\n" \
"               ida (make_align | ma) [0xaddr | reg] [alignment] Note: 0 to 32 are valid values, default: 0\n\n" \
"               ida (make_unknown | mu) [0xaddr | reg] [flags] Note: 0:simple, 1:expand (default), 2:names\n\n" \
"       [length] -> number of elements to create, default: 1\n" \
"       [0xaddr | reg] -> address in hex/decimal format or the register to make the type, default: Value of the PC\n" \
"                                         Adding a * will derereference the register, hopefully\n" \
"       ex:\n" \
"               ida mb -> makes 1 byte at the value of PC\n" \
"               ida mw 3 -> makes 3 words at the value of the PC\n" \
"               ida mw 0x401000 4 -> makes 4 words at 0x401000\n" \
"               ida mq rax 3 -> makes 3 qwords at rax\n" \
"               ida mq *rax 3 -> makes 3 qwords at *rax\n\n" \
"Other IDA Commands\n" \
"       Available make type commands:\n" \
"               ida (getname | getname) [0xaddr | reg] \n" \
"               ida (aarea | aa) (0xaddr | reg) (0xaddr | reg) Note: start and end addrs\n" \
"               ida (screenea | sa)\n" \
"               ida (jumpto | jt) [0xaddr | reg] \n\n\n" \
"Examples:\n" \
"       [length] -> number of elements to create, default: 1\n" \
"       [0xaddr | reg] -> address in hex/decimal format or the register to make the type, default: Value of the PC\n" \
"                                         Adding a * will derereference the register, hopefully\n" \
"       ex:\n" \
"               ida mb -> makes 1 byte at the value of PC\n" \
"               ida mw 3 -> makes 3 words at the value of the PC\n" \
"               ida mw 0x401000 4 -> makes 4 words at 0x401000\n" \
"               ida mq rax 3 -> makes 3 qwords at rax\n" \
"               ida mq *rax 3 -> makes 3 qwords at *rax\n"

/*

dlistener IDA Pro Bridge (!dlistener)

!dlistener start [[ip] [port]] - starts the dlistener server defaults: Host: 127.0.0.1 Port: 8088
!dlistener stop - stops the listener and terminates all client connections


IDA Interface (!ida)

IDA Names and Comments:
	Available commands:
		!ida (mn | makename) [addr] name -> Name the specified address or PC address
		!ida (mt | makecomment) [addr] comment -> Comment the specified address or PC address
		
IDA Make Type Command Set
	Available make type commands:
		!ida (make_string | ms) [0xaddr | reg] [0xaddr | reg] Note: first addr: start address Second Addr: end addr
		!ida (make_byte | mb) [0xaddr | reg] [length]
		!ida (make_word | mw) [0xaddr | reg] [length]
		!ida (make_dword | md) [0xaddr | reg] [length]
		!ida (make_qword | mq) [0xaddr | reg] [length]
		!ida (make_oword | mo) [0xaddr | reg] [length]
		!ida (make_double | mdbl) [0xaddr | reg] [length]
		!ida (make_float | mf) [0xaddr | reg] [length]
		!ida (make_string | ms) [0xaddr | reg] [length]
		!ida (make_code | mc) [0xaddr | reg] [length]
		!ida (make_name | mn) [0xaddr | reg] [length]
		!ida (make_align | ma) [0xaddr | reg] [alignment] Note: 0 to 32 are valid values, default: 0
		
	[length] -> number of elements to create, default: 1
	[0xaddr | reg] -> address in hex/decimal format or the register to make the type, default: Value of the PC
					  Adding a * will derereference the register, hopefully
	ex:
		!ida mb -> makes 1 byte at the value of PC
		!ida mw 3 -> makes 3 words at the value of the PC
		!ida mw 0x401000 4 -> makes 4 words at 0x401000
		!ida mq rax 3 -> makes 3 qwords at rax
		!ida mq *rax 3 -> makes 3 qwords at *rax

Other IDA Commands
	Available make type commands:
		!ida (getname | getname) [0xaddr | reg] 
		!ida (aarea | aa) (0xaddr | reg) (0xaddr | reg) Note: start and end addrs
		!ida (screenea | sa)
		!ida (jumpto | jt) [0xaddr | reg] 


Examples:
	[length] -> number of elements to create, default: 1
	[0xaddr | reg] -> address in hex/decimal format or the register to make the type, default: Value of the PC
					  Adding a * will derereference the register, hopefully
	ex:
		!ida mb -> makes 1 byte at the value of PC
		!ida mw 3 -> makes 3 words at the value of the PC
		!ida mw 0x401000 4 -> makes 4 words at 0x401000
		!ida mq rax 3 -> makes 3 qwords at rax
		!ida mq *rax 3 -> makes 3 qwords at *rax
*/
#endif