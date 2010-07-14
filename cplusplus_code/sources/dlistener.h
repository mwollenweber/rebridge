/*++

    Copyright (c) 2000  Microsoft Corporation

Module Name:

    dbgexts.h

--*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DllExport   __declspec( dllexport ) 

//
// Define KDEXT_64BIT to make all wdbgexts APIs recognize 64 bit addresses
// It is recommended for extensions to use 64 bit headers from wdbgexts so
// the extensions could support 64 bit targets.
//
#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>
#include <Dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct
#include <extsfns.h>

#ifdef __cplusplus
extern "C" {
#endif



#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)




// Global variables initialized by query.
extern PDEBUG_CLIENT4        g_ExtClient, g_cbClient;
extern PDEBUG_CONTROL        g_ExtControl;
extern PDEBUG_SYMBOLS2       g_ExtSymbols;
extern PDEBUG_REGISTERS		 g_ExtRegisters;
extern PDEBUG_SYSTEM_OBJECTS	g_ExtSystemObjects;


extern BOOL  Connected;
extern ULONG TargetMachine;

DllExport HRESULT
ExtQuery(PDEBUG_CLIENT4 Client);

void
ExtRelease(void);

void Release_Interfaces();
bool set_eventcb();
void Initialize_Server_Interfaces();
void Release_Server_Interfaces();

HRESULT
NotifyOnTargetAccessible(PDEBUG_CONTROL Control);

#ifdef __cplusplus
}
#endif
