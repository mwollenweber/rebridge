/*
dlistener.cpp
Author:	Adam Pridgen

Summary:

    This file contains the generic routines and initialization code
    for the debugger extensions dll. Mainly ripped from dbgexts.cpp (Copyright Microsoft).

*/

#include "dlistener.h"
#include "dlistener_windbg.h"
#include "dlistener_eventcb.h"
#include <strsafe.h>
#include <vector>
#include <string>



PDEBUG_CLIENT4        g_ExtClient=NULL, g_cbClient=NULL;
PDEBUG_CONTROL        g_ExtControl=NULL;
PDEBUG_SYMBOLS2       g_ExtSymbols=NULL;
PDEBUG_REGISTERS		 g_ExtRegisters=NULL;
PDEBUG_SYSTEM_OBJECTS	g_ExtSystemObjects=NULL;

WINDBG_EXTENSION_APIS   ExtensionApis;

ULONG   TargetMachine;
BOOL    Connected;

// Queries for all debugger interfaces.
extern "C" DllExport HRESULT
ExtQuery(PDEBUG_CLIENT4 Client)
{

    //Release_Interfaces();
	HRESULT Status;
	if((Status = DebugCreate( __uuidof(IDebugClient), (void **)&g_cbClient)) != S_OK){
		goto Fail;
	
	
	}
    if ((Status = Client->QueryInterface(__uuidof(IDebugControl),
                                 (void **)&g_ExtControl)) != S_OK)
    {
        goto Fail;
    }
    if ((Status = Client->QueryInterface(__uuidof(IDebugSymbols2),
                                (void **)&g_ExtSymbols)) != S_OK)
    {
    
	goto Fail;
    }
	if ((Status = Client->QueryInterface(__uuidof(IDebugRegisters),
                                (void **)&g_ExtRegisters)) != S_OK)
    {
    
	goto Fail;
    }
	if ((Status = Client->QueryInterface(__uuidof(IDebugSystemObjects),
                                (void **)&g_ExtSystemObjects)) != S_OK)
    {
    
	goto Fail;
    }
	
    g_ExtClient = Client;
    if ((Status = Client->QueryInterface(__uuidof(IDebugControl),
                                 (void **)&g_ExtControl)) != S_OK)
    {
        goto Fail;
    }
    if ((Status = Client->QueryInterface(__uuidof(IDebugSymbols2),
                                (void **)&g_ExtSymbols)) != S_OK)
    {
    
	goto Fail;
    }
	if ((Status = Client->QueryInterface(__uuidof(IDebugRegisters),
                                (void **)&g_ExtRegisters)) != S_OK)
    {
    
	goto Fail;
    }
    return S_OK;

 Fail:
    ExtRelease();
    return Status;
}
void Release_Interfaces()
{
    HRESULT Status;

    if (g_ExtControl != NULL)
    	EXT_RELEASE(g_ExtControl);
	if (g_ExtSymbols != NULL)
    	EXT_RELEASE(g_ExtSymbols);
	if (g_ExtRegisters != NULL)
    	EXT_RELEASE(g_ExtRegisters);
	if (g_ExtSystemObjects != NULL)
    	EXT_RELEASE(g_ExtSystemObjects);

}

// Cleans up all debugger interfaces.
void
ExtRelease(void)
{
    g_ExtClient = NULL;
	Release_Interfaces();
}


// Normal output.
void __cdecl
ExtOut(PCSTR Format, ...)
{
    va_list Args;

    va_start(Args, Format);
    g_ExtControl->OutputVaList(DEBUG_OUTPUT_NORMAL, Format, Args);
    va_end(Args);
}

// Error output.
void __cdecl
ExtErr(PCSTR Format, ...)
{
    va_list Args;

    va_start(Args, Format);
    g_ExtControl->OutputVaList(DEBUG_OUTPUT_ERROR, Format, Args);
    va_end(Args);
}

// Warning output.
void __cdecl
ExtWarn(PCSTR Format, ...)
{
    va_list Args;

    va_start(Args, Format);
    g_ExtControl->OutputVaList(DEBUG_OUTPUT_WARNING, Format, Args);
    va_end(Args);
}

extern "C" DllExport HRESULT
 DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    IDebugClient *DebugClient;
    PDEBUG_CONTROL DebugControl;
    HRESULT Hr;

    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;
    Hr = S_OK;

    if ((Hr = DebugCreate(__uuidof(IDebugClient),
                          (void **)&DebugClient)) != S_OK)
    {
        return Hr;
    }

    if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),
                                  (void **)&DebugControl)) == S_OK)
    {

        //
        // Get the windbg-style extension APIS
        //
        ExtensionApis.nSize = sizeof (ExtensionApis);
        Hr = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);

        DebugControl->Release();

    }
    DebugClient->Release();
    return Hr;
}


extern "C" DllExport void
 DebugExtensionNotify(ULONG Notify, ULONG64 Argument)
{
    UNREFERENCED_PARAMETER(Argument);

    //
    // The first time we actually connect to a target
    //

    if ((Notify == DEBUG_NOTIFY_SESSION_ACCESSIBLE) && (!Connected))
    {
        IDebugClient *DebugClient;
        HRESULT Hr;
        PDEBUG_CONTROL DebugControl;

        if ((Hr = DebugCreate(__uuidof(IDebugClient),
                              (void **)&DebugClient)) == S_OK)
        {
            //
            // Get the architecture type.
            //

            if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),
                                       (void **)&DebugControl)) == S_OK)
            {
                if ((Hr = DebugControl->GetActualProcessorType(
                                             &TargetMachine)) == S_OK)
                {
                    Connected = TRUE;
                }

                //NotifyOnTargetAccessible(DebugControl);

                DebugControl->Release();
            }

            DebugClient->Release();
        }
    }


    if (Notify == DEBUG_NOTIFY_SESSION_INACTIVE)
    {
        Connected = FALSE;
        TargetMachine = 0;
    }

    return;
}

extern "C" DllExport void
 DebugExtensionUninitialize(void)
{
    return;
}



extern "C" DllExport HRESULT 
 dlistener(PDEBUG_CLIENT4 Client, PCSTR args) {

    HRESULT result = dlistener_handler(Client, args);
	ExtRelease();

	return result;	
}

extern "C" DllExport HRESULT 
 ida(PDEBUG_CLIENT4 Client, PCSTR args) {

    
	HRESULT result = ida_handler(Client, args);
	ExtRelease();

	return result;	
}

extern "C" DllExport HRESULT 
 test(PDEBUG_CLIENT4 Client, PCSTR args) {

    
	HRESULT result = test_handler(Client, args);
	ExtRelease();

	return result;	
}
