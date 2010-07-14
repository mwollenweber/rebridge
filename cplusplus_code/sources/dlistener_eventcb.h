#ifndef __DLISTENER__EVENTCB_H__
#define __DLISTENER__EVENTCB_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <dbgeng.h>
#include <map>
#include "dlistener.h"



class EventCallbacks : public DebugBaseEventCallbacks
{
public:
    // IUnknown.
    STDMETHOD_(ULONG, AddRef)(
        THIS
        );
    STDMETHOD_(ULONG, Release)(
        THIS
        );

    // IDebugEventCallbacks.
    STDMETHOD(GetInterestMask)(
        THIS_
        OUT PULONG Mask
        );
    
    STDMETHOD(Breakpoint)(
        THIS_
        IN PDEBUG_BREAKPOINT Bp
        );
    STDMETHOD(Exception)(
        THIS_
        IN PEXCEPTION_RECORD64 Exception,
        IN ULONG FirstChance
        );
    STDMETHOD(CreateProcess)(
        THIS_
        IN ULONG64 ImageFileHandle,
        IN ULONG64 Handle,
        IN ULONG64 BaseOffset,
        IN ULONG ModuleSize,
        IN PCSTR ModuleName,
        IN PCSTR ImageName,
        IN ULONG CheckSum,
        IN ULONG TimeDateStamp,
        IN ULONG64 InitialThreadHandle,
        IN ULONG64 ThreadDataOffset,
        IN ULONG64 StartOffset
        );
    STDMETHOD(LoadModule)(
        THIS_
        IN ULONG64 ImageFileHandle,
        IN ULONG64 BaseOffset,
        IN ULONG ModuleSize,
        IN PCSTR ModuleName,
        IN PCSTR ImageName,
        IN ULONG CheckSum,
        IN ULONG TimeDateStamp
        );
    STDMETHOD(SessionStatus)(
        THIS_
        IN ULONG Status
        );

	STDMETHOD(ExitThread)(
		THIS_
    	IN ULONG  ExitCode
    );
	STDMETHOD(ExitProcess)(
		THIS_
    	IN ULONG  ExitCode
    );

	STDMETHOD(CreateThread)(
		THIS_
    	IN ULONG64  Handle,
    	IN ULONG64  DataOffset,
    	IN ULONG64  StartOffset
    );
	STDMETHOD(SystemError)(
		THIS_
    	IN ULONG  Error,
    	IN ULONG  Level
    );
	STDMETHOD(ChangeSymbolState)(
		THIS_
		IN ULONG  Flags,
    	IN ULONG64  Argument
    );
	STDMETHOD(ChangeDebuggeeState)(
		THIS_
		IN ULONG  Flags,
    	IN ULONG64  Argument
    );
	STDMETHOD(ChangeEngineState)(
		THIS_
		IN ULONG  Flags,
    	IN ULONG64  Argument
    );
	STDMETHOD(UnloadModule)(
		THIS_
   		IN PCSTR  ImageBaseName,
    	IN ULONG64  BaseOffset
    );


};




extern EventCallbacks g_EvtCbs;

#endif