#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <dbgeng.h>

#include "dlistener_eventcb.h"
#include "dlistener_net.h"
#include "dlistener_windbg.h"
#include "dlistener_wdbg.h"

EventCallbacks g_EvtCbs;

STDMETHODIMP_(ULONG)
EventCallbacks::AddRef(
    THIS
    )
{
    // This class is designed to be static so
    // there's no true refcount.
    return 1;
}

STDMETHODIMP_(ULONG)
EventCallbacks::Release(
    THIS
    )
{
    // This class is designed to be static so
    // there's no true refcount.
    return 0;
}

STDMETHODIMP
EventCallbacks::GetInterestMask(
    THIS_
    OUT PULONG Mask
    )
{
    *Mask = DEBUG_EVENT_BREAKPOINT | 
			DEBUG_EVENT_CREATE_PROCESS | 
			DEBUG_EVENT_CHANGE_ENGINE_STATE |
			DEBUG_EVENT_CREATE_THREAD;
    return S_OK;
}

STDMETHODIMP
EventCallbacks::Breakpoint(
    THIS_
    IN PDEBUG_BREAKPOINT Bp
    )
{
    ULONG Id;
    ULONG64 bpAddr;

    if (Bp->GetId(&Id) != S_OK)
    {
        return DEBUG_STATUS_BREAK;
    }
	// get address
	if (Bp->GetOffset(&bpAddr) != S_OK)
    {
        return DEBUG_STATUS_BREAK;
    }
	/*
	Funny story, turns out I can handle this
	stuff down in the ChangeEngineState handler.
	Peace!
	// update registers state
	update_registers();
	// send the BPHIT message
	if (is_client_connected())
		send_bphit(bpAddr);
	*/
    return DEBUG_STATUS_BREAK;
}

STDMETHODIMP
EventCallbacks::Exception(
    THIS_
    IN PEXCEPTION_RECORD64 Exception,
    IN ULONG FirstChance
    )
{	
	dprintf("Exception occurred!\n");
	if(Exception->ExceptionCode == EXCEPTION_SINGLE_STEP){
		// update registers state
		update_registers();
		// send the BPHIT message
		ULONG64 addr = (ULONG64)Exception->ExceptionAddress;
		if (is_client_connected())
			send_bphit(addr);
		return DEBUG_STATUS_BREAK;
	}
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::CreateProcess(
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
    )
{
    /*UNREFERENCED_PARAMETER(ImageFileHandle);
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(ModuleSize);
    UNREFERENCED_PARAMETER(ModuleName);
    UNREFERENCED_PARAMETER(CheckSum);
    UNREFERENCED_PARAMETER(TimeDateStamp);
    UNREFERENCED_PARAMETER(InitialThreadHandle);
    UNREFERENCED_PARAMETER(ThreadDataOffset);
    UNREFERENCED_PARAMETER(ImageName);*/
    
	dprintf("Create Process occurred.  BaseOffset is 0x%08x, StartOffset is 0x%08x!\n",BaseOffset,StartOffset );
    //dprintf("        PEB address is 0x%08x!\n",get_debuggee_baseoffset() );
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::LoadModule(
    THIS_
    IN ULONG64 ImageFileHandle,
    IN ULONG64 BaseOffset,
    IN ULONG ModuleSize,
    IN PCSTR ModuleName,
    IN PCSTR ImageName,
    IN ULONG CheckSum,
    IN ULONG TimeDateStamp
    )
{
    dprintf("Load Module occurred!\n");
	dprintf("BaseOffset is 0x%08x. Imagename %s!\n",BaseOffset, ModuleName );
    dprintf("        PEB address is 0x%08x!\n",get_debuggee_baseoffset() );

    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::SessionStatus(
    THIS_
    IN ULONG SessionStatus
    )
{
    // A session isn't fully active until WaitForEvent
    // has been called and has processed the initial
    // debug events.  We need to wait for activation
    // before we query information about the session
    // as not all information is available until the
    // session is fully active.  We could put these
    // queries into CreateProcess as that happens
    // early and when the session is fully active, but
    // for example purposes we'll wait for an
    // active SessionStatus callback.
    // In non-callback applications this work can just
    // be done after the first successful WaitForEvent.
    if (SessionStatus != DEBUG_SESSION_ACTIVE)
    {
        return DEBUG_STATUS_NO_CHANGE;
    }
    dprintf("Session Status occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}
STDMETHODIMP
EventCallbacks::ChangeDebuggeeState(
    THIS_
	IN ULONG  Flags,
    IN ULONG64  Argument){
    //dprintf("Change Debuggee State Status occurred!  Flags: 0x%08x Argument: 0x%08x\n", Flags, Argument);
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::ChangeEngineState(
    THIS_
	IN ULONG  Flags,
    IN ULONG64  Argument){
	
	ULONG64 addr = 0;
	if (Flags == DEBUG_CES_EXECUTION_STATUS){
		switch(Argument){
			case DEBUG_STATUS_STEP_OVER:
			case DEBUG_STATUS_STEP_INTO:
			case DEBUG_STATUS_BREAK:
			case DEBUG_STATUS_REVERSE_STEP_BRANCH:
			case DEBUG_STATUS_REVERSE_STEP_OVER:
			case DEBUG_STATUS_REVERSE_STEP_INTO:
				//update_registers();
				addr = get_current_pc();
				if (is_client_connected() && addr != -1){
					dprintf("A Break or step occurred, sending the following address: 0x%08x\n", addr);
					dprintf("        PEB address is 0x%08x!\n",get_debuggee_baseoffset() );
					send_bphit(addr);
				}
		}
	}
    return DEBUG_STATUS_NO_CHANGE;
}
STDMETHODIMP
EventCallbacks::UnloadModule(
    IN PCSTR  ImageBaseName,
    IN ULONG64  BaseOffset
	){
	UNREFERENCED_PARAMETER(ImageBaseName);
    UNREFERENCED_PARAMETER(BaseOffset);
    dprintf("Unload Module occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::ExitProcess(
    THIS_
	IN ULONG  ExitCode){
	 dprintf("Exit Process occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}


STDMETHODIMP
EventCallbacks::ChangeSymbolState(
    THIS_
	IN ULONG  Flags,
    IN ULONG64  Argument){
    dprintf("Change Symbol State Status occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::SystemError(
    THIS_
	IN ULONG  Error,
	IN ULONG  Level){
	dprintf("Change Symbol State Status occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::CreateThread(
    THIS_
  	IN ULONG64  Handle,
    IN ULONG64  DataOffset,
    IN ULONG64  StartOffset){
    dprintf("Create Thread occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::ExitThread(
    THIS_
	IN ULONG  ExitCode){
	 dprintf("Exit Thread occurred!\n");
    return DEBUG_STATUS_NO_CHANGE;
}