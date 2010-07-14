/*
dlistener_windbg.cpp
Authors:	Adam Pridgen

Summary:	

*/

//#include <winnt.h>
#include <dbgeng.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <string>
#include <windows.h>
#include <set>
#include <map>
//#include <winternl.h>


//#include "seh_exception.h"
#include "cmd_translation.h"
#include "dlistener.h"
#include "dlistener_eventcb.h"
#include "dlistener_net.h"
#include "dlistener_windbg.h"
#include "dlistener_wdbg.h"


#define PLUGIN_NAME "dlistener"
#define BADADDR 4294967295
#define log dprintf
PDEBUG_CLIENT4 cbClient;
extern EventCallbacks g_EvtCbs;



std::map<std::string, ULONG64> regs_vals;
void initialize_registers(){
	
	get_registers_and_values(regs_vals);

}

int exception_filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{

	if(code == EXCEPTION_ACCESS_VIOLATION)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	
	return EXCEPTION_CONTINUE_SEARCH;

}


PDEBUG_SYSTEM_OBJECTS get_sysobj_interface(){

	PDEBUG_CLIENT4 l_Client;
	PDEBUG_SYSTEM_OBJECTS l_SysObj;
	if(DebugCreate( __uuidof(IDebugClient), (void **)&l_Client) != S_OK){
		return NULL;
	}
	if ( l_Client->QueryInterface(__uuidof(IDebugSystemObjects),(void **)&l_SysObj) != S_OK)
    {
    	return NULL;
    }
	return l_SysObj;
}

PDEBUG_DATA_SPACES4 get_dataspace_interface(){

	PDEBUG_CLIENT4 l_Client;
	PDEBUG_DATA_SPACES4 l_Dspace;
	if(DebugCreate( __uuidof(IDebugClient), (void **)&l_Client) != S_OK){
		return NULL;
	}
	if ( l_Client->QueryInterface(__uuidof(IDebugDataSpaces),(void **)&l_Dspace) != S_OK)
    {
    	return NULL;
    }
	return l_Dspace;
}

PDEBUG_CLIENT4 get_client_interface(){

	PDEBUG_CLIENT4 l_Client;
	if(DebugCreate( __uuidof(IDebugClient), (void **)&l_Client) != S_OK){
		return NULL;
	}
	return l_Client;
}


PDEBUG_CONTROL get_control_interface(){
	HRESULT Status = S_OK;
	PDEBUG_CLIENT4 l_Client;
	PDEBUG_CONTROL l_ExtControl;
	if(DebugCreate( __uuidof(IDebugClient), (void **)&l_Client) != S_OK){
		return NULL;
	}
	if (l_Client->QueryInterface(__uuidof(IDebugControl),(void **)&l_ExtControl) == S_OK)
		return l_ExtControl; 
	return NULL;
}



bool get_images_by_names(std::vector<std::string> &image_names){
	ULONG64 peb;
	PEB thepeb;
	ZeroMemory(&thepeb, sizeof(thepeb));
	ULONG64 ImageBaseAddress_off = (ULONG64)&(thepeb.ImageBaseAddress) - (ULONG64)&thepeb;
	ULONG64 addr = -1, peb_off;
	PDEBUG_SYSTEM_OBJECTS l_SysObj = get_sysobj_interface();
	// retrieve the peb address from the process
	if(l_SysObj == NULL)
		return addr;
	if(l_SysObj->GetCurrentProcessPeb(&peb) != S_OK)
		return addr;
	EXT_RELEASE(l_SysObj);

	if (!get_vmemory_off_values(peb,&thepeb, sizeof(PEB),NULL)){
		addr = -1;
	}

	//RTL_USER_PROCESS_PARAMETERS processParameters;
	//if (!get_vmemory_off_values((ULONG64)(thepeb.ProcessParameters),&processParameters, sizeof(processParameters),NULL)){
	//	addr = -1;
	//}
	std::string image_name;
	UNICODE_STRING p_name = thepeb.ProcessParameters->ImagePathName;
	//convert_wchar_to_string(p_name.Buffer, image_name);
	dprintf("Image name: %s\n",image_name);
	PPEB_LDR_DATA ldr = ((PPEB)peb )->Ldr;
	LIST_ENTRY head = ldr->InMemoryOrderModuleList,
						 next = head;
	ULONG64 size;
	do{
		LDR_DATA_TABLE_ENTRY *pldr_data =  (LDR_DATA_TABLE_ENTRY *)(next.Flink);
		UNICODE_STRING wdll_name = pldr_data->FullDllName;
		std::string dll_name;
		ULONG64 dllBase = (ULONG64)pldr_data->DllBase,
				entryPoint = 0;
		convert_wchar_to_string(wdll_name.Buffer, dll_name);
		dprintf("Name: %s Base: 0x%08x Entrypoint: 0x%08x\n",dll_name, dllBase, entryPoint);
		image_names.push_back(dll_name);
		next = pldr_data->InMemoryOrderLinks;
	}while(&head != &next);
	return addr;
}

bool read_unicode_string_buffer(UNICODE_STRING *pUniStr, std::string& out){
	bool result = false;
	out = "";
	if (pUniStr->MaximumLength == 0 || pUniStr->Length == 0 ||
		pUniStr->MaximumLength < pUniStr->Length  )
		return result;

	wchar_t *buffer = new wchar_t[pUniStr->Length+sizeof(wchar_t)];
	if (buffer == NULL){
		return result;
	}
	ZeroMemory(buffer, pUniStr->Length+sizeof(wchar_t));
	if (!get_vmemory_off_values((ULONG64)pUniStr->Buffer,buffer,sizeof(wchar_t)*pUniStr->Length,NULL)){
		delete buffer;
	}else{
		result = true;
		convert_wchar_to_string(buffer, out);
		delete buffer;

	}
	return result;
}

std::string get_base_filename(std::string fullname){
	ULONG64 pos =  std::string::npos;
	if ((pos = fullname.find_last_of("\\") )!= std::string::npos &&
		pos+1 < fullname.size() ){
		return fullname.substr(pos+1,fullname.size()-pos);
	}else{
		return fullname;
	}

}

// Function still lists all the modules shown in the
// debugger, but the MemoryLocation and the DllBase
// and ImageName are all valid  
ULONG64 get_image_base_address(std::string search_image){
	
	ULONG64 peb;
	PEB thepeb;
	ULONG64 ImageBaseAddress_off = (ULONG64)&(thepeb.ImageBaseAddress) - (ULONG64)&thepeb;
	ULONG64 addr = -1, peb_off;
	PDEBUG_SYSTEM_OBJECTS l_SysObj = get_sysobj_interface();
	// retrieve the peb address from the process
	if(l_SysObj == NULL)
		return addr;
	if(l_SysObj->GetCurrentProcessPeb(&peb) != S_OK)
		return addr;
	EXT_RELEASE(l_SysObj);	
	ZeroMemory(&thepeb, sizeof(thepeb));
	if (!get_vmemory_off_values(peb,&thepeb,sizeof(thepeb),NULL)){
	//if (!get_pvmemory_off_value(peb, &addr)){
		addr = -1;
	}

	
	std::string image_fullname, image_filename;
	PPEB ppeb = (PPEB) &thepeb;
	RTL_USER_PROCESS_PARAMETERS processParameters;
	ZeroMemory(&processParameters, sizeof(processParameters));
	if (!get_vmemory_off_values((ULONG64)(ppeb->ProcessParameters),&processParameters,sizeof(processParameters),NULL)){
	//if (!get_pvmemory_off_value(peb, &addr)){
		addr = -1;
	}

	UNICODE_STRING p_name = processParameters.ImagePathName;
	
	if (!read_unicode_string_buffer(&processParameters.ImagePathName, image_fullname))
		return addr;
	//dprintf("Image name: %s\n",image_fullname.c_str());
	
	image_filename = get_base_filename(image_fullname);
	
	if (search_image == image_filename || search_image == image_fullname){
		return get_debuggee_baseoffset();
	}

	//dprintf("Image file name: %s\n",image_filename.c_str());
	
	PEB_LDR_DATA obtainLdrOff;
	ULONG64 inMemModuleListOff = (ULONG64) (&obtainLdrOff.InMemoryOrderModuleList) -(ULONG64) (&obtainLdrOff);
	PPEB_LDR_DATA ldr = ppeb->Ldr;
	ULONG64 list_entry_off = *(ULONG64 *) &(ldr->InMemoryOrderModuleList) -  *(ULONG64 *) ldr;
	LIST_ENTRY head = ldr->InMemoryOrderModuleList, 
						next = head;
	ULONG64 x = (ULONG64)head.Blink;
	
	next = head;
	do{
		bool failed_to_read_name = false;
		LDR_DATA_TABLE_ENTRY *pldr_data =  (LDR_DATA_TABLE_ENTRY *)(next.Flink);
		std::string dll_fullname, dll_filename;
		ULONG dllLocation = (ULONG) pldr_data->MemoryLocation, 
			  dllBase =  (ULONG) pldr_data->DllBase;
				
		
		// catch the ACCESS_VIOLATION exception if the dll is a bad name
		__try{
			convert_wchar_to_string(pldr_data->FullDllName.Buffer,dll_fullname);
		} __except(exception_filter(GetExceptionCode(), GetExceptionInformation()) ) {
			dll_fullname = "";
		}

		dll_filename = get_base_filename(dll_fullname);
		
		//dprintf("Base: 0x%08x Memory: 0x%08x   Name: %s \n", dllBase, dllLocation,dll_filename.c_str());
		if (dll_filename == search_image){
			return getBaseOfCode(dllLocation);
		}
		next = *next.Flink;
	}while(head.Flink != next.Flink);
	return addr;

}


// TODO: make this happen when the server is initialized
// TODO: do i want to grab *all* registers?  If so the
// g_ExtRegisters needs to be used to grab all the registers
void init_register_value(const char* reg_array[]){
	
	for(unsigned int i=0; reg_array[i] != 0;i++){
		std::string r = reg_array[i];
		regs_vals[r] = 0;
	}
}

bool get_vmemory_off_values(ULONG64 offset, PVOID value, ULONG bufSize, ULONG *bytesRead){
	
	PDEBUG_DATA_SPACES4 l_DataSpace = get_dataspace_interface();
	bool success = false;
	if(l_DataSpace == NULL)
		return false;
	if(l_DataSpace->ReadVirtual(offset,value,bufSize,bytesRead) == S_OK)
		success = true;
	EXT_RELEASE(l_DataSpace);
	return success;
}

bool set_vmemory_off_values(ULONG64 offset, PVOID value, ULONG bufSize, ULONG *bytesWrote){
	
	PDEBUG_DATA_SPACES4 l_DataSpace = get_dataspace_interface();
	bool success = false;
	if(l_DataSpace == NULL)
		return false;
	if(l_DataSpace->WriteVirtual(offset,value,bufSize,bytesWrote) == S_OK)
		success = true;
	EXT_RELEASE(l_DataSpace);
	return success;
}


bool get_vmemory_off_value(ULONG64 offset, ULONG64 *value){
	PDEBUG_DATA_SPACES4 l_DataSpace = get_dataspace_interface();
	bool success = false;
	*value = -1;
	return get_vmemory_off_values(offset, (PVOID)value, sizeof(value),NULL);
}
bool get_pvmemory_off_value(ULONG64 offset, ULONG64 *value){
	return get_pvmemory_off_values(1, offset, value);
}
bool get_pvmemory_off_values(ULONG cnt, ULONG64 offset, ULONG64 *value){
	PDEBUG_DATA_SPACES4 l_DataSpace = get_dataspace_interface();
	bool success = false;
	*value = -1;
	if(l_DataSpace == NULL)
		return false;
	if(l_DataSpace->ReadPointersVirtual(cnt, offset,value) == S_OK)
		success = true;
	EXT_RELEASE(l_DataSpace);
	return success;
}

bool get_register_value(char *reg, ULONG64 *value){
	*value = -1;
	ULONG reg_idx;
	DEBUG_VALUE rvalue;
	PDEBUG_REGISTERS l_Registers = get_register_interface();
	bool success = false;
	if(l_Registers == NULL)
		return false;
	if(l_Registers->GetIndexByName(reg,&reg_idx) == S_OK){
		if(l_Registers->GetValue(reg_idx, &rvalue) == S_OK){
			*value = rvalue.I64;
			success = true;
		}
	}
	EXT_RELEASE(l_Registers);
	return success;
}

// this function may be called from anywhere,
// so we need to create a new client and get 
// the current address via a register.
ULONG64 get_current_pc(){
	ULONG64 addr = -1;
	DEBUG_VALUE value;
	if(get_register_value("rip",&addr)){
		return addr;
	}else if(get_register_value("eip",&addr)){
		return addr;
	}
	else{
		dprintf("Could not find the eip or rip register.  WTF?  you need to implement your own PC retrival, Dude!");
	}
	return -1;
}

ULONG64 getBaseOfCode(ULONG64 addr){
	ULONG64 rebase_addr = -1;
	IMAGE_NT_HEADERS64 imageHeaders64;
	ZeroMemory(&imageHeaders64, sizeof(IMAGE_NT_HEADERS64));
	PDEBUG_DATA_SPACES4 l_DataSpaceObj = get_dataspace_interface();
	if(l_DataSpaceObj == NULL)
		return rebase_addr;
	if(l_DataSpaceObj->ReadImageNtHeaders(addr, &imageHeaders64) != S_OK)
		return rebase_addr;
	EXT_RELEASE(l_DataSpaceObj);	
	
	rebase_addr = imageHeaders64.OptionalHeader.BaseOfCode + addr;
	return rebase_addr;

}

ULONG64 get_debuggee_baseoffset(){
	IMAGE_DOS_HEADER dosHeader;
	ULONG64 peb;
	PEB dummy;
	ULONG64 ImageBaseAddress_off = (ULONG64)&(dummy.ImageBaseAddress) - (ULONG64)&dummy;
	ULONG64 addr = -1, peb_off, rebase_addr = -1;

	PDEBUG_SYSTEM_OBJECTS l_SysObj = get_sysobj_interface();
	// retrieve the peb address from the process
	if(l_SysObj == NULL)
		return rebase_addr;
	if(l_SysObj->GetCurrentProcessPeb(&peb) != S_OK)
		return rebase_addr;
	EXT_RELEASE(l_SysObj);	
	if (!get_pvmemory_off_value(peb+ImageBaseAddress_off, &addr)){
		return rebase_addr;
	}
	return getBaseOfCode(addr);
	
}	


PDEBUG_REGISTERS get_register_interface(){
	PDEBUG_CLIENT4 l_Client;
	PDEBUG_REGISTERS l_Registers;
	if(DebugCreate( __uuidof(IDebugClient), (void **)&l_Client) != S_OK){
		return NULL;
	}
	if ( l_Client->QueryInterface(__uuidof(IDebugRegisters),(void **)&l_Registers) != S_OK)
    {
    	return NULL;
    }
	return l_Registers;
}

void update_registers(){
	std::map<std::string, ULONG64>::iterator iter = regs_vals.begin();
	PDEBUG_REGISTERS l_Registers = get_register_interface();
	if(l_Registers == NULL)
		return ;
	
	for(;iter != regs_vals.end();iter++){
		ULONG idx;
		DEBUG_VALUE v;
		memset(&v, 0, sizeof(v));
		if(l_Registers->GetIndexByName(iter->first.c_str(), &idx)!=S_OK){
			log(PLUGIN_NAME": Failed to get the register index value for %s.\n",iter->first.c_str());	
		}
		if(l_Registers->GetValue(idx, &v)!=S_OK){
			log(PLUGIN_NAME": Failed to get the register value for %u.\n",idx);	
		}
		// this might be a bug.  on x86 a 64 bit number can exist on [eax + edx], or something like that
		iter->second = v.I64;
	}
}

void get_registers(std::string &regs){
	update_registers();
	convert_reg_vals_to_string(regs_vals, regs);
}


bool check_convert_addr_val(std::string in, ULONG64 *ea){
	char *c = (char *) in.c_str();
	if (all_digits_c(c)){
		*ea = convert_string_to_addr(in);
		return true;
	}
	// check for deref operator
	if (*c == '*'){
		if (!get_register_value(++c, ea)){
			return false;
		}
		ULONG64 off = *ea;
		/* 
		   this will sign extend the value and create
		   a pointer out of the read parameter. think
		   this is what we want, hmm, not sure though.
		*/
		return get_pvmemory_off_value(*ea,ea); 
	}
	return get_register_value(c, ea);
}

void get_registers_and_values(std::map<std::string, ULONG64> &reg_collection){
	
	PDEBUG_REGISTERS l_Registers = get_register_interface();
	if(l_Registers == NULL)
		return ;
	
	unsigned long reg_cnt;
	if(l_Registers->GetNumberRegisters(&reg_cnt)!=S_OK){
			log(PLUGIN_NAME": Failed to get the number of registers.\n");	
	}
	char buf[2048];
	unsigned long name_sz;
	for(unsigned long idx =0;idx < reg_cnt;idx++){
		*buf = 0;
		name_sz &= 0;
		DEBUG_VALUE v;
		memset(&v, 0, sizeof(v));
		if(l_Registers->GetDescription(idx, buf, 2048, &name_sz, NULL)!=S_OK){
			log(PLUGIN_NAME": Failed to get the register name for %d.\n",idx);	
		}

		if(l_Registers->GetValue(idx, &v)!=S_OK){
			log(PLUGIN_NAME": Failed to get the register value for %u.\n",idx);	
		}
		std::string reg_name = buf;
		reg_collection[reg_name] = v.I64;
	}

}

void set_registers(std::map<std::string, std::string> &regs){

	std::map<std::string, std::string>::iterator reg = regs.begin();
	std::map<ULONG, ULONG64> idx_vals;
	if(regs.size() == 0)
		return;
	g_ExtRegisters = get_register_interface();
	for(;reg != regs.end(); reg++){
		ULONG idx = 0;
		DEBUG_VALUE reg_val;

		ZeroMemory(&reg_val, sizeof(reg_val));
		if (g_ExtRegisters->GetIndexByName(reg->first.c_str(), &idx) != S_OK){
			log(PLUGIN_NAME": failed to get register index for %s\n",reg->first.c_str());
			continue;
		}
		idx_vals[idx] = convert_string_to_addr(reg->second);		
	}
	
	ULONG count = idx_vals.size();
	
	DEBUG_VALUE *val_ary = new DEBUG_VALUE[count];
	ZeroMemory(val_ary, sizeof(DEBUG_VALUE)*count);
	
	ULONG *idx_ary = new ULONG[count];
	ZeroMemory(idx_ary, sizeof(ULONG)*count);
	
	std::map<ULONG, ULONG64>::iterator idx_vals_i = idx_vals.begin();
	
	for(ULONG i=0; idx_vals_i != idx_vals.end(); idx_vals_i++,i++){
		idx_ary[i] = idx_vals_i->first;
		if (sizeof(ULONG) == 8){
			val_ary[i].I64 = idx_vals_i->second;
			val_ary[i].Type = DEBUG_VALUE_INT64;
		}
		else{
			val_ary[i].I32 = idx_vals_i->second;
			val_ary[i].Type = DEBUG_VALUE_INT32;
		}
	}
	if (g_ExtRegisters->SetValues(count, 
								  idx_ary, 
								  0,
								  val_ary) != S_OK){
		log(PLUGIN_NAME": failed to set register values, not sure which ones though\n");
	}
	delete val_ary;
	delete idx_ary;
}

// Start the Extension commands
void hello_world(){
	std::string arg_s = "makename 0x40000 main";
	//std::vector<std::string > *cmd = tokenize(args_s);


	dprintf("Hello world...yes, bunnies and jaguars are fucking awesome.  *Fistbump*\n");


}


void cleanup_vector_strs(std::vector<std::string > *x){
	x->clear();
	delete x;
}


bool set_eventcbs(){
	bool result = true;
	PDEBUG_CLIENT4 l_Client = NULL;
	if ((l_Client = get_client_interface()) == NULL){
		log(PLUGIN_NAME": Failed to set the CallBack events cbClient: 0x%08x.\n", (ULONG)cbClient);
		return false;
	}
	if (l_Client->SetEventCallbacks(&g_EvtCbs) != S_OK){
		result = false;
		log(PLUGIN_NAME": Failed to set the CallBack events cbClient: 0x%08x.\n", (ULONG)cbClient);
	}
	l_Client->Release();
	return result;
}


HRESULT dlistener_handler(PDEBUG_CLIENT4 Client, PCSTR args){
	static bool handling_ml_cmd = false;
	static std::string cached_cmd_args = "",
					   cached_cmd = "";
	std::string cmd = "",
				cmd_args = "",
				cli_input = args;

	
	//Release_Interfaces();
	static bool init_cmd_handlers = false;
	unsigned int x = cli_input.find_first_not_of(" ");
	if (handling_ml_cmd && cli_input == ""){
		cmd = cached_cmd;
		cached_cmd = "";
		cmd_args = cached_cmd_args ;
		cached_cmd_args = "";
		handling_ml_cmd = false;
		return execute_command_handler(cmd, cmd_args);
	}else if(handling_ml_cmd){
		cached_cmd_args += (cli_input+"\n");
		return true;
	}
	
	
	cmd = cli_input.substr(0, cli_input.find_first_of(" "));
	cmd_args = "";
	if (!init_cmd_handlers){
		init_command_handlers();
		init_cmd_handlers = true;
	}
	if(cmd.size() != cli_input.size())
		cmd_args = cli_input.substr(cmd.size()+1, cli_input.size()-cmd.size());
	cmd = get_command_alias(cmd);
	if(!is_listening() && cmd != "start"){
		log("Only start and stop can be called when the listener is not running.\n");
		return S_OK;	
	}
	
	if(is_ml_command(cmd)){
		handling_ml_cmd = true;
		cached_cmd = cmd;
		cached_cmd_args  = cmd_args+"\n";
		return true;
	}else if(cmd == "hello world"){
		hello_world();
		return S_OK;
	}

	if(execute_command_handler(cmd, cmd_args)){
		log("Successfully called %s with %s\n", cmd.c_str(),cmd_args.c_str());
		if (cmd == "start"){
			if (set_eventcbs())
				log("Successfully added event callbacks\n");
		}	
	}
	else{
		log("UNSUPPORTED command: %s\n", cmd.c_str());
	}
	return S_OK;
}


HRESULT ida_handler(PDEBUG_CLIENT4 Client, PCSTR args){
	std::string args_s = args;
	//std::vector<std::string > *cmd = tokenize(args_s);
	// we are going to send the IDA command over as a string, and just 
	// let IDA python handle the hard parts
	
	bool cmdError = false;
	if(!is_listening()){
		dprintf(PLUGIN_NAME": Debug listener is not started yet.\n");
		return S_OK;
	}else if(!is_client_connected() && !is_connected()){
		dprintf(PLUGIN_NAME": There is no client connection.\n");
		return S_OK;
	}
	
	
	//ULONG ida_cmd = get_type_from_cmd((*cmd)[0]);
	unsigned char req = 0;
	send_idapython_cmd("pycmd "+args_s);
	return S_OK;
}


HRESULT dl_cmd_handler(PDEBUG_CLIENT4 Client, PCSTR args){
	std::string args_s = args;
	bool cmdError = false;
	if(!is_listening()){
		dprintf(PLUGIN_NAME": Debug listener is not started yet.\n");
		return S_OK;
	}else if(!is_client_connected() && !is_connected()){
		dprintf(PLUGIN_NAME": There is no client connection.\n");
		return S_OK;
	}
	// execute_cli_commnads are commands that will be executed locally and id so sent else where
	if(execute_command_handler(args_s)){
		//send_data(buf);
		dprintf(PLUGIN_NAME": Successully handled command and sent msg.\n");
	}else{
		dprintf(PLUGIN_NAME": Unable to handle command: %s.\n", args_s.c_str());

	}
	

	return S_OK;
}

HRESULT test_handler(PDEBUG_CLIENT4 Client, PCSTR args){
	std::string args_s = args;
	// using this function to test code	
	bool cmdError = false;
	ULONG64 x = get_image_base_address(args_s);
	
	
	return S_OK;
}


bool get_remote_dlistener_regs(std::string args){
	/* TODO */
	return true;
}

