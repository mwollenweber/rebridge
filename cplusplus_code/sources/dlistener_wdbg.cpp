/*
dlistener_wdbg.cpp
Authors:	Adam Pridgen
			Matthew Wollenweber

Summary:	This file contains idabridge commands specific to windbg and are placed here rather than cmd_translation

*/
#include <DbgEng.h>
#include <dbgeng.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <string>
#include <windows.h>
#include <set>
#include <map>


#include "cmd_translation.h"
#include "dlistener.h"
#include "dlistener_wdbg.h"
#include "dlistener_windbg.h"
#include "dlistener_net.h"
#include "Buffer.h"


inline void endian_swap(unsigned __int64& x);
inline void endian_swap(unsigned int& x);

#define PLUGIN_NAME "dlistener"
#define log dprintf


volatile SOCKET dbg_server_conn = INVALID_SOCKET,
		 		current_client = INVALID_SOCKET;
bool RUN_SERVER = false;
HANDLE SERVER_THREAD = INVALID_HANDLE_VALUE;

PDEBUG_CLIENT4 gs_ExtClient;
PDEBUG_CONTROL gs_ExtControl;
PDEBUG_SYMBOLS2 gs_ExtSymbols;
PDEBUG_REGISTERS gs_ExtRegisters;
PDEBUG_SYSTEM_OBJECTS gs_ExtSystemObjects;

void Initialize_Server_Interfaces()
{
    HRESULT Status;
	if((Status = DebugCreate( __uuidof(IDebugClient), (void **)&gs_ExtClient)) != S_OK){
		goto Fail;
	}
	if (gs_ExtClient==NULL){
		goto Fail;
	}
    if ((Status = gs_ExtClient->QueryInterface(__uuidof(IDebugControl),(void **)&gs_ExtControl)) != S_OK){
        goto Fail;
    }
    if ((Status = gs_ExtClient->QueryInterface(__uuidof(IDebugSymbols2),(void **)&gs_ExtSymbols)) != S_OK){
    	goto Fail;
    }
	if ((Status = gs_ExtClient->QueryInterface(__uuidof(IDebugRegisters),(void **)&gs_ExtRegisters)) != S_OK){
    	goto Fail;
    }
	if ((Status = gs_ExtClient->QueryInterface(__uuidof(IDebugSystemObjects),(void **)&gs_ExtSystemObjects)) != S_OK){
    	goto Fail;
    }
	if ((Status = gs_ExtClient->QueryInterface(__uuidof(IDebugControl),(void **)&gs_ExtControl)) != S_OK){
        goto Fail;
    }
    if ((Status = gs_ExtClient->QueryInterface(__uuidof(IDebugSymbols2),(void **)&gs_ExtSymbols)) != S_OK){
		goto Fail;
    }
	return;

 Fail:	
    Release_Server_Interfaces();
    return;
}

void Release_Server_Interfaces()
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
	gs_ExtClient = NULL;
}



//#define log dprintf

// START Eagles code
//buffer to cache data in the case WSAEWOULDBLOCK
static Buffer sendBuf;

bool is_listening(){
	return dbg_server_conn != INVALID_SOCKET;
}
bool is_client_connected(){
	return current_client != INVALID_SOCKET;
}
bool is_connected(){
	// TODO: implement a client aspect where i can connect to a 
	// remote server
	// in case i want to implement a client for this later, rather 
	// than waiting for a connection
	// for the time being always return false
	return false;
}


bool init_network(){
	WSADATA wsock;
	if (WSAStartup(MAKEWORD(2, 2), &wsock) != 0) {
	  log(PLUGIN_NAME": init_network() failed.\n");
	  return false;
	}
	//check requested version
	if (LOBYTE(wsock.wVersion) != 2 || HIBYTE(wsock.wVersion) != 2) {
	  WSACleanup();
	  log(PLUGIN_NAME": Winsock version 2.2 not found.\n");
	  return false;
	}
	return true;
}
// added the bind and listen code here
BOOL init_listener_socket(std::string &host, short port){

	SOCKET sock;
	sockaddr_in *result = NULL, *ptr = NULL, hints;
	memset(&hints,0,sizeof(hints));
	hints.sin_family = AF_INET;
	hints.sin_addr.s_addr = inet_addr((char *)host.c_str());
	hints.sin_port = htons(port);
	//If a domain name was specified, we may not have an IP.
	if (hints.sin_addr.s_addr == INADDR_NONE) {
	  hostent *he = gethostbyname((char *)host.c_str());
	  if (he == NULL) {
	     log(PLUGIN_NAME": Unable to resolve name: %s\n", (char *)host.c_str());
	     return INVALID_SOCKET;
	  }
	  hints.sin_addr = *(in_addr*) he->h_addr;
	}

	//create a socket.
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET) {
		if (bind( sock, (sockaddr *)&hints, sizeof(hints)) == SOCKET_ERROR){
		 log(PLUGIN_NAME": Failed to bind the socket.\n");
		 closesocket(sock);
	     sock = INVALID_SOCKET;
	  }
	}
	if ( listen( sock, SOMAXCONN ) == SOCKET_ERROR ) {
		log( PLUGIN_NAME": Error at listen(): %ld\n", WSAGetLastError() );
	    closesocket(sock);
	    WSACleanup();
		sock = INVALID_SOCKET;
	}
	if(sock != INVALID_SOCKET){
		log( PLUGIN_NAME": Socket successfully started.\n");
	}
	return sock;
}

//how large if the current data packet under construction
int requiredSize(Buffer &b) {
   if (b.size() >= (int)sizeof(int)) {
      return ntohl(*(int*)b.get_buf());
   }
   return -1;
}
//does the buffer containa a complete data packet?
bool isComplete(Buffer &b) {
   int rs = requiredSize(b);
   return rs > 0 && b.size() >= rs;
}

//shift the content of a buffer left by one data packet
void shift(Buffer &b) {
   if (isComplete(b)) {
      unsigned int rs = requiredSize(b);
      unsigned int extra = b.size() - rs;
      const unsigned char *buf = b.get_buf();
      b.reset();
      if (extra) {
         b.write(buf + rs, extra);
      }
   }
}

//shift the content of a buffer left by len bytes
void shift(Buffer &b, int len) {
   if (len <= b.size()) {
      int extra = b.size() - len;
      const unsigned char *buf = b.get_buf();
      b.reset();
      if (extra) {
         b.write(buf + len, extra);
      }
   }
}

// based on Eagles IDA Connector
int send_data(Buffer &b, SOCKET sock) {
   SOCKET conn_local = sock != INVALID_SOCKET? sock: current_client;
   if (conn_local == INVALID_SOCKET) return 0;  
   
   Buffer out(b.size() + sizeof(int));
   int sz = b.size() + sizeof(int);
   out.writeInt(sz);
   //stats[1][command]++;
   out << b;
   int len = send(conn_local, (const char*)out.get_buf(), out.size(), 0);
   if (len == SOCKET_ERROR) {
      int error = WSAGetLastError();
      if (error == WSAEWOULDBLOCK) {
         sendBuf << out;
         return 0;
      }
      else {
         //cleanup();
         //killWindow();
         log(PLUGIN_NAME": Failed to send requested data. %d != %d. Error: %x, %d\n", len, out.size(), error, error);
         return -1;
      }
   }
   else if (len != out.size()) {
      //move the remainder into sendBuf
      shift(out, len);
      sendBuf << out;
      //msg(PLUGIN_NAME": Short send. %d != %d.", len, out.size());
   }
   return len;
}


DWORD WINAPI run_server(LPVOID args){
	std::vector<std::string > *a = (std::vector<std::string > *) ((LPVOID *)args)[0];
	std::string host = (*a)[0],
		 port = (*a)[1];
	std::string localhost = "127.0.0.1";
	HANDLER handler = (HANDLER) ((LPVOID *)args)[1];
	//g_ExtClient = *((PDEBUG_CLIENT4 *) ((LPVOID *)args)[2]);
	delete a;
	short s_port = 0;
	if(port.size() > 0)
		s_port = (short) atoi(port.c_str());
	
	if (s_port == 0)
		s_port = DEFAULT_PORT;
	
	if (host.size() == 0) 
		host = localhost;
	
	//log(PLUGIN_NAME": Starting the listener with the following params, host: %s port: %d\n",host.c_str(), s_port);
	dbg_server_conn = init_listener_socket(host, s_port);
	while(RUN_SERVER && dbg_server_conn != INVALID_SOCKET){
		SOCKET client = INVALID_SOCKET;
		client = accept(dbg_server_conn, NULL, NULL);
		if (client == INVALID_SOCKET){
			continue;
		}
		log(PLUGIN_NAME": Handling a client socket.\n");
		current_client = client;
		Initialize_Server_Interfaces();
		handle_client_comms(client, handler);
		Release_Server_Interfaces();
		current_client = INVALID_SOCKET;
	}
	Release_Server_Interfaces();
	dbg_server_conn = INVALID_SOCKET;
	log(PLUGIN_NAME": Server just exitted.\n");
	return 0;
}



//mjw: main function to handle inbound commands
void handle_client_comms(SOCKET client, HANDLER handler){
	static Buffer b(4096*1024);
	char buf[2048];	
	if (handler == NULL){
		shutdown_current_client();
		return;
	}
	while(RUN_SERVER){
		int len = recv(client, buf, sizeof(buf), 0);
		if (len <= 0){
			shutdown_current_client();
			break;
		}
		b.write(buf, len);
		while(isComplete(b)){
			log(PLUGIN_NAME": Rcv'd a valid buffer handling the client message.\n" );
			Buffer data(b.get_buf() + sizeof(int), requiredSize(b) - sizeof(int));
			bool result = handler(data);
			log(PLUGIN_NAME": Done handling the request.\n" );
			shift(b);
		}

	}


}


void shutdown_server(){
	if(dbg_server_conn != INVALID_SOCKET)
		closesocket(dbg_server_conn);
	dbg_server_conn = INVALID_SOCKET;
}
void shutdown_current_client(){
	if (current_client != INVALID_SOCKET)
		closesocket(current_client);
	current_client = INVALID_SOCKET;
}

int stop_server(){
	RUN_SERVER = false;
	log(PLUGIN_NAME": shutting down the listener.\n");
	log(PLUGIN_NAME": shutting down the server.\n");
	shutdown_server();
	log(PLUGIN_NAME": closing down client connections.\n");
	shutdown_current_client();
	log(PLUGIN_NAME": shutdown complete.\n");
	return WSACleanup();
}


bool start_server(std::string& host, std::string& port){
	RUN_SERVER = true;
	
	if(is_listening())
		return true;
	LPVOID *args = new LPVOID[3];
	std::vector<std::string >*server_args = new std::vector<std::string >;
	
	server_args->push_back(host); 
	server_args->push_back(port);
	args[0] = (LPVOID) server_args;
	args[1] = (LPVOID) (&msg_dispatcher);
	args[2] = (LPVOID) (g_ExtClient);
	//log(PLUGIN_NAME": Address of server_args: 0x%08x and args[0]: 0x%08x.\n", (VOID)server_args, (VOID)args[0]);
	DWORD dwThreadId;
	if(!init_network()){
		log(PLUGIN_NAME": failed to initialize the network.\n");
		return false;
	}
	log(PLUGIN_NAME": network initialized.\n");
	SERVER_THREAD = CreateThread(NULL, 0,run_server, (LPVOID) args, 0, &dwThreadId);
	return SERVER_THREAD != 0;
}




bool msg_dispatcher(Buffer &b) {
	// clone the recv buffer
	
	unsigned int sz = b.size();
	char *data = new char [sz];
	if(data == NULL)
	{
		fprintf(stderr, "ERROR: null pointer\n");
		return false;
	}

	b.read(data,sz);
	Buffer myBuffer(data, sz); // want to skip the buffer size
	delete data;
	log(PLUGIN_NAME": Rcvd a client request.\n");
	return recv_net_command(myBuffer);
}


bool check_gsClient_interfaces(){
	bool valid = gs_ExtClient != NULL;
	valid &= gs_ExtSymbols != NULL;
	valid &= gs_ExtSystemObjects != NULL;
	valid &= gs_ExtRegisters != NULL;
	return valid && (gs_ExtControl != NULL);

}

/* 
   these functions are all called from the 
   prospective of the listener, if they are 
   not stuff will break!
*/
void clear_breakpoints(){
	ULONG bp_count;
	PDEBUG_BREAKPOINT	bp;
	//gs_ExtControl->GetNumberBreakpoints(&bp_count)
	while(gs_ExtControl->GetNumberBreakpoints(&bp_count) ==S_OK &&
		bp_count > 0){
		if(gs_ExtControl->GetBreakpointByIndex(0, &bp)==S_OK){
			gs_ExtControl->RemoveBreakpoint(bp);
		}
	}
}



void get_all_bps(std::vector<ULONG64> &bps){
	PDEBUG_BREAKPOINT	bp;
	ULONG bp_count;
	gs_ExtControl->GetNumberBreakpoints(&bp_count);
	for (ULONG cnt=0; cnt<bp_count;cnt++){
		if(gs_ExtControl->GetBreakpointByIndex(cnt, &bp)==S_OK){
			ULONG64 addr;
			bp->GetOffset(&addr);
			bps.push_back(addr);
		}
	}
}

bool add_breakpoint(ULONG64 ea){
	PDEBUG_BREAKPOINT	bp;
	HRESULT hr;
	if(gs_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp) == S_OK ){
		bp->SetOffset(ea);
		bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);
		return true;
	}
	return false;
}


void add_breakpoints(std::vector<std::string > *bps){
	std::map<ULONG64,ULONG> bp_map;
	ULONG bp_count;
	PDEBUG_BREAKPOINT	bp;

	gs_ExtControl->GetNumberBreakpoints(&bp_count);
	for (ULONG cnt=0; cnt<bp_count;cnt++){
		if(gs_ExtControl->GetBreakpointByIndex(cnt, &bp)==S_OK){
			ULONG64 addr;
			bp->GetOffset(&addr);
			bp_map[addr] = cnt;
		}
	}
	std::vector<std::string>::iterator iter = bps->begin();
	for(;iter != bps->end(); iter++){
		bp = NULL;
		ULONG64 addr = convert_string_to_addr(*iter);
		if(bp_map.find(addr) != bp_map.end()){
			if(gs_ExtControl->GetBreakpointByIndex(bp_map[addr], &bp)==S_OK){
				bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);
			}
			continue;
		}
		if(!add_breakpoint(addr))
			log(PLUGIN_NAME": Failed to set and enable breakpoint: 0x%08x\n",addr);
	}
}


void get_breakpoints(std::string &bp_str){
	std::vector<ULONG64> bps;
	get_all_bps(bps);
	convert_bps_to_string(bps, bp_str);
}


bool handle_break_cmd(ULONG tid){
	if(tid == -1 && check_gsClient_interfaces()){
		// suspend all and process
		suspend_all_threads();
		
		if(!check_gsClient_interfaces()){// || ctrl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK){
			dprintf(PLUGIN_NAME":Failed to resume process execution\n");
			//EXT_RELEASE(ctrl);
			return false;
		}
		return suspend_execution(gs_ExtControl);
	}
	else if (check_gsClient_interfaces()){
		/*if(!is_tid_valid(tid)){
			dprintf(PLUGIN_NAME":Failed to find the thread id in this process\n");
			return true;
		}*/
		return suspend_thread(tid);
	}
	dprintf(PLUGIN_NAME":Failed b/c global server interfaces invalid!\n");
	return false;	
}
bool suspend_all_threads(){
	ULONG t_cnt;
	if (gs_ExtSystemObjects->GetNumberThreads(&t_cnt) != S_OK){
		dprintf(PLUGIN_NAME":Failed to get the number of threads\n");
		return true;
	}
	ULONG *ids = new ULONG[t_cnt];
	if (gs_ExtSystemObjects->GetThreadIdsByIndex(0,t_cnt,NULL,ids) != S_OK){
		delete ids;
		dprintf(PLUGIN_NAME":Failed to get the thread ids of this process\n");
		return true;
	}
	for(ULONG i = 0; i<t_cnt;i++)
		suspend_thread(ids[i]);
	delete ids;
	return true;
}


bool suspend_thread(ULONG tid){
	HANDLE tHandle = OpenThread( THREAD_ALL_ACCESS, false, tid);
	if(tHandle == INVALID_HANDLE_VALUE){
		dprintf(PLUGIN_NAME":Failed to OpenThread for suspension.\n");
		return true;
	}
	if (SuspendThread(tHandle) != -1){
		// success
		dprintf(PLUGIN_NAME":Successfully suspended TID: %d.\n");
	}else{
		dprintf(PLUGIN_NAME":Failed to suspended TID: %d.\n");
	}
	CloseHandle(tHandle);
	return true;
}


DWORD WINAPI trigger_run(LPVOID args){
	PDEBUG_CONTROL ctrl = (PDEBUG_CONTROL)args;
	dprintf(PLUGIN_NAME": Attempting to resume the execution of the threads");
	ctrl->Execute(DEBUG_OUTCTL_ALL_OTHER_CLIENTS, "g", DEBUG_EXECUTE_ECHO);
	EXT_RELEASE(ctrl);
	return 0;
}
bool resume_execution(PDEBUG_CONTROL ctrl){
	dprintf(PLUGIN_NAME": proximity mine set, gtfo, go, go, goooooo!\n");
	HRESULT s= ctrl->Execute(DEBUG_OUTCTL_ALL_OTHER_CLIENTS, "g", DEBUG_EXECUTE_ECHO);
	return s == S_OK;
}

bool suspend_execution(PDEBUG_CONTROL ctrl){
	HRESULT s= ctrl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
	return s == S_OK;
}

bool is_tid_valid(ULONG tid){
	ULONG tid_idx=0;
	ULONG t_cnt;
	if (gs_ExtSystemObjects->GetNumberThreads(&t_cnt) != S_OK){
		dprintf(PLUGIN_NAME":Failed to get the number of threads\n");
		return false;
	}
	ULONG *ids = new ULONG[t_cnt];
	for(; tid_idx< t_cnt, ids[tid_idx]!=tid; tid_idx++){}
	delete ids;
	return tid_idx != t_cnt;
}

bool handle_resume_cmd(ULONG tid){
	bool break_process = false;
	if(tid == -1 && check_gsClient_interfaces()){
		// resume all and process
		resume_all_threads();
		// check the g_ExtControl is not NULL first and attempt to get a valid control
		// then execute the SetExecutionStatus
		//PDEBUG_CONTROL ctrl = get_ExtControl();
		
		if(!check_gsClient_interfaces()){// || ctrl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK){
			dprintf(PLUGIN_NAME":Failed to resume process execution\n");
			//EXT_RELEASE(ctrl);
			return false;
		}
		return resume_execution(gs_ExtControl);
	}
	else if (check_gsClient_interfaces()){
		if(!is_tid_valid(tid)){
			dprintf(PLUGIN_NAME":Failed to find the thread id in this process\n");
			return true;
		}
		return resume_thread(tid);
	}
	dprintf(PLUGIN_NAME":Failed b/c global server interfaces invalid!\n");
	return false;

		
}

bool resume_all_threads(){
	ULONG t_cnt;
	if (gs_ExtSystemObjects->GetNumberThreads(&t_cnt) != S_OK){
		dprintf(PLUGIN_NAME":Failed to get the number of threads\n");
		return true;
	}
	ULONG *ids = new ULONG[t_cnt];
	if (gs_ExtSystemObjects->GetThreadIdsByIndex(0,t_cnt,NULL,ids) != S_OK){
		delete ids;
		dprintf(PLUGIN_NAME":Failed to get the thread ids of this process\n");
		return true;
	}
	for(ULONG i = 0; i<t_cnt;i++)
		resume_thread(ids[i]);
	delete ids;
	return true;
}


bool resume_thread(ULONG tid){
	HANDLE tHandle = OpenThread( THREAD_ALL_ACCESS, false, tid);
	if(tHandle == INVALID_HANDLE_VALUE){
		dprintf(PLUGIN_NAME":Failed to OpenThread for resume.\n");
		return true;
	}
	if (ResumeThread(tHandle) != -1){	
		// success
		dprintf(PLUGIN_NAME":Successfully Resumed TID: %d.\n",tid);
	}else{
		dprintf(PLUGIN_NAME":Failed to resume TID: %d.\n",tid);
	}
	CloseHandle(tHandle);
	return true;
}


bool add_alias_cli(std::string args){
	log("Attempting to add the following aliases into the command line: %s\n",args.c_str());
	add_alias_list(args);
	return true;
}


bool set_regs_cli(std::string args){
	unsigned char cmd_type = CMD_REQ;
	std::string cmd = "setregs";
	return send_cmd_string(cmd,get_registers_string(),cmd_type);
}

bool set_regs_req(Buffer &buf){
	std::string reg_vals_str = "";
	if(buf.readString(reg_vals_str)){
		std::map<std::string, std::string> *regs_vals = parse_registers(reg_vals_str);
		if (regs_vals == NULL){
			log("There was an error, and the registers and values were not parsed!");
			return true;
		}
		set_registers(*regs_vals);
		regs_vals->clear();
		delete regs_vals;
		return true;
	}
	return false;
}

bool get_regs_req(Buffer &buf){
	std::string cmd = "setregs";
	buf.reset();
	return send_cmd_string(cmd,get_registers_string(),CMD_REQ);
}

bool get_regs_cli(std::string args){
	unsigned char cmd_type = CMD_REQ;
	std::string cmd = "getregs";
	std::string out = "";
	return send_cmd_string(cmd,out,cmd_type);
}
bool get_regs_rsp(Buffer &buf){
	return set_regs_req(buf);
}

bool rebase_req(Buffer &b){
	ULONG64 addr = get_debuggee_baseoffset();
	std::stringstream builder;
	std::string cmd = "rebase";
	builder << "0x" << std::hex << addr;
	return send_cmd_string(cmd,builder.str(),CMD_RES);
}

bool rebase_cli(std::string& args){
	ULONG64 addr = get_debuggee_baseoffset();
	std::stringstream builder;
	std::string cmd = "rebase";
	builder << "0x" << std::hex << addr;
	return send_cmd_string(cmd,builder.str(),CMD_REQ);
}


bool set_bps_req(Buffer &b){
	std::vector<std::string > *bps = read_bps_from_buffer(b);
	if (bps && bps->size()){
		// TODO: add breakpoint based off offset names,
		// like dll export +- offset to addres
		add_breakpoints(bps);
	}else{
		clear_breakpoints();
	}
	if(bps){
		bps->clear();
		delete bps;
	}
	return true;
}

bool set_bps_cli(std::string args){
	std::string cmd = "setbps";
	std::string bps;
	get_breakpoints(bps);
	return send_cmd_string(cmd,bps,CMD_RES);
}



bool get_bps_rsp(Buffer &buf){
	return set_bps_req(buf);
}

bool get_bps_req(Buffer &b){
	std::string bps;
	get_breakpoints(bps);
	send_cmd_string("setbps", bps, CMD_REQ);
	return true;
}

bool break_req(Buffer &b){
	std::string tid = "";
	std::string cmd = "break";
	std::string results = "";
	if (b.readString(tid)){
		ULONG v = _strtoi64(tid.c_str(),NULL,16);
		if(handle_break_cmd(v)){
			convert_addr_to_string(get_current_pc(), results);
			return send_cmd_string(cmd,results,CMD_RES);
		}
	}
	results = "-1";
	return send_cmd_string(cmd,results,CMD_RES);;
}

bool resume_req(Buffer &b){
	std::string tid = "";
	if (b.readString(tid)){
		ULONG v = convert_string_to_numval(tid);
		handle_resume_cmd(v);
	}
	return true;
}

/*
bool python_cli(std::string& args){
	std::string cmd = "python";
	
	std::string ip_cmd = args.substr(0,args.find_first_of(" "));
	ip_cmd = get_command_alias(ip_cmd);
	if (ip_cmd == ""){
		return false;
	}

	std::string ip_args = "";
	if (ip_cmd.size() != args.size())
		args.substr(args.find_first_not_of(ip_cmd+" "),args.size()-ip_cmd.size());
	Buffer b(cmd.size()+ip_cmd.size()+ip_args.size()+100);
	b.writeInt(CMD_REQ);
	b.writeString(cmd);
	b.writeString(ip_cmd);
	b.writeString(ip_args);
	send_data(b);
	return true;
}

bool python_rsp(Buffer &buf){
	std::string results;
	if (buf.readString(results)){
		log("IDAPython Command Results: %s",results.c_str());
		return true;
	}
	return false;
}
*/

bool get_bps_cli(std::string &args){
	std::string cmd = "getbps";
	return send_cmd_string(cmd);
}

bool status_cli(std::string &args){
	std::string cmd = "getstatus";
	return send_cmd_string(cmd);
}
bool get_regs_cli(std::string &args){
	std::string cmd = "getregs";
	return send_cmd_string(cmd);
}
bool set_bps_cli(std::string &args){
	std::string cmd = "setbps", bps="";
	get_breakpoints(bps);
	return send_cmd_string(cmd,bps);
}
bool set_regs_cli(std::string &args){
	std::string cmd = "setregs", regs="";
	get_registers(regs);
	return send_cmd_string(cmd,regs);
}
bool add_alias_cli(std::string &args){
	if (args.size() == 0){
		log("Failed to add the command.\n");
		return false;
	}
	add_alias_list(args);
	return true;
}

bool start_cli(std::string &args){
	std::vector<std::string > *arg_toks = tokenize(args);
	std::string host = "127.0.0.1";
	std::string port = "8088";
	bool result = false;
	
	if (arg_toks->size() >= 1){
		host = (*arg_toks)[0];
	}
	if(arg_toks->size() >= 2){
		port = (*arg_toks)[1];
	}
	if (host.size() > 0 && port.size() > 0){
		log("Attempting to launch start the server: %s %d\n", host.c_str(), port.c_str());
		result = start_server(host, port);
	}


	arg_toks->clear();
	delete arg_toks;
	return result;
}

bool stop_cli(std::string &args){
	return stop_server() == 0;
}

bool add_pycmd_cli(std::string &args){
	std::string cmd = "pyadd",
				new_cmd = "",
				code = "";
				
	if (args.size() == 0){
		log("Failed to add the command.\n");
		return false;
	}
	new_cmd = args.substr(0, args.find_first_of(" "));
	if (new_cmd == args){
		log("Failed to add the command.\n");
		return false;
	}
	code = args.substr(new_cmd.size()+1, args.size() - new_cmd.size()+1);
	Buffer obuf;
	obuf.writeInt(CMD_REQ);
	obuf.writeString(cmd);
	obuf.writeString(new_cmd);
	obuf.writeString(code);
	send_data(obuf);
	return false;
}


bool add_pycmd_rsp(Buffer &buf){
	std::string cmd = "",
				results = "",
				aliasto = "pycmd";

	if(!buf.readString(cmd)){
		// failed to read the command name
		log("Invalid msg recieved\n");
		return true;
	}else if (buf.readString(results) && results == "0"){
		// failed to read the python code
		log("%s: successfully added\n", cmd.c_str());
		
		add_pycmd_alias(aliasto, cmd);
		return true;
	}
	log("Failed: %s not added\n",cmd.c_str());
	return true;
}

bool list_cli(std::string &args){
	
	log("Should list the available commands here, but that might be a long listing with all the idapython commands\n");
	
	return true;
}

bool isHex(char c){

	return (c >= '0' && c <= '9') ||  (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

}

bool isPrintable(char c){

	return (c >= ' ' && c <= '?') ||  (c >= 'A' && c <= '~');

}

std::string convert_string_to_raw(std::string input){
	// convert strings from cli to raw format
	// \\x90 will be treated as \x90 and
	// \x90 will be converted to 0x90
	ULONG64 pos_byte;
	std::stringstream builder;
	const char *cbuf = input.c_str();
	for(pos_byte = 0; pos_byte < input.size(); pos_byte++){
		// if pos_byte = 
		char b1 = cbuf[pos_byte];
			 
		if (b1 == '\\' && pos_byte+1 < input.size()){
			char b2 = cbuf[pos_byte+1];
			
			if (b2 == 'x' && 
				pos_byte+3 < input.size() &&
				isHex(*(cbuf+pos_byte+2)) &&
				isHex(*(cbuf+pos_byte+3))) {
				std::string s = input.substr(pos_byte+1, pos_byte+3);
				s = "0"+s;
				char val = (char)convert_string_to_addr(s);
				// increment one less, b/c the for loop will incr
				pos_byte += 3;
				builder << val;
				continue;
			}else if (b2 == '\\' && 
					  pos_byte+2 < input.size() &&
					  cbuf[pos_byte+1] == '\\' &&
					  cbuf[pos_byte+2] == 'x'){
				builder << b1;
				builder << cbuf[pos_byte+2];
				pos_byte += 2;
				continue;
			}
		}
		builder << b1;
	}
	std::string data = builder.str();
	return data;
}

bool write_memory_cli(std::string &args){
	log("writememory commands should be ran from ida\n");
	log("read commands should be ran from ida\n");
	std::vector<std::string >* tokens = tokenize(args);
	// atm only support address/name and data
	bool result = false;
	std::string data = "", 
				addr_s = "",
				cmd="readmem";
	if (tokens == NULL){
		return false;
	}else if(tokens->size() < 2){
		delete tokens;
		return result;
	}
	addr_s = (*tokens)[0];
	// convert data into a raw char string
	delete tokens;
	ULONG64 addr;
	// TODO: addr address resolution for windbg
	//addr = convert_string_to_addr(addr_s);
	/*if (addr == -1){
		// we will fail here
		return result;
	}*/
	result = true;
	data = args.substr(args.find_first_not_of(addr_s)+1, args.size()-(addr_s.size()+1));
	// todo loook at data here
	data = convert_string_to_raw(data);
	send_two_arg_buffer(addr_s, data, cmd,CMD_REQ);
	return result;

}

bool write_memory_req(Buffer &buf){
	// write memory 
	// arg0 takes an address or eventually a symbol+offset
	// arg1 data
	unsigned char cmd_type = CMD_REQ;
	std::string cmd = "writemem";
	std::string cmd_str = "";
	std::string out = "";
	std::string addr="", data="";
	
	if (!buf.readString(addr)){
		
		// TODO: send an error buffer and return


	}else if (!buf.readString(data)){
		// TODO: send an error buffer and return

	}
	ULONG64 addr_val = convert_string_to_addr(addr);
	// TODO: return value?
	return set_vmemory_off_values(addr_val, (PVOID) data.c_str(),data.size(), NULL);
}

bool write_memory_rsp(Buffer & buf){
	unsigned char cmd_type = CMD_RES;
	std::string cmd = "writemem";
	std::string cmd_str = "";
	std::string out = "";

	buf.readString(cmd_str);
	log("write_memory_res = %s\n", cmd_str.c_str());
	return true;
}

bool read_memory_cli(std::string &args){
	log("read commands should be ran from ida\n");
	std::vector<std::string >* tokens = tokenize(args);
	// atm only support address/name and data
	bool result = false;
	std::string cnt_s = "", 
				addr_s = "",
				cmd="readmem";
	if (tokens == NULL){
		return false;
	}else if(tokens->size() < 1){
		delete tokens;
		return result;
	}
	addr_s = (*tokens)[0];
	cnt_s = "1";
	if (tokens->size() > 1){
		cnt_s = (*tokens)[1];
	}
	delete tokens;
	ULONG64 addr, cnt;
	// TODO: named address resolution for windbg
	cnt = convert_string_to_addr(cnt_s);
	if (cnt == -1){
		// TODO: we will fail here
		return result;
	}
	result = true;
	send_two_arg_buffer(addr_s, cnt_s, cmd,CMD_REQ);
	return result;
}

bool send_two_arg_buffer(std::string arg0, std::string arg1, std::string cmd, unsigned char cmd_type){
		Buffer buf(arg0.size()+arg1.size()+100);
		buf.writeInt(cmd_type);
		buf.writeString(cmd);
		buf.writeString(arg0);
		buf.writeString(arg1);
		return send_data(buf);
}


bool read_memory_req(Buffer &buf){
	unsigned char cmd_type = CMD_REQ;
	std::string cmd = "readmem";
	std::string addr_s = "", 
				cnt_s = "",
				data = "";
	bool result = false;
	
	if (!buf.readString(addr_s) || addr_s.size() == 0){
		// error return msg?
		addr_s = "0xFFFFFFFF";
		send_two_arg_buffer(addr_s,data,cmd,CMD_RES);
		return result;
	}else if(!buf.readString(cnt_s)){
		// TODO: error return msg?
		cnt_s = "1";
	}
	
	
	ULONG64 readSz = convert_string_to_addr(cnt_s),
			addr = convert_string_to_addr(addr_s);

	if (addr == -1){
		addr_s = "0xFFFFFFFF";
		send_two_arg_buffer(addr_s,data,cmd,CMD_RES);
		return result;
	}else if(readSz == -1){
		readSz = 1;
	}
	char *readBuf = new char[readSz];
	if (readBuf == NULL){
		// return error msg?
		addr_s = "0xFFFFFFFF";
		send_two_arg_buffer(addr_s,data,cmd,CMD_RES);
		return result;
	}
	if (get_vmemory_off_values(addr,(PVOID) readBuf, readSz,NULL)){
		data = std::string(readBuf, readSz);
		result = true;
	}
	delete readBuf;
	send_two_arg_buffer(addr_s,data,cmd,CMD_RES);
	return result;
}

void convert_data_string_hex(std::string data, std::string &out){

	const char *cBuf = data.c_str();
	std::string tmp = "";
	for (unsigned int pos = 0; pos < data.size(); pos++){


	}


}

bool read_memory_rsp(Buffer & buf){
	unsigned char cmd_type = CMD_RES;
	std::string cmd = "readmem";
	std::string cmd_str = "";
	std::string out = "";
	std::string addr_s = "",
				data_s = "";
	if (!buf.readString(addr_s)){
		// TODO error msg
	}else if (!buf.readString(data_s)){
		// TODO error msg
	}
	// TODO finish me!!!!!
	std::stringstream builder;
	const char *cBuf = data_s.c_str();
	for(unsigned int pos = 0; pos < data_s.size(); pos++){
		if (isPrintable(cBuf[pos])){
			builder << cBuf[pos];
			continue;
		}
		builder << "\\x" << std::hex << std::setfill('0') << std::setw(2) << ((unsigned int)cBuf[pos] & 0xff);
	}
	out = builder.str();
	log("read_memory_rsp = %s: %s\n", addr_s.c_str(), out.c_str());
	return true;
}


bool python_command_cli(std::string &args){
	std::string pycmd = "pycmd",
				results = "",
				pargs = "",
				cmd = "",
				python = "python";
	
	if (args == ""){
		log("No command or arguments given,\n");
		return false;
	}



	cmd = args.substr(0, args.find_first_of(" "));
	
	/*if(!is_pycmd(cmd)){
		log("No python command is defined locally by this name.\n");
		return false;
	}*/
	
	if (cmd.size() != args.size())
		pargs = args.substr(cmd.size()+1,args.size()-cmd.size());
	
	Buffer obuf(cmd.size() + pargs.size() + 100);
	obuf.writeInt(CMD_REQ);
	obuf.writeString(pycmd);
	obuf.writeString(cmd);
	obuf.writeString(pargs);
	send_data(obuf);	
	return true;
}

bool python_command_rsp(Buffer &b){
	std::string results = "Error: invalid command",
				cmd = "";
	
	
	if( !b.readString(cmd) ){
		log("Received an command that could not be read");
		return true;
	}
	if(!b.readString(results)){
		log("Received invalid results for %s",cmd.c_str());
		return true;
	}
	log("%s results: %s",cmd.c_str(),results.c_str());
	return true;
}

bool pyeval_cli(std::string &args){
	std::string cmd = "pyeval",
				code = "";
	
	code = args;
	if (trimmed(code, " ") == ""){
		log("Unable to send and empty code string.\n");
		return false;
	}
	Buffer obuf(cmd.size() + code.size() + 100);
	obuf.writeInt(CMD_REQ);
	obuf.writeString(cmd);
	obuf.writeString(code);
	send_data(obuf);	
	return true;
}

bool pyeval_rsp(Buffer &b){
	std::string results = "";
	
	
	if( !b.readString(results) ){
		log("pyeval: No Results");
		return true;
	}
	log("pyeval: %s\n",results.c_str());
	return true;
}

bool python_cli(std::string &args){
	std::string cmd = "python",
				code = args;
	if (args.size() == 0){
		log("Failed to add the command.\n");
		return false;
	}
	
	Buffer obuf(cmd.size() + code.size() + 100);
	obuf.writeInt(CMD_REQ);
	obuf.writeString(cmd);
	obuf.writeString(code);
	send_data(obuf);	
	return true;
}

bool python_rsp(Buffer &b){
	std::string results = "";
	
	
	if( !b.readString(results) ){
		log("python: No Results");
		return true;
	}
	log("python: %s\n",results.c_str());
	return true;
}

// commands
// get will have three entries, and set will have two
// setregs, set_regs_cli, set_regs_req, -
// getregs, get_regs_cli, get_regs_req, get_regs_rsp->set_regs_req
// getbps, get_bps_cli, get_bps_req, get_bps_rsp
// setbps, set_bps_cli, set_bps_req <-- 
// addalias, add_alias_cli, -, -
// rebase, rebase_cli, rebase_req, -
// resume, -, resume_req, -
// break, -, break_req, -

void init_command_handlers(){
	init_idapython_aliases();
	// idapython cmd and cli handler registration
	//register_cmd_handler("idapython", default_net_handler, idapython_rsp, idapython_cli );

	// addalias cmd and cli handler registration
	register_cmd_handler("addalias", default_net_handler, default_net_handler, add_alias_cli );

	// rebase cmd and cli handler registration
	register_cmd_handler("rebase", rebase_req, default_net_handler, rebase_cli );

	// resume cmd and cli handler registration
	register_cmd_handler("resume", resume_req, default_net_handler, default_cli_handler );

	// setregs cmd and cli handler registration
	register_cmd_handler("setregs", set_regs_req, default_net_handler, set_regs_cli );

	// break cmd and cli handler registration
	register_cmd_handler("break", break_req, default_net_handler, default_cli_handler );

	// setbps cmd and cli handler registration
	register_cmd_handler("setbps", set_bps_req, default_net_handler, set_bps_cli );

	// getregs cmd and cli handler registration
	register_cmd_handler("getregs", get_regs_req, get_regs_rsp, get_regs_cli );

	// getbps cmd and cli handler registration
	register_cmd_handler("getbps", get_bps_req, get_bps_rsp, get_bps_cli );

	// start cmd and cli handler registration
	register_cmd_handler("start", default_net_handler, default_net_handler, start_cli);

	// start cmd and cli handler registration
	register_cmd_handler("stop", default_net_handler, default_net_handler, stop_cli);

	//mjw status
	register_cmd_handler("status", status_handler, status_handler, status_cli);

	//writemem/readmem
	register_cmd_handler("writemem", write_memory_req, write_memory_rsp, write_memory_cli);
	register_cmd_handler("readmem", read_memory_req, read_memory_rsp, read_memory_cli);
	
	// python command cmd and cli handler registration
	register_cmd_handler("pyadd", default_net_handler, add_pycmd_rsp, add_pycmd_cli);
	add_ml_command("pyadd");

	// python command cmd and cli handler registration
	register_cmd_handler("list", default_net_handler, default_net_handler, list_cli);

	// python command cmd and cli handler registration
	register_cmd_handler("pycmd", default_net_handler, python_command_rsp, python_command_cli);
	//add_ml_command("pycmd");
	std::string pycmd = "pycmd";
	add_pycmd_alias(pycmd, pycmd);
	// python command cmd and cli handler registration
	register_cmd_handler("python", default_net_handler, python_rsp, python_cli);
	add_ml_command("python");

	// python command cmd and cli handler registration
	register_cmd_handler("pyeval", default_net_handler, pyeval_rsp, pyeval_cli);
	//add_ml_command("pyeval");
}



std::string get_registers_string(){
	std::stringstream builder;
	std::map<std::string, ULONG64> reg_collection;
	get_registers_and_values(reg_collection);
	std::map<std::string, ULONG64>::iterator iter = reg_collection.begin();
	//  build the python dictionary
	//builder << "regs={";
	for(;iter != reg_collection.end(); iter++){
		//builder << "\"" << iter->first << "\":" << std::hex << iter->second << ",";
		builder <<  iter->first << ":0x" << std::hex << iter->second << ",";
	}
	std::string out = builder.str();
	return out;
}

// __int64 for MSVC, "long long" for gcc
inline void endian_swap(unsigned __int64& x)
{
    x = (x>>56) | 
        ((x<<40) & 0x00FF000000000000) |
        ((x<<24) & 0x0000FF0000000000) |
        ((x<<8)  & 0x000000FF00000000) |
        ((x>>8)  & 0x00000000FF000000) |
        ((x>>24) & 0x0000000000FF0000) |
        ((x>>40) & 0x000000000000FF00) |
        (x<<56);
}

inline void endian_swap(unsigned int& x)
{
    x = (x>>24) | 
        ((x<<8) & 0x00FF0000) |
        ((x>>8) & 0x0000FF00) |
        (x<<24);
}