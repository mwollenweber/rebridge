#include "idanet.hpp"
#include "dlistener_ida.h"
#include "dlistener_net.h"
#include "cmd_translation.h"
#include <iostream>
#include <ida.hpp>
#include <auto.hpp>
#include <idp.hpp>
#include <diskio.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <area.hpp>
#include <frame.hpp>
#include <segment.hpp>
#include <enum.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <vector>
//#include "dlistener_ui.h"
#include <cstdio>

#define LAST_SERVER_SUPVAL 2
#define LAST_PORT_ALTVAL 2
#define DLISTENER_NETNODE "$ DLISTENER NETNODE"
volatile HWND mainWindow;
volatile HMODULE hModule;



// taken from collabreate
IDAPYTHON_FN  IDAPython_run_string = NULL;
IDAPYTHON_FN IDAPython_eval_string= NULL;
IDAPYTHON_FREE	 IDAPython_destroy_object = NULL;

#define log msg
#define PLUGIN_NAME "idabridge"
netnode cnn(DLISTENER_NETNODE, 0, true);
static Dispatcher tempDispatcher;



std::map<std::string, long long> name_to_current_long_vals;

std::string IDABRIDGE_IMPORT  = "from idabridge import *\nfrom idabridge.buffer import *\n";




cli_t cli_dlistener =
{
    sizeof(cli_t),
    0,
    "idabridge",
    "idabridge plugin",
    "Enter any expression",
    dlistener_command_handler,
    NULL,
    NULL
};

HMODULE IDAPythonHModule = NULL;

void init_registers(void){
	if (is_connected()){
		//send_get_regs();
	}else{
		// print helper
		// which register set 
		// do they want to initialize
	}
}

void enable_dlistener_cli(bool enable)
{
    if (enable)
        install_command_interpreter(&cli_dlistener);
    else
        remove_command_interpreter(&cli_dlistener );
}





bool idaapi add_command(std::string python_code, std::string &results){
	unsigned long buf_size=-1;//=8096	;
	char *result_buf=NULL;// (char*)malloc(buf_size);
	python_code += "\n";
	bool result = IDAPython_run_string(python_code.c_str(),&result_buf,&buf_size);
	handle_result_buf(result_buf, buf_size, results);
	return result;
}

bool idaapi execute_python_run_string(std::string python_code, std::string &results){
	unsigned long buf_size=-1	;
	char *result_buf=NULL;// (char*)malloc(buf_size);
	python_code += "\n";
	bool result = IDAPython_run_string(python_code.c_str(),&result_buf,&buf_size);
	handle_result_buf(result_buf, buf_size, results);
	return result;
}

bool idaapi execute_python_eval_command(std::string cmd_function,std::string args,  std::string &results){

	std::string python_code = cmd_function + "( " + args +" )\n";
	return execute_python_eval_command(python_code, results);

}

bool idaapi execute_python_eval_command(char* python_code, std::string &results){

	std::string code = python_code;
	return execute_python_eval_command(code, results);
}

bool idaapi execute_python_eval_command(std::string python_code, std::string &results){
	unsigned long buf_size=-1;//=8096	;
	char *result_buf=NULL;// (char*)malloc(buf_size);
	bool result = false;
	std::string line_del = "\n";
	python_code += line_del;
	std::vector<std::string > * pcmd_inputs = tokenize(python_code, line_del);

	
	if(pcmd_inputs == NULL){
			results = "Unknown Error Occurred when adding the command!\n";
			return false;
	}
	// remove all the empties
	std::vector<std::string > cmd_inputs;
	std::vector<std::string >::iterator cmd_iter = pcmd_inputs->begin();
	for (;cmd_iter != pcmd_inputs->end(); cmd_iter++){
		if(*cmd_iter != ""){
			cmd_inputs.push_back(*cmd_iter);
		}
	}
	pcmd_inputs->clear();
	delete pcmd_inputs;
	// done with empties here

	// rejoin the strings up to size-1 file_input the code, and eval the last line
	if (cmd_inputs.size() > 2){
		std::string python_code = join(&cmd_inputs,0,cmd_inputs.size()-2);
		if(IDAPython_run_string(python_code.c_str(),&result_buf,&buf_size)){
			python_code = cmd_inputs[cmd_inputs.size()-1];
			IDAPython_destroy_object((void *)result_buf);
			buf_size = -1;
			result = IDAPython_eval_string(python_code.c_str(),&result_buf,&buf_size);
		}
	// file_input the first line code, and eval the 2nd line
	}else if (cmd_inputs.size() == 2){		
		// execute first line as file input
		// and second as eval
		std::string python_code = cmd_inputs[0];
		if (IDAPython_run_string(python_code.c_str(),&result_buf,&buf_size)){
			python_code = cmd_inputs[cmd_inputs.size()-1];
			IDAPython_destroy_object((void *)result_buf);
			buf_size = -1;
			std::string fname = "<string>";
			result = IDAPython_eval_string(python_code.c_str(),&result_buf,&buf_size);
		}
	// Eval the last line, we want this case in an else
	// because if there is an error, from before, we want to
	// report it
	}else{
		std::string python_code = cmd_inputs[0];
		buf_size = -1;
		std::string fname = "<string>";
		result = IDAPython_eval_string(python_code.c_str(),&result_buf,&buf_size);
	}
	
	handle_result_buf(result_buf, buf_size, results);	
	return result;
}

void handle_result_buf(char* result_buf, unsigned long buf_size, std::string &results){
	bool result = false;
	if (result_buf != NULL){
		results = std::string(result_buf, buf_size);
		IDAPython_destroy_object((void *)result_buf);
	}else{
		results = "Unknown Error Occurred when adding the command!\n";
	}
}

bool idaapi load_remote_file(std::string &filename, std::string &base64data, std::string &results){
	std::stringstream build_ip_cmd;
	char *result_buf = NULL;
	unsigned long buf_size = -1;
	build_ip_cmd << "from base64 import decodestring\n";
	build_ip_cmd << "remote_filename = '''" << filename << "'''\n";
	build_ip_cmd << "remote_b64filedata = '''" << base64data << "'''\n";
	build_ip_cmd << "remote_binfiledata = decodestring(remote_b64filedata)\n";
	build_ip_cmd << "remote_outfile = open(remote_filename,'wb')\n";
	build_ip_cmd << "remote_outfile.write(remote_binfiledata)\n";
	std::string python_code = build_ip_cmd.str();
	bool result = IDAPython_run_string(python_code.c_str(),&result_buf, &buf_size);
	handle_result_buf(result_buf, buf_size, results);
	return result;
}


bool idaapi dlistener_command_handler(const char *line)
{
	bool ret;
	log("in dlistener_command_handler\n");
	static bool handling_ml_cmd = false;
	static std::string cached_cmd_args = "",
					   cached_cmd = "";
	std::string cmd = "",
				cmd_args = "",
				tinput = line,
				cli_input = line;
	std::string results;
	// clear out the cli
	char * tline = (char *)line;
	tline[0] = '\0';
	
	// added to handle multi-line commands
	if (handling_ml_cmd && cli_input == ""){
		cmd = cached_cmd;
		cached_cmd = "";
		cmd_args = cached_cmd_args ;
		cached_cmd_args = "";
		handling_ml_cmd = false;
		execute_cli_idabridge(cmd, cmd_args, results);
		return true;
	}else if(handling_ml_cmd){
		cached_cmd_args += (cli_input+"\n");
		return true;
	}

	
	if(tinput.size() == 0){
		return false;
	}

	cmd = cli_input.substr(0, cli_input.find_first_of(" "));
	
	if(cmd.size() < cli_input.size())
		cmd_args = cli_input.substr(cmd.size()+1, cli_input.size()-cmd.size());
	
	
	/* mjw removed
	if (cmd  == "start" || cmd == "stop" || cmd == "status"){
		return execute_command_handler(cmd, cmd_args);
	}
	*/
	__try
	{
		ret = execute_command_handler(cmd, cmd_args);
		if(ret)
		{
			//successful return
			return ret;
		}
		else //try in python
		{
			// added to handle multi-line commands, 
			// allows us to parse and identify the command
			// then we can cache everything before we execute the command
			if(is_ml_command(cmd)){
				handling_ml_cmd = true;
				cached_cmd = cmd;
				cached_cmd_args  = cmd_args+"\n";
				return true;
			}
			log("going crazy...er python\n");
			execute_cli_idabridge(cmd, cmd_args, results);	
			return true;
		}

	}
	__except(cmd_filter(GetExceptionCode(), GetExceptionInformation()))
	{
		log("executing a command is completely fuxored. belgh\n");
		return false;
	}

}
int idaapi init(void) {
   
   log(PLUGIN_NAME": loaded\n");
   if (init_network()) {
      mainWindow = (HWND)callui(ui_get_hwnd).vptr;
      hModule = GetModuleHandle("idabridge.plw");

	  if(!hModule)
	  {
		  log("hmodule is fucked\n");
		  return -1;
	  }

	  init_command_handlers();
	  IDAPythonHModule = GetModuleHandle("python.plw");
	  IDAPython_run_string = (IDAPYTHON_FN)GetProcAddress(IDAPythonHModule,"IDAPython_run_string");
	  IDAPython_eval_string = (IDAPYTHON_FN)GetProcAddress(IDAPythonHModule,"IDAPython_eval_string");
	  IDAPython_destroy_object = (IDAPYTHON_FREE)GetProcAddress(IDAPythonHModule,"IDAPython_destroy_object");
      enable_dlistener_cli(true);
	  std::string results = "";
	  if (execute_python_run_string(IDABRIDGE_IMPORT, results)){
		log("Successfully loaded the idabridge module.\n");
	  }else{
		log("Failed to load the idabridge python module.  Stuff will fail.\n");
	  }
	  return PLUGIN_KEEP;
   }
   else {
      return PLUGIN_SKIP;
   }
}


void idaapi run(int arg) { }
void idaapi term(void) {
   log(PLUGIN_NAME": being unloaded\n");
   if (is_connected()) {
      cleanup();
   }
   term_network();
   enable_dlistener_cli(false);
}

//--------------------------------------------------------------------------
//char comment[] = "This is a skeleton plugin. It doesn't do a thing.";
char *comment = NULL;
char *help = NULL;

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "idabridge";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F7";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};


ULONG64 get_ea_t(Buffer &b){
	ULONG64 addr;
	addr = b.readLong(); // 8-byte word address
	//addr = translate_dbg_to_ida(addr);
	return addr;
}

void execute_cli_idabridge(std::string cmd, std::string args, std::string &results){
	std::string buf_data = "",
				python_buffer_str = "";
	python_buffer_str = "cmd = '''" + cmd + "'''\n";
	python_buffer_str += "args = '''" + args + "'''\n";
	python_buffer_str += "_kargs = {}\n";
	execute_idabridge_handle_cli(python_buffer_str, results);
}

void execute_idabridge_handle_cli(std::string python_buffer_str, std::string &results){
		const std::string BUFFER_TAG = "<BUFFER>:";
		if(execute_python_run_string(python_buffer_str,results)){
 		std::string idabridge_handle_cli = "idabridge.handle_cli(cmd, args)";
		if(execute_python_eval_command(idabridge_handle_cli,results)){
			if (results.find_first_of(BUFFER_TAG) == 0 && 
				results.size() > BUFFER_TAG.size()){
				Buffer buf(results.size()+100);
				buf.write(results.c_str()+BUFFER_TAG.size(), results.size());
				send_data(buf);
				log("Sending the resulting buffer to the remote debugger.\n");
			}
		}
		log("Resulting Python Call Returned: %s\n", results.c_str());
	}
}

void execute_idabridge_handle_msg(std::string python_buffer_str, std::string &results){
	//moves the buffer over from ida to python
	const std::string BUFFER_TAG = "<BUFFER>:";
	if(execute_python_run_string(python_buffer_str,results)){
		std::string idabridge_handle_msg = "idabridge.handle_msg(buffer)";
		if(execute_python_eval_command(idabridge_handle_msg,results)){
			if (results.find_first_of(BUFFER_TAG) == 0 && 
				results.size() > BUFFER_TAG.size()){
				Buffer buf(results.size()+100);
				buf.write(results.c_str()+BUFFER_TAG.size(), results.size());
				send_data(buf);
				log("Sending the resulting buffer to the remote debugger.\n");
			}
		}
	}
	log("Resulting Python Call Returned: %s\n", results.c_str());
}


void execute_net_msg_idabridge(Buffer & buf, std::string &results){
	std::stringstream hexlify;
	std::string buf_data = "", data="",
				python_buffer_str = "";
	buf.readBufferToString(data);
	const char *d = data.c_str();
	for (unsigned int i = 0; i < data.size(); i++){
		unsigned char val = d[i];
		hexlify << std::setfill('0') << std::setw(2) <<std::hex << ((int)val);
	}
	python_buffer_str =  "buf_data = '''"+ hexlify.str()+"'''\n";
	python_buffer_str += "buffer = Buffer(buf_data,hexlified=True)\n";
	python_buffer_str += "_kargs = {}\n";
	execute_idabridge_handle_msg(python_buffer_str, results);
}









bool start_cli(std::string &args){
	std::string default_host = "127.0.0.1",
			    default_port = "8088";
	char host_c[8096] = {"127.0.0.1\0"};
	cnn.supstr(LAST_SERVER_SUPVAL, host_c, sizeof(host_c));
	short port = cnn.altval(LAST_PORT_ALTVAL);

	/*if (strnlen(host_c, 8096) == 0){
		strncpy(host_c, default_host.c_str(), default_host.size())
	}*/
	if (port == 0)
		port = (short) convert_string_to_addr(default_port);

	if (is_connected()){
		log("Already connected.\n");
		return true;
	}
	std::vector<std::string > *arg_toks = tokenize(args);
	std::string host = host_c;
    bool result = true;

	SOCKET new_sock = INVALID_SOCKET;
	if (arg_toks->size() >= 1){
		host = (*arg_toks)[0];
	}
	if(arg_toks->size() >= 2){
		port = (short) convert_string_to_addr((*arg_toks)[1]);
	}
	if (host.size() == 0){
		result = false;
	}
    //connect to the server.
    SOCKET conn = INVALID_SOCKET;
	if (result){
		log(PLUGIN_NAME"Attempting a connection to: %s %d\n", host.c_str(), port);
		conn = connect_to(host.c_str(), port);
	}
	if (createSocketWindow(conn, msg_dispatcher)) {
		log(PLUGIN_NAME": successfully connected to %s:%d\n", host.c_str(), port);
		cnn.altset(LAST_PORT_ALTVAL, port);
		cnn.supset(LAST_SERVER_SUPVAL, host.c_str());
	}
	if (is_connected()){
		std::string rebase = "rebase",
					getregs = "getregs",
					getbps = "getbps",
					results = "";
		log("Rebasing the Binary.\n");
		execute_cli_idabridge(rebase, "", results);
		log("Updating the Registers.\n");
		execute_cli_idabridge(getregs, "", results);
		log("Updating the Breakpoints.\n");
		execute_cli_idabridge(getbps, "", results);
	}

	return is_connected();
}

bool stop_cli(std::string & args){
	return term_network();
}

bool status_cli(std::string &args){
	log("in start_status\n");
	send_get_status();

	return true;
}



bool add_pycommand_cli(std::string &args){
	std::string new_cmd = "",
				code = "",
				aliasto = "pycmd",
				results = "";

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
	if(add_command(code, results)){
		results = "Successfully added command: ";
		results += new_cmd;
		add_pycmd_alias(aliasto, new_cmd);
	}
	log("Results: %s\n",results.c_str());
	return true;
}


bool add_pycommand_req(Buffer &buf){
	std::string cmd = "pyadd",
				new_cmd = "",		
				code = "",
				results = "",
				aliasto = "pycmd";

	if(!buf.readString(new_cmd)){
		// failed to read the command name
		results = "Invalid command";
	}else if (!buf.readString(code)){
		// failed to read the python code
		results = "Failed to add command: ";
		results += new_cmd;
	}else if(add_command(code,results)){
		results = "0";
		add_pycmd_alias(aliasto, new_cmd);
	}
	Buffer obuf;
	obuf.writeInt(CMD_RES);
	obuf.writeString(cmd);
	obuf.writeString(new_cmd);
	obuf.writeString(results);
	send_data(obuf);
	return true;
}



void init_command_handlers(){

	// start cmd and cli handler registration
	register_cmd_handler("start", default_net_handler, default_net_handler, start_cli);

	// stop cmd and cli handler registration
	register_cmd_handler("stop", default_net_handler, default_net_handler, stop_cli);
	
	register_cmd_handler("status", status_handler, status_handler, status_cli);
	// python command cmd and cli handler registration
	add_ml_command("pyadd");
	add_ml_command("python");

}



// imported from dlistener_ui

bool msg_dispatcher(Buffer &b) {
	// clone the recv buffer
	// TODO: could make this a mt-part to remove load from reciver
	Buffer myBuffer(b.size()); // want to skip the buffer size
	myBuffer << b;
	b.reset();
	std::string results = "";
	execute_net_msg_idabridge(myBuffer, results);
	return true;
}

int cmd_filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) 
{
	/*
   if (code == EXCEPTION_ACCESS_VIOLATION)
   {
		return EXCEPTION_EXECUTE_HANDLER;
   }

   else 
   {
	   return EXCEPTION_CONTINUE_SEARCH;
   };
   */

	return EXCEPTION_CONTINUE_SEARCH;

}
