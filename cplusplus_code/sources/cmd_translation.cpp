#include <string>
#include <algorithm>
#include <Windows.h>
#include <winsock.h>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <utility>
#include <set>
#include "cmd_translation.h"
#include "idapython_aliases.h"

#ifdef IDABRIDGE
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <md5.h>
#define log msg
#define PLUGIN_NAME "dlistener"
#endif

#ifndef IDABRIDGE
#include <dbgeng.h>
#include <windows.h>
#include <wdbgexts.h>
#include <extsfns.h>
#define log dprintf
#define PLUGIN_NAME "dwdbg"
#endif



char * BPHIT_ALIASES = "bphit";
char * GETBPS_ALIASES = "getbps";
char * SETBPS_ALIASES = "setbps";
char * GETREGS_ALIASES = "getregs";
char * SETREGS_ALIASES = "setregs";
char * READMEM_ALIASES = "readmem";
char * WRITEMEM_ALIASES = "writemem";
char * BREAK_ALIASES = "break";
char * RESUME_ALIASES = "resume";
char * REBASE_ALIASES = "rebase";
char * STATUS_ALIASES = "status";
char* EMPTY_ALIAS = "";

char * ALIAS_ARRAY[] = {
	BPHIT_ALIASES,
	GETBPS_ALIASES,
	SETBPS_ALIASES,
	GETREGS_ALIASES,
	SETREGS_ALIASES,
	READMEM_ALIASES,
	WRITEMEM_ALIASES,
	BREAK_ALIASES,
	RESUME_ALIASES,
	STATUS_ALIASES,
	EMPTY_ALIAS
};



// aliases map
std::map<std::string, std::string> command_aliases;
std::map<std::string, std::string> pycommand_aliases;
//std::map<std::string, std::string> idapython_aliases;
std::set<std::string> ml_commands;


bool is_ml_command(std::string cmd){
	return ml_commands.find(cmd) != ml_commands.end();
}
void add_ml_command(char* cmd){
	std::string cmd_ = cmd;
	add_ml_command(cmd_);
}

void add_ml_command(std::string cmd){
	ml_commands.insert(cmd);
}

std::string trimmed( std::string const& str, char const* strip ){
	std::string::size_type const first = str.find_first_not_of(strip);
	return ( first==std::string::npos ) ? std::string() : str.substr(first, str.find_last_not_of(strip)-first+1);
}

void init_idapython_aliases(){
	char **aliases = IDAPYTHON_ALIASES;
	while(*aliases != '\0'){
		add_pycmd_alias_list(*aliases, ",");
		aliases++;
	}

}

bool is_pycmd(std::string cmd){
	return pycommand_aliases.find(cmd) != pycommand_aliases.end();
}

void add_pycmd_alias(std::string name, std::string alias){
	pycommand_aliases[alias] = name;
}

void add_pycmd_alias_list(char * alias_lst, char * del){
	std::string aliases = alias_lst;
	std::string del_ = del;
	add_pycmd_alias_list(aliases, del_);
}

void add_pycmd_alias_list(std::string alias_lst, std::string del){
	std::vector<std::string >* items = tokenize(alias_lst, del);
	if(items->size() > 0){
		add_pycmd_alias_list((*items)[0], items);
	}
	items->clear();
	delete items;
}
void add_pycmd_alias_list(std::string name, std::vector<std::string >* items){
	std::vector<std::string >::iterator iter = items->begin();
	for (; iter != items->end(); iter++){
		if (*iter != "")
			add_pycmd_alias(name, *iter);
	}
}


void add_alias_list(char * alias_lst, char * del){
	std::string aliases = alias_lst;
	std::string del_ = del;
	add_pycmd_alias_list(aliases, del_);
}

void add_alias(std::string name, std::string alias){
	command_aliases[alias] = name;
}

void add_alias_list(std::string alias_lst, std::string del){
	std::vector<std::string >* items = tokenize(alias_lst, del);
	if(items->size() > 0){
		add_alias_list((*items)[0], items);
	}
	items->clear();
	delete items;
}

void add_alias_list(std::string name, std::string alias_lst, std::string del){
	std::vector<std::string >* items = tokenize(alias_lst, del);
	if(items->size() > 0){
		add_alias_list(name, items);
	}
	items->clear();
	delete items;
}

void add_alias_list(std::string name, std::vector<std::string >* items){
	std::vector<std::string >::iterator iter = items->begin();
	for (; iter != items->end(); iter++){
		if (*iter != "")
			add_alias(name, *iter);
	}
}

void init_command_definitions(){
	unsigned int idx = 0;
	idx = 0;
	std::string alias_name;
	while(idx < sizeof(ALIAS_ARRAY)){
		std::string alias_lst = ALIAS_ARRAY[idx];
		std::vector<std::string >* items = tokenize(alias_lst, ",");
		std::string name = (*items)[0];
		add_alias_list(name,alias_lst,",");
		items->clear();
		delete items;
		idx++;
	}
}



std::vector<std::string > *tokenize(const std::string& str, const char* _del){
	std::string del = _del;
	return tokenize(str,del);
}

std::vector<std::string > *tokenize(const std::string& str, std::string del){
	std::vector<std::string > *tokens = new std::vector<std::string > ;
	
	std::string::size_type lastPos = str.find_first_not_of(del,0);
	std::string::size_type currentPos = str.find_first_of(del,lastPos);
	while(std::string::npos != currentPos || std::string::npos != lastPos){
		std::string s = str.substr(lastPos, currentPos - lastPos);
		tokens->push_back(s);
		lastPos = str.find_first_not_of(del,currentPos);
		currentPos = str.find_first_of(del,lastPos);
	}
	return tokens;
}


std::string join(std::vector<std::string > *tokens, unsigned int start, unsigned int end, std::string del){
	std::stringstream build_string;
	unsigned int end_ = end==-1 ? tokens->size(): end;
	for(unsigned int start_=start; start_ < end_;start_++){
		build_string << (*tokens)[0] << del;
	}
	std::string result = build_string.str();
	return result;
}


CMD_HANDLERS APP_CMD_HANDLER;
bool execute_command_handler(std::string cmd, unsigned char cmd_type, Buffer &buf){

	std::string cmd_name = cmd.substr(0, cmd.find_first_of(" "));
	// this may cause problems since idapython is using the same map collection
	cmd_name = command_aliases[cmd_name];
	log("execute_command_handler: processing cmd = %s\n", cmd.c_str());

	cmd_type = cmd_type == 0 ? 0 : 1;
	NET_FN_HANDLER *handlers = NULL;
	if (cmd_type == 0)
		handlers = &APP_CMD_HANDLER.req; //requests
	else 
		handlers = &APP_CMD_HANDLER.res; //responses

	if (handlers->find(cmd_name) != handlers->end()){
		NET_FN handler = (*handlers)[cmd_name];
		return handler(buf);
	}
	else{
		log("ERROR: could not find a handler for %s\n", cmd.c_str());
	}

	
	return false;
}

bool execute_command_handler(std::string args){
	std::string cmd_name = args.substr(0, args.find_first_of(" "));
	if (cmd_name.size() != args.size())
		args = args.substr(args.find_first_not_of(cmd_name), args.size()-cmd_name.size());
	return execute_command_handler(cmd_name, args);
}



bool execute_command_handler(std::string cmd_name, std::string args){
	
	cmd_name = command_aliases[cmd_name];
	CLI_FN_HANDLER *handlers = NULL;
	handlers = &APP_CMD_HANDLER.cli;
	if (handlers->find(cmd_name) != handlers->end()){
		CLI_FN handler = (*handlers)[cmd_name];
		return handler(args);
	}
	return false;
}

std::string getpycmdalias(std::string cmd_name){
	std::string cmd = "";
	if (pycommand_aliases.find(cmd_name) != pycommand_aliases.end()){
		// command is not present in our alias list
		return pycommand_aliases[cmd_name];
	}
	return cmd;
}

std::string get_command_alias(std::string cmd_name){
	std::string cmd = "";
	if (command_aliases.find(cmd_name) != command_aliases.end()){
		// command is not present in our alias list
		return command_aliases[cmd_name];
	}
	else if (pycommand_aliases.find(cmd_name) != pycommand_aliases.end()){
		// command is not present in our alias list
		return pycommand_aliases[cmd_name];
	}
	return cmd;
}

void register_cmd_handler(std::string cmd_name){
	command_aliases[cmd_name] = cmd_name;
	if (APP_CMD_HANDLER.cli.find(cmd_name) == APP_CMD_HANDLER.cli.end())
		APP_CMD_HANDLER.cli[cmd_name] = default_cli_handler;
	if (APP_CMD_HANDLER.req.find(cmd_name) == APP_CMD_HANDLER.req.end())
		APP_CMD_HANDLER.req[cmd_name] = default_net_handler;
	if (APP_CMD_HANDLER.res.find(cmd_name) == APP_CMD_HANDLER.res.end())
		APP_CMD_HANDLER.res[cmd_name] = default_net_handler;
}

void register_cmd_handler(std::string cmd_name, NET_FN handler, unsigned char cmd_type){
	command_aliases[cmd_name] = cmd_name;
	cmd_type = cmd_type == 0 ? 0 : 1;
	NET_FN_HANDLER *handlers = NULL;
	if (cmd_type)
		APP_CMD_HANDLER.res[cmd_name] = handler;
	else 
		APP_CMD_HANDLER.req[cmd_name] = handler;
	
}

void register_cmd_handler(std::string cmd_name, 
							NET_FN req_handler, 
							NET_FN res_handler, 
							CLI_FN cli_handler ){
	command_aliases[cmd_name] = cmd_name;
	APP_CMD_HANDLER.res[cmd_name] = res_handler;
	APP_CMD_HANDLER.req[cmd_name] = req_handler;
	APP_CMD_HANDLER.cli[cmd_name] = cli_handler;
}

void register_cmd_handler(char * cmd_name, 
							NET_FN req_handler, 
							NET_FN res_handler, 
							CLI_FN cli_handler ){
	std::string cmd_name_ = cmd_name;
	register_cmd_handler(cmd_name_, req_handler, res_handler, cli_handler);
}

void register_cmd_handler(std::string cmd_name, CLI_FN handler){
	command_aliases[cmd_name] = cmd_name;
	APP_CMD_HANDLER.cli[cmd_name] = handler;
}

bool default_net_handler(Buffer &b){
	b.rewind(b.get_rlen());
	std::string cmd_type = (b.readInt() == 0) ? "CMD_REQ" : "CMD_RSP";//cmd type
	std::string cmd;
	b.readString(cmd);
	log("Default Handler: cmd_type: %s cmd_name: %s\n",cmd_type.c_str(), cmd.c_str());
	return true;
}

bool default_cli_handler(std::string& args){
	return true;
}




bool all_digits_c(char *value){
	unsigned int len = strlen(value);
	bool flag = false;
	if (!len)
		return false;
	for (unsigned int i = 0; i < len; i++,value++){
		if (!isdigit(*value) && !isxdigit(*value)){
			if ((*value == 'x' || *value == 'X') && !flag){
				flag = true;
				continue;
			}
			return false;
		}
	}
	return true;
}


LONG64 convert_string_to_numval(std::string s){
	const char *c = s.c_str();
	
	if (!all_digits_c((char *)c)){
		return false;
	}
	if ((c[0] == '0' && c[1] == 'x') ||
		(c[0] == '0' && c[1] == 'X')){
		return _strtoi64(c,NULL,16);
	}
	return _strtoi64(c,NULL,10);
}






bool all_digits_s(std::string s){
	return all_digits_c((char *)s.c_str());
}

std::map<std::string, std::string> *read_regs_from_buffer(Buffer &b){
	
	unsigned int len = b.readInt();
	len = len > b.get_wlen() ? b.get_wlen() : len;
	char *data = (char *)malloc(len+1);
	if (data == NULL)
		return NULL;
	
	std::map<std::string, std::string> *reg_vals = new std::map<std::string, std::string>;
	if((reg_vals) == NULL)
		return NULL;

	b.read(data, len);
	data[len] = 0;
	std::string str = data;
	// parse registers and values
	// <reg name>:<value>
	std::vector<std::string > *v = tokenize(str, ",");
	for (;v->size() > 0;){
		std::string rv_pair = v->back();
		std::string::size_type end_reg_name = rv_pair.find_first_of(":",0);
		std::string reg_name = rv_pair.substr(0, end_reg_name);
		std::string value = rv_pair.substr(end_reg_name+1);
		std::pair<std::string, std::string> p(reg_name,value);
		reg_vals->insert(p);
		v->pop_back();
	}
	delete v;
	return reg_vals;
}

std::map<std::string, std::string> *parse_registers(std::string str){
	
	std::map<std::string, std::string> *reg_vals;
	reg_vals = new std::map<std::string, std::string>();
	if((reg_vals) == NULL)
		return NULL;

	// parse registers and values
	// <reg name>:<value>,<reg name>:<value>
	std::string reg_val = ":";
	std::vector<std::string > *v = tokenize(str, ",");
	for (;v->size() > 0;){
		std::string rv_pair = v->back();
		std::string::size_type end_reg_name = rv_pair.find_first_of(reg_val,0);
		std::string reg_name = rv_pair.substr(0, end_reg_name);
		std::string value = rv_pair.substr(end_reg_name+1);
		std::pair<std::string, std::string> p(reg_name,value);
		reg_vals->insert(p);
		v->pop_back();
	}
	delete v;
	return reg_vals;
}




std::vector<std::string> * parse_breakpoints(std::string str){
	// <addr>:<ida name>, ignoring the ida names atm
	std::map<std::string, std::string> *addr_names;
	addr_names = new std::map<std::string, std::string>();
	if((addr_names) == NULL)
		return NULL;

	// parse bps and names
	// <bp>:<name>,<bp>:<name>
	std::string bp_name_del = ":";
	std::vector<std::string > *v = tokenize(str, ",");
	for (;v->size() > 0;){
		std::string rv_pair = v->back();
		std::string::size_type end_reg_name = rv_pair.find_first_of(bp_name_del,0);
		std::string reg_name = rv_pair.substr(0, end_reg_name);
		std::string value = rv_pair.substr(end_reg_name+1);
		std::pair<std::string, std::string> p(reg_name,value);
		addr_names->insert(p);
		v->pop_back();
	}
	delete v;
	std::vector<std::string > *bps = new std::vector<std::string >;
	std::map<std::string, std::string>::iterator addr_names_iter = addr_names->begin();
	for(;addr_names->end() != addr_names_iter; addr_names_iter++)
		bps->push_back(addr_names_iter->first);
	
	delete addr_names;
	return bps;
}

bool parse_breakpoint_info(std::string stmt, 
						   std::string &bp,
						   std::string &bp_active,
						   std::string &bp_condition){
	bp = "0x0";
	bp_active = "False";
	bp_condition = "";
	bool result = false;
	std::vector<std::string > *bps = tokenize(stmt, ":");
	if (bps == NULL){
		return result;
	}
	if (bps->size() > 0){
		bp = (*bps)[0];
		result = true;
	}
	if (bps->size() > 1)
		bp_active = (*bps)[1];
	if (bps->size() > 2)
		bp_condition = (*bps)[2];
	bps->clear();
	delete bps;
	return result;
}

std::vector<std::string> * read_bps_from_buffer(Buffer &b){
	
	std::string data = "";
	if (!b.readString(data))
		return NULL;
	// parse registers and values
	// bps,bps,bps
	std::vector<std::string > *v = tokenize(data, ",");
	return v;
}


ULONG64 convert_char_to_addr(const char *c){
	if ((c[0] == '0' && c[1] == 'x') ||
		(c[0] == '0' && c[1] == 'X') ||
		(c[0] == '\\' && c[1] == 'x') ||
		(c[0] == '\\' && c[1] == 'X')){
		return _strtoui64(c,NULL,16);
	}
	return _strtoui64(c,NULL,10);

}
ULONG64 convert_string_to_addr(std::string &s){
	if (!all_digits_s(s))
		return -1;
	return convert_char_to_addr(s.c_str());
}

void convert_reg_vals_to_string(std::map<std::string,ULONG64> &reg_vals, std::string& out){
	std::stringstream ss;
	std::map<std::string,ULONG64>::iterator iter = reg_vals.begin();
	for(;iter != reg_vals.end(); iter++){
		std::string addr;
		convert_addr_to_string(iter->second, addr);
		ss << iter->first<<":"<<addr;
		std::map<std::string,ULONG64>::iterator check = iter;
		if(++check !=  reg_vals.end()){
			ss << ",";
		}
	}
	out = ss.str();
}
void convert_bps_to_string(std::vector<ULONG64> &bps, std::string& out){
	std::stringstream ss;
	std::vector<ULONG64>::iterator iter = bps.begin();
	//  ":" to pretend like there is a name attached the bp
	// TODO: add names to the bps
	for(;iter != bps.end(); iter++){
		std::string addr;
		ss << "0x" << std::hex << *iter << ":";
		std::vector<ULONG64>::iterator check = iter;
		if(++check !=  bps.end()){
			ss << ",";
		}
	}
	out = ss.str();
}




CHAR w2a(WCHAR w){return CHAR(w);}

void convert_wchar_to_string(PWSTR wbuf, std::string &out){
	std::wstring wstr = wbuf;
	std::string dest ((std::size_t)wstr.size(), '\x00');
	std::transform(wstr.begin(), wstr.end(), dest.begin(), w2a);
	out = dest;
}

void convert_addr_to_string(ULONG64 val, std::string &out){
	std::stringstream ss;
	ss << "0x" << std::hex << val;
	out = ss.str();
}

bool status_handler(Buffer &b){
	log("starting status handler\n");
	b.rewind(b.get_rlen());
	std::string cmd_type = (b.readInt() == 0) ? "CMD_REQ" : "CMD_RSP";//cmd type
	std::string cmd;
	b.readString(cmd);
	log("Default Handler: cmd_type: %s cmd_name: %s\n",cmd_type.c_str(), cmd.c_str());
	return true;
}
void convert_byte_to_string(char value, std::string &out){
	ULONG64 x = value&0xff;
	convert_addr_to_string(value, out);
}
