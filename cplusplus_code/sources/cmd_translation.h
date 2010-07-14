#ifndef __CMD_XLATION_H__
#define __CMD_XLATION_H__

#include <string>
#include <algorithm>
#include <Windows.h>
#include <winsock.h>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>

#include "buffer.h"




typedef bool (*NET_FN)(Buffer &buf);
typedef bool (*CLI_FN)(std::string& args);

typedef std::map<std::string, NET_FN> NET_FN_HANDLER;
typedef std::map<std::string, CLI_FN> CLI_FN_HANDLER;

typedef struct _CMD_HANDLERS{
	NET_FN_HANDLER res;
	NET_FN_HANDLER req;
	CLI_FN_HANDLER cli;
	_CMD_HANDLERS():res(),req(),cli(){}
} CMD_HANDLERS, *PCMD_HANDLERS;

bool is_ml_command(std::string cmd);
void add_ml_command(std::string cmd);

// Handle cli based commands
bool execute_command_handler(std::string args);
bool execute_command_handler(std::string cmd, std::string args);
void register_cmd_handler(std::string cmd_name, CLI_FN handler);
// Handle net based commands
bool execute_command_handler(std::string cmd, unsigned char cmd_type, Buffer &buf);
void register_cmd_handler(std::string cmd_name);
void register_cmd_handler(std::string cmd_name, NET_FN handler, unsigned char cmd_type);
void register_cmd_handler(char * cmd_name, NET_FN req_handler, NET_FN res_handler, CLI_FN cli_handler );
void register_cmd_handler(std::string cmd_name, NET_FN req_handler, NET_FN res_handler, CLI_FN cli_handler );
// default cmd handlers
bool default_cli_handler(std::string& args);
bool default_net_handler(Buffer& buf);
bool status_handler(Buffer &b);



void convert_long64_to_string(ULONG64 value, std::string &out);
void convert_int_to_string(ULONG32 value, std::string &out);
void convert_short_to_string(short value, std::string &out);
void convert_byte_to_string(char value, std::string &out);


std::map<std::string, std::string> *parse_registers(std::string str);
std::vector<std::string> * parse_breakpoints(std::string str);
bool parse_breakpoint_info(std::string stmt, 
						   std::string &bp,
						   std::string &bp_active,
						   std::string &bp_condition);

//bool parse_templated_args();

// templates

void init_idapython_aliases();
bool is_pycmd(std::string cmd);
std::string getpycmdalias(std::string cmd_name);
void add_pycmd_alias(std::string name, std::string alias);
void add_pycmd_alias_list(std::string alias_lst, std::string del=" ");
void add_pycmd_alias_list(std::string name, std::vector<std::string >* items);




void add_alias(std::string name, std::string alias);
void add_alias_list(std::string alias_lst, std::string del=" ");
void add_alias_list(std::string name, std::vector<std::string >* items);
std::string get_command_alias(std::string cmd_name);

unsigned int get_type_from_cmd(std::string &cmd);
bool all_digits_c(char *value);
LONG64 convert_string_to_numval(std::string s);

std::string join(std::vector<std::string > *tokens, unsigned int start=0, unsigned int end=-1, std::string del="\n");
std::vector<std::string > *tokenize(const std::string& str, std::string del=" ");
std::vector<std::string > *tokenize(const std::string& str, const char* _del);

void add_alias(std::string name, std::string alias);


struct strCmp {
  bool operator()( const char* s1, const char* s2 ) const {
	  return ::strcmp( s1, s2 ) < 0;
  }
};

bool all_digits_c(char *value);
bool all_digits_s(std::string value);
void convert_addr_to_string(ULONG64 value, std::string &out);
ULONG64 convert_string_to_addr(std::string &s);
ULONG64 convert_char_to_addr(const char *c);
void convert_reg_vals_to_string(std::map<std::string,ULONG64> &reg_vals, std::string& out);
void convert_bps_to_string(std::vector<ULONG64> &bps, std::string& out);
void send_cmd_rsp(UINT cmd, std::string &str);

//
std::map<std::string, std::string> * read_regs_from_buffer(Buffer &b);
std::vector<std::string> * read_bps_from_buffer(Buffer &b);

void convert_wchar_to_string(PWSTR buf, std::string &out);
std::string trimmed( std::string const& str, char const* strip );


// msg type result or command
#define CMD_REQ 0
#define CMD_RES 1
#define CMD_CLI 2


#define MAX_INT 0xffffffff
#define MAX_SHT 0xffff
#define MAX_CHR 0xff
// cmd->template array


#endif