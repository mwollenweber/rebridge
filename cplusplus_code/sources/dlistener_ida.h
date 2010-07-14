#ifndef __DLISTENER__IDA_H__
#define __DLISTENER__IDA_H__
#include "dlistener_net.h"

#include <Windows.h>
#include <map>
#include <vector>
#include <string>
#include <excpt.h>

#include "cmd_translation.h"

typedef bool (*IDAPYTHON_FREE)(void *);
typedef bool (*IDAPYTHON_CMD)(const char *name_, const char *expr, char *errbuf, size_t errbufsize);
typedef bool (*IDAPYTHON_FN)(const char *run_string, 
						/*in-out*/ char **result_buf, 
						/*in-out*/ unsigned long *buf_size
);
typedef bool (*IDAPYTHON_CODE)(const char *run_string, 
							const char *filename, 
						/*in-out*/ char **result_buf, 
						/*in-out*/ unsigned long *buf_size);



int cmd_filter(unsigned int, struct _EXCEPTION_POINTERS *);

//std::vector<std::string > *tokenize(const std::string& str, std::string del);



void handle_result_buf(char* result_buf, unsigned long buf_size, std::string &results);
std::string build_breakpoint_set_string(std::vector<std::string> *bp_vals);
std::string build_breakpoint_update_string(std::vector<std::string> *bp_vals);

void add_str_to_buffer(std::string &s, Buffer &b);

ULONG64 get_ea_t(Buffer &b);


typedef bool (*IDA_CMD_HANDLER)(Buffer &B);

bool idaapi execute_python_eval_command(char * cmd_function,char * args,  std::string &results);
bool idaapi execute_python_eval_command(std::string cmd_function,std::string args,  std::string &results);
bool idaapi execute_python_eval_command(char * python_code,  std::string &results);
bool idaapi execute_python_eval_command(std::string python_code,  std::string &results);

void execute_net_msg_idabridge(Buffer & buf, std::string &results);
void execute_idabridge_handle_cli(std::string python_buffer_str, std::string &results);
void execute_idabridge_hanle_msg(std::string python_buffer_str, std::string &results);
void execute_cli_idabridge(std::string cmd, std::string args, std::string &results);

bool start_cli(std::string &args);
bool stop_cli(std::string &args);
bool status_cli(std::string &args);

void init_command_handlers();
bool idaapi dlistener_command_handler(const char *line);
bool msg_dispatcher(Buffer &b);


#endif