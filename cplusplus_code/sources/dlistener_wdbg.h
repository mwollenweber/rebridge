#ifndef __DLISTENER__WDBG_H__
#define __DLISTENER__WDBG_H__
#include "Buffer.h"
#include <string>
#include <Windows.h>
#include <winsock.h>
#include <dbgeng.h>
#include <map>
#include <vector>

typedef bool(*HANDLER)(Buffer &) ;

#define DEFAULT_PORT 8088

typedef struct mregs{
	void * value;
	unsigned int size;
} REG, *PREG;

bool start_listener(std::string &host, std::string &port);
int send_data(Buffer &b, SOCKET sock=INVALID_SOCKET);
bool msg_dispatcher(Buffer &b);
void handle_client_comms(SOCKET client, HANDLER handler);
void cleanup_sock(SOCKET client);

void get_registers_and_values(std::map<std::string, ULONG64> &reg_collection);

bool start_server(std::string& host, std::string& port);
int stop_server();

bool is_listening();
bool is_connected();
bool is_client_connected();
void shutdown_server();
void shutdown_current_client();



bool is_tid_valid(ULONG tid);

bool handle_break_cmd(ULONG64 tid);
bool suspend_thread(ULONG tid);
bool suspend_all_threads();
bool suspend_execution(PDEBUG_CONTROL ctrl);

bool add_breakpoint(ULONG64 ea);
void add_breakpoints(std::vector<std::string > *bps);
void clear_breakpoints();

bool handle_resume_cmd(ULONG tid);
bool resume_thread(ULONG tid);
bool resume_all_threads();
bool resume_execution(PDEBUG_CONTROL ctrl);

// added this stuff
std::string get_registers_string();

bool idapython_cli(std::string &args);
bool idapython_rsp(Buffer &buf);

bool rebase_cli(std::string &args);
bool rebase_req(Buffer &buf);


bool get_regs_cli(std::string &args);
bool get_regs_rsp(Buffer &buf);
bool get_regs_req(Buffer &buf);

bool set_regs_req(Buffer &buf);
bool set_regs_cli(std::string &args);

bool set_bps_cli(std::string & args);
bool set_bps_req(Buffer &b);

bool status_cli(Buffer &b);
bool resume_req(Buffer &b);

bool break_req(Buffer &b);

bool get_bps_cli(std::string &args);
bool get_bps_req(Buffer &b);
bool get_bps_rsp(Buffer &buf);

bool rebase_cli(std::string &args);
bool rebase_req(Buffer &b);

bool write_memory_req(std::string args);
bool write_memory_cli(Buffer &buf);
bool write_memory_rsp(Buffer &buf);

bool add_alias_cli(std::string& args);
bool start_cli(std::string& args);
bool stop_cli(std::string& args);
void init_command_handlers();

bool add_pycmd_rsp(Buffer &buf);
bool add_pycmd_cli(std::string &args);

bool send_two_arg_buffer(std::string arg0, std::string arg1, std::string cmd, unsigned char cmd_type);

#endif