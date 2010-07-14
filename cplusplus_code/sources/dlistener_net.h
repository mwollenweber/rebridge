#ifndef __DLISTENER__NET_H__
#define __DLISTENER__NET_H__
#include "Buffer.h"
#include <string>
#include <Windows.h>
#include <map>
#include <vector>

#define DEFAULT_PORT 8088



bool recv_net_command(Buffer &b);

void send_cmd_results(Buffer &buf, std::string cmd, std::string results="", unsigned char cmd_type=1);



void send_break_cmd(unsigned int tid=-1 );
void send_resume_cmd(unsigned int tid=-1 );
void send_bphit(ULONG64 ea);
void send_get_status();

void send_idapython_cmd(std::string cmd);


bool send_cmd_string(std::string cmd, std::string result="", unsigned char cmd_type=0);

#endif