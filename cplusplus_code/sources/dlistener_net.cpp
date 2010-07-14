#include "cmd_translation.h"
#include "dlistener_net.h"
#include "Buffer.h"
#include <string>
#include <algorithm>
#include <Windows.h>
#include <winsock.h>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>





// change dependent on the project
#ifdef IDABRIDGE
#include "idanet.hpp"
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
#define log msg
#define PLUGIN_NAME "dida"
#else
#include <dbgeng.h>
#include <Windows.h>
#include <winsock.h>
#include <wdbgexts.h>
#include "dlistener_wdbg.h"
#define log dprintf
#define PLUGIN_NAME "dwdbg"
#endif


bool recv_net_command(Buffer &b){
	//mjw look here

	// read cmd string
	unsigned char cmd_type = b.readInt() == 0 ? 0 : 1;
	std::string cmd = "";
	if(!b.readString(cmd)){
		// log that we recieved a bad cmd string
		b.reset();
		return true;
	}
	// look up and execute command
	log("Received the following command: %s\n", cmd.c_str());
#ifdef IDABRIDGE
#else
	return execute_command_handler(cmd,cmd_type,b);
#endif
}


void send_cmd_results(Buffer &buf, std::string cmd, std::string results, unsigned char cmd_type){
	buf.reset();
	buf.writeInt(CMD_RES);
	buf.writeString(cmd);
	buf.writeString(results);
	send_data(buf);
}

void send_get_status()
{
	log("in send_get_status\n");

	std::stringstream builder;
	std::string cmd = "getstatus";
	send_cmd_string(cmd,builder.str(),CMD_REQ);
}

void send_get_bps(){
	std::stringstream builder;
	std::string cmd = "getbps";
	send_cmd_string(cmd,builder.str(),CMD_REQ);
}
void send_break_cmd(unsigned int tid ){
	std::stringstream builder;
	builder << "0x" << std::hex << tid;
	std::string cmd = "break";
	send_cmd_string(cmd,builder.str(),CMD_REQ);
}



void send_resume_cmd(unsigned int tid ){
	std::stringstream builder;
	builder << "0x" << std::hex << tid;
	std::string cmd = "resume";
	send_cmd_string(cmd,builder.str(),CMD_REQ);
}

void send_get_regs(){
	std::stringstream builder;
	std::string cmd = "getregs";
	send_cmd_string(cmd,builder.str(),CMD_REQ);
}
/* send the bp was hit */
void send_bphit(ULONG64 ea){
	std::stringstream builder;
	std::string cmd = "bphit";
	builder << "0x" << std::hex << ea;
	send_cmd_string(cmd,builder.str(),CMD_REQ);
}





void send_cmd_rsp(UINT cmd, std::string &str){
	Buffer b;
	b.writeInt(CMD_RES);
	b.writeInt(cmd);
	b.writeInt(str.size());
	b.write(str.c_str(), str.size());
	send_data(b);
}

bool send_cmd_string(std::string cmd, std::string result, unsigned char cmd_type){
	Buffer buf;
	buf.writeInt(cmd_type);
	buf.writeString(cmd);
	buf.writeString(result);
	send_data(buf);
	return true;
}

void send_idapython_cmd(std::string cmd){
	unsigned int len = cmd.size();
	len += 8;
	Buffer buf(len);
	buf.writeInt(CMD_REQ);
	buf.writeInt(cmd.size());
	buf.write(cmd.c_str(), cmd.size());
	send_data(buf);
}