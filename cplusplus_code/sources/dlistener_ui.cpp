//#include <AtlBase.h>
//#include <atlstr.h>
#include "resource.h"
#include <iostream>
#include "dlistener_net.h"
#include "cmd_translation.h"
#include "idanet.hpp"
#include "dlistener_ui.h"
#include <vector>
#include <iomanip>
#include <tchar.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <md5.h>
#include <netnode.hpp>

#include "sdk_versions.h"
#include "buffer.h"
#include <string>
#include <pro.h>

#include "dlistener_ida.h"
#include "dlistener_net.h"
#include <sstream>

#define LAST_SERVER_SUPVAL 2
#define LAST_PORT_ALTVAL 2
volatile HWND mainWindow;
volatile HMODULE hModule;

volatile HWND regsWindow = NULL;
volatile HWND consoleWindow = NULL;
volatile HWND memmgtWindow = NULL;
volatile HWND bpmgtWindow = NULL;

#define DLISTENER_NETNODE "$ DLISTENER NETNODE"



// this code will break if compiled as Unicode.





std::map<std::string, IDA_CMD_HANDLER> handler_map;

netnode cnn(DLISTENER_NETNODE, 0, true);
static Dispatcher tempDispatcher;
void convert_tchar_to_addr_s(TCHAR *t, std::string &addr_s){
	ULONG64 ea = convert_tchar_to_addr(t);
	convert_addr_to_string(ea, addr_s);
}

TCHAR *convert_addr_to_tchar(ULONG64 addr_ea){
	std::string addr_s;
	convert_addr_to_string(addr_ea, addr_s);
	return convert_string_to_tchar(addr_s);
}


TCHAR * convert_string_to_tchar(std::string & c){
	char *tmp = (char*)c.c_str();
	TCHAR *result = (TCHAR*) malloc(sizeof(TCHAR)*(c.size()+1));
	//USES_CONVERSION;
	TCHAR *conv = tmp; //A2T(tmp);

	if (result == NULL)
		return NULL;
	unsigned int len = sizeof(TCHAR)*(c.size()); 
	memcpy(result, conv, sizeof(TCHAR)*(c.size()));
	memset(result+len, 0, sizeof(TCHAR));
	return result;
}
bool all_digits_t(TCHAR *value){
	unsigned int len = _tcslen(value);
	bool flag = false;
	if (!len)
		return false;
	for (unsigned int i = 0; i < len; i++,value++){
		if (!_istdigit(*value) && !_istxdigit(*value)){
			if((*value == TEXT('x') || *value == TEXT('X')) && !flag  ){
				flag = true;
				continue;
			}
			return false;
		}
	}
	return true;
}


bool set_addr_value_s(HWND dlg, int dlgItem, std::string &value){
	//USES_CONVERSION;
	TCHAR *tmp = (TCHAR *)value.c_str();//T2A((char *)value.c_str());
	SetDlgItemText(dlg,dlgItem,tmp);
	return true;
}
bool set_addr_value_ea(HWND dlg, int dlgItem,ULONG64 value){
	std::string r;
	convert_addr_to_string(value, r);
	set_addr_value_s(dlg,dlgItem, r);	
	return true;
}


ULONG64 get_addr_value(HWND dlg, int dlgItem){
	TCHAR value[80]= {0};
	GetDlgItemText(dlg,dlgItem,value,80);
	return convert_tchar_to_addr(value);
}


std::string* get_convert_dlg_str(HWND dlg, int dlgItem){
	unsigned int multiplier = 1,
				 cnt=0,
				 tcnt=0;
	TCHAR *buffer = (TCHAR *)malloc(1024*sizeof(TCHAR)*multiplier),
		  *tbuffer = NULL;
	if (!buffer){
		return NULL;
	}
	ZeroMemory(buffer, 1024*sizeof(TCHAR)*multiplier);
	
	while(true){
		if ((tcnt = GetDlgItemText(dlg, dlgItem, buffer+cnt, 1024)) == 0){
			// error occurred here, but i dont care atm
			break;
		}
		cnt+=tcnt;
		if (tcnt == 1023){
			// buffer was not big enough :(
			multiplier +=1;
			if (multiplier == 0){
				// wtf ?!?
				break;
			}
			// save, alloc, zero, copy, burn, free
			// save, alloc, zero
			tbuffer = buffer;
			buffer =  (TCHAR *)malloc(1024*sizeof(TCHAR)*multiplier);
			ZeroMemory(buffer, (1024*sizeof(TCHAR)*multiplier));
			// copy, burn
			memcpy(buffer,tbuffer, (1024*sizeof(TCHAR)*(multiplier-1)));
			ZeroMemory(tbuffer, (1024*sizeof(TCHAR)*(multiplier-1)));
			// free
			free(tbuffer);
			tbuffer = NULL;
		}
	}
	//CString x;
	char *tmp = buffer;

	// i do the following because i am not sure how T2A works :(
	char *myStr = (char *) malloc(cnt+3);
	if (!myStr){
		if(buffer){
			free(buffer);
		}
	}
	// convert tchar to std::string
	memcpy(myStr, tmp, cnt);
	myStr[cnt] = 0;
	std::string *x = new std::string;
	*x = myStr;
	free(myStr);
	return x;
}


//message handler for the server connection dialog
// taken from collabreate project.  See AUTHORS
BOOL CALLBACK ConnectDlgProc(HWND hwndDlg, UINT message, 
                             WPARAM wParam, LPARAM lParam) { 
   char host[128];
   char sport[16];
   int port;
   switch (message) { 
	case WM_INITDIALOG: {
		// Initializa all the window handles
		regsWindow = consoleWindow = memmgtWindow = bpmgtWindow = NULL;
		port = cnn.altval(LAST_PORT_ALTVAL);
		if (port == 0) {
			port = DEFAULT_PORT;
		}

		host[0] = 0;
		cnn.supstr(LAST_SERVER_SUPVAL, host, sizeof(host));
		qsnprintf(sport, sizeof(sport), "%d", port);
		SetDlgItemText(hwndDlg, IDC_HOSTNAME, host);
		SetDlgItemText(hwndDlg, IDC_PORT, sport);
		return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
         case IDCONNECT: {//OK Button 
            GetDlgItemText(hwndDlg, IDC_HOSTNAME, host, sizeof(host));
            GetDlgItemText(hwndDlg, IDC_PORT, sport, sizeof(sport));
            port = atoi(sport);

            cnn.altset(LAST_PORT_ALTVAL, port);
            cnn.supset(LAST_SERVER_SUPVAL, host);

            //connect to the server.
            SOCKET conn = connect_to(host, port);
            if (conn == INVALID_SOCKET) {
               EndDialog(hwndDlg, 0);
            }            
            else if (createSocketWindow(conn, tempDispatcher)) {
               msg(PLUGIN_NAME": successfully connected to %s:%d\n", host, port);
               EndDialog(hwndDlg, 1);
            }
            else {
               closesocket(conn);
               EndDialog(hwndDlg, 0);
            }
            return TRUE; 
         }
         case IDSTOP: //Cancel Button 
            EndDialog(hwndDlg, 0);
            return TRUE; 
         } 
   } 
   return FALSE; 
}

void update_register_values_from_dlg(HWND hwndDlg, std::string & out){
	std::map<unsigned int, std::string>::iterator iter = ui_to_name.begin();
	std::stringstream ss(std::stringstream::in | std::stringstream::out);
	// read all the registers
	// update current values from the dialog
	for(;iter != ui_to_name.end();iter++){
		// only add the comma after the first register is added
		std::stringstream convert_num(std::stringstream::in | std::stringstream::out);
		unsigned int ui_val = iter->first;
		std::string reg_name = iter->second;
		convert_num << "0x"<< std::setfill('0') << std::setw(8) <<std::hex << get_addr_value(hwndDlg,ui_val);
		std::string value = convert_num.str();
		ui_to_current_vals[ui_val] = value;
		name_to_current_vals[reg_name] = value;
		ss<<reg_name<<":"<<name_to_current_vals[reg_name];
		if(++iter != ui_to_name.end())
			ss << ",";
		iter--;
	}
	out = ss.str();
}

void update_dlg_from_register_values(){
	HWND hwndDlg = regsWindow;
	if (regsWindow == NULL){
		msg("Regs Dailog not available, not updating the UI.");	
		return;
	}
	std::map<unsigned int, std::string>::iterator iter = ui_to_name.begin();
	std::stringstream ss(std::stringstream::in | std::stringstream::out);
	// read all the registers
	// update current values from the dialog
	for(;iter != ui_to_name.end();iter++){
		// only add the comma after the first register is added
		unsigned int ui_val = iter->first;
		std::string reg_name = iter->second;
		std::string value = ui_to_current_vals[ui_val];
		if (!all_digits_s(value)){
			// set the values to 0x0
			value = "0x00000000";
			ui_to_current_vals[ui_val] = value;
			name_to_current_vals[reg_name] = value;
		}
		// convert from char to TCHAR
		set_addr_value_s(hwndDlg, ui_val, value);
	}
	
}



BOOL CALLBACK RegsDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam){
	std::string out = "";
	//check_dbger_connection();
	switch(message){
		case WM_INITDIALOG:
			msg(PLUGIN_NAME": sending a msg to get registers from the remote debugger.");
			return TRUE;
		case WM_DESTROY:
			regsWindow = NULL;
			return TRUE;
	 	case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
		case IDCANCEL:	
		case IDC_QUIT:
			DestroyWindow(hwndDlg);
			regsWindow = NULL;
			return TRUE;
		case IDC_GETREGS:
			// send a get regs message
			// how do i set a call back function to update this window?
			// answer: set global window handles and update when the files 
			// 			are recieved
			send_get_regs();
			return TRUE;
		case IDC_SETREGS:
			// update registers from the dialog
			update_register_values_from_dlg(hwndDlg, out);
			send_set_regs(out);
			return TRUE;
		case CMD_RES:
			update_dlg_from_register_values();
			return TRUE;
	
		 }
	}
	return FALSE;
}

bool get_addr_value_s(HWND dlg, int dlgItem, std::string &value){

	return true;

}

void kill_ui_windows(){
			// close all the windows below.
			if (regsWindow)DestroyWindow(regsWindow);
			if(consoleWindow)DestroyWindow(consoleWindow);
			if(memmgtWindow)DestroyWindow(memmgtWindow);
			if(bpmgtWindow)DestroyWindow(bpmgtWindow);
}

BOOL CALLBACK DbgDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam){
	unsigned int tid = -1;
	//check_dbger_connection();
	
	switch(message){
		case WM_INITDIALOG:
			select_registers_32();
			rebase_addr.addr = (ULONG64) get_imagebase();
			rebase_addr.use_rebase = false;
			set_addr_value_ea(hwndDlg, IDC_REBASE,rebase_addr.addr);
			return TRUE;
		case WM_DESTROY:
			kill_ui_windows();
			consoleWindow = NULL;
			return TRUE;
        case WM_COMMAND: 
        switch (LOWORD(wParam)) { 
 		 case IDC_GETREBASE:
			 if(lParam == CMD_RES){
				// TODO: fix the use of global variabls (e.g. rebase_addr and use_rebase)
				set_addr_value_ea(hwndDlg, IDC_REBASE,rebase_addr.addr);
			}else{
				send_get_base();
			}
			return true;
		
		case IDC_CBREBASE:
				if(BST_CHECKED == IsDlgButtonChecked(hwndDlg,IDC_CBREBASE)){
					rebase_addr.addr = get_addr_value(hwndDlg, IDC_REBASE);
					rebase_addr.use_rebase = true;
				}else{
					rebase_addr.use_rebase = false;
				}
				return true;

		case IDCANCEL:	
     	case IDC_QUIT:
			// clean-up, disconnect, and close the window
			cleanup(false);
			consoleWindow = NULL;
			DestroyWindow(hwndDlg);
			return TRUE;
		case IDC_SUSPROC:
			// send a BP packet to the remote
			// debugger
			send_break_cmd();
			return TRUE;
		case IDC_RESPROC:
			// resume process at the other end
			// of the debugger
			send_resume_cmd();
			return TRUE;
		case IDC_SUSTID:
			// read TID value from edit control
			// send a BP packet to the remote
			// debugger
			tid = GetDlgItemInt(hwndDlg, IDC_SUSTID, NULL, false);
			send_break_cmd(tid);
			return TRUE;
		case IDC_RESTID:
			// read TID value from edit control
			// resume process at the other end
			// of the debugger
			tid = GetDlgItemInt(hwndDlg, IDC_SUSTID, NULL, false);
			send_resume_cmd(tid);
			return TRUE;
		
		case IDC_MEMMGT:
			// pop-up dlg for memory reading and writing
			if(!memmgtWindow){
				//memmgtWindow = CreateDialog(hModule, MAKEINTRESOURCE(IDD_MEMMGT), consoleWindow, MemMgtDlgProc);
				//ShowWindow(memmgtWindow, SW_SHOW); 
			}
			return TRUE;
		case IDC_BPMGT:
			// pop-up dlg for managing bps on the remote dbg'er
			if(bpmgtWindow == NULL){
				bpmgtWindow = CreateDialog(hModule, MAKEINTRESOURCE(IDD_BPMGT), consoleWindow, BpmgtDlgProc);
				ShowWindow(bpmgtWindow, SW_SHOW);
			}
			return TRUE;
		case IDC_REGMGT:
			// pop-up dlg for managing regs on the remote dbg'er
			if(regsWindow == NULL){
				regsWindow = CreateDialog(hModule, 
                                        MAKEINTRESOURCE(IDD_REGS), 
                                        consoleWindow, 
                                        RegsDlgProc);
				ShowWindow(regsWindow, SW_SHOW); 
			}
			return TRUE;

		}


	}
	return FALSE; 
}



bool do_connect(Dispatcher d) {
   //if we are already connected then do nothing.
   if (is_connected()) return true;
   msg(PLUGIN_NAME": Not connected creating the dialog box\n");
   tempDispatcher = d;
   return DialogBox(hModule, MAKEINTRESOURCE(IDD_CONNECT), mainWindow, ConnectDlgProc) == 1;
}

bool handle_rebas_msg(Buffer &b){

	return true;
}





bool handle_ida_cmd(Buffer &b){
	unsigned int ida_cmd;
	ida_cmd = b.readInt(); // size of the data packet
	if (ida_cmd > IDA_CMD_HANDLER_CNT)
		return true;
	//return true;	
	return (*IDA_HANDLER_ARY[ida_cmd])(b);
}
/*
bool rsp_cmd_handler(Buffer &b){
  	unsigned int cmd;
	cmd = b.readInt(); // size of the data packet
	switch(cmd){
		case GETBPS:
			return ida_recv_get_bps(b);
		case GETREGS:
			return ida_recv_get_regs(b);
		case GETBASE:
			return ida_recv_getbase(b);
		default:
			return false;
	}

}


bool req_cmd_handler(Buffer &b){
  	unsigned int cmd;
	cmd = b.readInt(); // size of the data packet
	switch(cmd){
		case BPHIT:
			return handle_bphit_cmd(b);
		case IDA_CMD:
			return handle_ida_cmd(b);
		default:
			return false;
	}
}
*/

bool msg_dispatcher(Buffer &b) {
	// clone the recv buffer
	unsigned int sz = b.get_wlen()+1;
	Buffer myBuffer(sz);
	myBuffer << b;
	b.reset();
	// TODO: could make this a mt-part to remove load from reciver
	return recv_net_command(myBuffer);
}


void read_lbitems_csv(HWND hwndLB, std::string &out){
	std::stringstream ss;
	unsigned int count = SendMessage(hwndLB, LB_GETCOUNT, 0,0);
	if (count ==0){
		out = "";
		return;
	}
	for (unsigned int idx = 0; idx < count; idx++){
		unsigned int len = SendMessage(hwndLB, LB_GETTEXTLEN, idx,0);
		if (len == LB_ERR)
			continue;
		TCHAR *buffer = (TCHAR *)malloc(sizeof(TCHAR)*(len+1));
		ZeroMemory(buffer, sizeof(TCHAR)*(len+1));
		HRESULT result = SendMessage(hwndLB, LB_GETTEXT, idx,(LPARAM)buffer);
		if (result == LB_ERR){
			free(buffer);
			continue;
		}
		std::string x;
		if(!all_digits_t(buffer)){
			continue;
		}
		convert_tchar_to_addr_s(buffer, x);
		free(buffer);
		ss << x;
		if (idx +1 != count)
			ss << ",";
	}
	out = ss.str();

}

void check_dbger_connection(){
	if(!is_connected()){
		if(consoleWindow)
			SendMessage(consoleWindow, IDC_QUIT, 0,0);
	}

}



void update_lb_from_bps(HWND hwndLB, std::vector<std::string> &bps){
	std::vector<std::string>::iterator iter = bps.begin();
	unsigned int hResult;
	SendMessage(hwndLB,LB_RESETCONTENT,0,0);
	for (; iter != bps.end(); iter++){
		ULONG64 ea = convert_string_to_addr(*iter);
		TCHAR *tmp = convert_addr_to_tchar(ea);
		SendMessage(hwndLB,LB_ADDSTRING,0,(LPARAM) tmp);
		free(tmp);
	}

}

BOOL CALLBACK BpmgtDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam){
	HWND hwndLB = NULL;
	std::string addrs;
	ULONG64 addr_ea;
	TCHAR *str;
	TCHAR value[80]= {0};
	//check_dbger_connection();
	unsigned int current_item = 0,
				 count = 0;
	std::vector<std::string> *bps = NULL;
	switch(message){
		case WM_INITDIALOG:
			//send_get_bps();
			return TRUE;
		case WM_DESTROY:
			bpmgtWindow = NULL;
			return TRUE;
        case WM_COMMAND: 
        switch (LOWORD(wParam)) { 
			case IDCANCEL:	
			case IDC_QUIT:
				DestroyWindow(hwndDlg);
				bpmgtWindow = NULL;
				return TRUE;
			case IDC_ADDBP:
				// if there is a valid address in the box
				// add that to the list box control
				// other wise just return
				// ID_BP is the text box
				// IDC_LBBPPS is the list box
				GetDlgItemText(hwndDlg, IDC_BP,value,80);
				if (_tcslen(value) == 0)
					return TRUE;
				addr_ea = get_addr_value(hwndDlg, IDC_BP);
				str = convert_addr_to_tchar(addr_ea);
				if (str == NULL)
					return TRUE;

				hwndLB = GetDlgItem(hwndDlg,IDC_LBBPS);
				SendMessage(hwndLB, LB_ADDSTRING, 0, (LPARAM) str);
				free(str);
				return TRUE;
			case IDC_REMBP:
				// if there is an address selected in the list box
				// remove it, other wise remove the first address in
				// the box
				hwndLB = GetDlgItem(hwndDlg,IDC_LBBPS);
				if (SendMessage(hwndLB, LB_GETCOUNT, 0,0)==0)
					return TRUE;
				current_item = SendMessage(hwndLB, LB_GETCURSEL, 0,0);
				if (current_item == LB_ERR) current_item = 0;
				// may need to decrement current_item if it is not 0
				SendMessage(hwndLB, LB_DELETESTRING, current_item,0);
				return TRUE;
			case IDC_SETBPS:
				// send a set bps message to the end-point server
				hwndLB = GetDlgItem(hwndDlg,IDC_LBBPS);
				if (SendMessage(hwndLB, LB_GETCOUNT, 0,0)==0)
					return TRUE;
				read_lbitems_csv(hwndLB, addrs);
				// iterate over all the items in the LB
				// convert them to an "A" string
				// add them to a comma separated list
				send_set_bps(addrs);
				return TRUE;
			case IDC_RESETBPS:
				// send a set bps message to the end-point server
				addrs = "";
				// iterate over all the items in the LB
				// convert them to an "A" string
				// add them to a comma separated list
				send_set_bps(addrs);
				return TRUE;
			case IDC_GETBPS:
				// send a get bps message to the endpoint server
				send_get_bps();
				return TRUE;
			case CMD_RES:
				bps = (std::vector<std::string> *)lParam;
				hwndLB = GetDlgItem(hwndDlg,IDC_LBBPS);
				update_lb_from_bps(hwndLB, *bps);
				return true;

		 }


	}
	return FALSE; 

}
ULONG64 convert_tchar_to_addr(TCHAR *value){
	if (!all_digits_t(value)){
		return 0;
	}
	if (value[0] == TEXT('0') && value[1] == TEXT('x') ||
		value[0] == TEXT('0') && value[1] == TEXT('X')){
		return _tcstoui64(value,NULL,16);
	}
	return _tstoi64(value);
	
}
