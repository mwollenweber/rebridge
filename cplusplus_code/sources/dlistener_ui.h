#ifndef __DLISTENER_UI_H
#define __DLISTENER_UI_H

#include "dlistener_ida.h"
#include "resource.h"
#include "idanet.hpp"


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


#define PLUGIN_NAME "dlistener"
// I get it dont use dangerous funcs
// tchar.h is the culprit for this
// define
#define USE_DANGEROUS_FUNCTIONS


extern volatile HWND mainWindow;
extern volatile HMODULE hModule;


extern volatile HWND regsWindow;// = NULL;
extern volatile HWND consoleWindow;// = NULL;
extern volatile HWND memmgtWindow;// = NULL;
extern volatile HWND bpmgtWindow;// = NULL;

bool rsp_cmd_handler(Buffer &b);
bool req_cmd_handler(Buffer &b);

void check_dbger_connection();
std::string* get_convert_dlg_str(HWND dlg, int dlgItem);
ULONG64 get_addr_value(HWND dlg, int dlgItem);
bool get_addr_value_s(HWND dlg, int dlgItem, std::string &value);

bool set_addr_value_s(HWND dlg, int dlgItem, std::string &value);
bool set_addr_value_ea(HWND dlg, int dlgItem,ULONG64 value);





BOOL CALLBACK RegsDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);
void update_dlg_from_register_values();
void update_register_values_from_dlg(HWND hwndDlg, std::string &out);
void update_lb_from_bps(HWND hwndDlg, std::vector<std::string> &bps);


BOOL CALLBACK ConnectDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);
bool msg_dispatcher(Buffer &);
bool do_connect(Dispatcher d);
bool cmd_handler(Buffer &b);
bool handle_ida_cmd(Buffer &b);
bool handle_bphit_cmd(Buffer &b);

BOOL CALLBACK DbgDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK BpmgtDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);
TCHAR *convert_string_to_tchar(std::string & c);
TCHAR *convert_addr_to_tchar(ULONG64 addr_ea);
void convert_tchar_to_add_s(TCHAR *value);
ULONG64 convert_tchar_to_addr(TCHAR *value);
bool all_digits_t(TCHAR *value);


//BOOL CALLBACK SelectCmdProc(UINT message, WPARAM wParam, LPARAM lParam);
//BOOL CALLBACK DlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);
//LRESULT EditSubclassProc(HWND, UINT, WPARAM, LPARAM);
#endif