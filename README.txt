README

I. Contributors and Derivations
1) IDA Pro networking and Buffer Messages are borrowed from Collabreate by C. Eagle and T. Vidas
2) WinDbg Networking is based on Bykugan in the Metasploit Project by Lin0XX and Pusscat
3) VDB and Vtrace are a product of Invisigoth tne Kenshoto crew

Thanks to them :)

II. Getting it working

IDA 5.6 or 5.7 is required for this alpha version of the software.   Visual Studio C++ Express 
2010, swig, Python, Windows Debugging Tools, IDA 5.6 (5.7 is not tested yet) and probably something 
else. 

File Structure:

%code_dir%\rebridge\cplusplus_code\idabridge32\<idabridge C++ project to build idabridge for IDA Pro 32-bit>
%code_dir%\rebridge\cplusplus_code\idabridge64\<idabridge C++ project to build idabridge for IDA Pro Advanced>
%code_dir%\rebridge\cplusplus_code\windbg32\<windbg C++ project to build wdbgbridge32 for windbg 32-bit>
%code_dir%\rebridge\cplusplus_code\windbg64\<windbg C++ project to build wdbgbridge64 for windbg 64-bit>
%code_dir%\rebridge\cplusplus_code\idasdk56\<copy contents of idasdk56 into this directory>
%code_dir%\rebridge\cplusplus_code\DebuggerDeps\inc\<copy contents of %Windows Debugging Tools%\sdk\inc here>
%code_dir%\rebridge\cplusplus_code\DebuggerDeps\libx86\<copy contents of %Windows Debugging Tools%\sdk\lib\i386 here>
%code_dir%\rebridge\cplusplus_code\DebuggerDeps\libx64\<copy contents of %Windows Debugging Tools%\sdk\lib\amd64 here>

%code_dir%\rebridge\python_code\idabridge\<contains the code that needs to be copied into %idapro%\python\>




Compile a custom IDA Python module for IDA Pro.  Rebridge use IDAPython as an external library,
so Python can be used from our code.  We chose to go this route, because we wanted to pass values
back and forth from Python after command calls.  These results may be forwarded onto the remote
server if the value represents a Buffer String or just passed and printed to the CLI if the value 
is not a Buffer.

	A. Compiling IDAPython
	Checkout IDAPython from the repo, follow the directions for setting up build environment for
		IDA Python (e.g. copy IDA SDK, install Swig, ), and then copy the IDA Python python.cpp to 
		a back up copy.  After backing that file, copy the rebridge\IdaPython Stuff\python.cpp into 
		the idapython directory, thus overwriting the file.
		

III. IDAbridge component compilation set-up
Depending on the build version, the IDA Pro SDK location may need to be updated.  Currently we have only tested this
on IDA Pro 5.6.  Copy the contents of IDASDK5.6 into the \rebridge\cplusplus_code\idasdk56\.  The project *should* build.

IV. WDbgBridge compilation set-up
Copy the files for DebuggerDeps as described in the File Structure.  

V. Compile and build the components
Compile the components, and they should end up in %code_dir%\rebridge\cplusplus_code\[Release || Debug] depending
on the build configuration settings.

VI. Copy the Files
Copy the idabridge.dll and idapython.dll into the %idapro%\plugins\ directory.
Copy the wdbgbridge.dll %Debugging Tools%\winext\ directory.
Copy the rebridge\python_code\idabridge\ into the %idapro%\python directory.

VII.  Using VDB
The standeard version of VDB or the one included with the software package maybe used.  The VDB package just needs to 
be copied into the idabridge.  To start the debugger, cd into the idabridge directory and type 'python avdb'.  'avdb' 
loads simply loads VDB with vdbbridge.  

To start the server, simply type 'start' and 'stop' will stop the server.  To send a command to vdbbridge, use
'ib' command name and arguments.  Commands are added in vdbbridge.py and vdbhandlers.py contains all the command implementations.

*Basic Architecture Overview*
vdbbridge is the primary network component that will communicate on the network.  Commands are kept in vdbhandlers, and
they are derived from a Handler class in basehandler.  The command handler must implement the following three functions,
cli (command line), req (request message handler), rsp (response message handler), and evt (handle events).

VIII.  Using Windbg
Load the Windbg plugin windbgbridge.dll example: .load c:\rebridge\windbg\windbg_bridge.dll
Start the listener: !dlistener start
Execute commands as desired, for example: !dlistener writemem 0xDEADBEFF "\x42\x42\x42\x42"

VIIII.  Using IDA Pro
Alt-F7 to start the IDA Pro plugin.  In the CLI, type 'start <server> port'.  Execute a command by typing the command and 
arguments into the CLI.

Commands are added in idabridge.py and idahandlers.py contains all the command implementations.


*Basic Architecture Overview*
idabridge is the primary network component that will communicate on the network.  Commands are kept in idahandlers, and
they are derived from a Handler class in basehandler.  The command handler must implement the following three functions,
cli (command line), req (request message handler), rsp (response message handler), and evt (handle events).

The plugin functionality works in the following manner.  The plugin loads a custom version of IDAPython, and this will be 
used to persist the command environment in Python.  When a command is entered into the cli, the command is checked to see 
if whether or not it is handled in the C/C++.  If the command is not handled in C/C++, the command and arguments are 
assigned in the Python Environment, and the idabridge.handle_cli is called with the arguments assigned in Python. 

When the idabridge.handle_cli will return a <BUFFER>string or a string.  If the return value is <BUFFER> the command handler
will send the BUFFER out on the socket.


