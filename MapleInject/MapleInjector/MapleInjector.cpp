// MapleInjector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <cwctype>
#include <thread>
#include <string>
#include "MapleInjector.h"

//#define MODULE_NAME L"MapleInject.dll"
//#define MODULE_INIT "Initialize"
//#define MODULE_UNLOAD "Unload"
//#define EXEC_NAME	"MapleSaga.exe"

std::thread mt;
std::thread updatethread;

std::wstring module_working_path(L"<auto>");
std::string updating_status("");
std::string functname_init("Initialize");
std::string functname_unload("Unload");
std::string target_executable("MapleSaga.exe");
std::wstring injected_dll(L"MapleInject.dll");

std::string thread_message("");

bool auto_update = true;
bool running = false;

ULONGLONG dll_last_updatetime = MAXULONGLONG; //prevent an update when dll version is first loaded and compared to last_version






//static console header
void refreshconsole() {
	system("cls");
	std::cout << "Welcome to MapleStory autoinjector!\n";
	std::cout << "Please use this application in the release folder of your payload dll.\n";
	std::cout << "-----------------------------------------------\n";
	std::cout << "You can use the following commands: exit, forceupdate, autoupdate\n\n";
	std::cout << "Main thread:\t" << (running ? "running" : "off") << "\n";
	std::cout << "Last message:\t" << thread_message.c_str() << "\n";
	std::cout << "Update status:\t" << ((updating_status.length() > 0) ? updating_status.c_str() : (auto_update ? "<auto=on>" : "<auto=off>")) << "\n";
	std::cout << "Dll time:\t" << dll_last_updatetime << "\n";
	std::cout << "Payload:\t"; std::wcout << injected_dll.c_str() << "\n";
	std::cout << "Destination:\t"; std::wcout << module_working_path.c_str() << "\n";
	std::cout << "-----------------------------------------------\n";
	std::cout << "> ";


}



//Enables debug privileges.
void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}


//All data our injected function uses will be
//put inside the following struct and
//copied into memory.
//Because the compiler creates its own call table
//for dll functions, no functions work
//when injected. We combat this by
//finding the function pointer and passing it
//to our injected function by this struct.
typedef HMODULE (__stdcall *FUNCT_LL)(LPCWSTR);
typedef FARPROC (__stdcall *FUNCT_GPA)(HMODULE, LPCSTR);
typedef BOOL (__stdcall *FUNCT_FL)(HMODULE);

struct injectiondata {
	FUNCT_LL LoadLibrary;
	FUNCT_LL GetModuleHandle;
	FUNCT_GPA GetProcAddress;
	FUNCT_FL FreeLibrary;
	wchar_t path[MAX_PATH];
	char name_initialize[32];
	char name_unload[32];
};



//These functions will get injected into another program
//C will work fine as long as we:
//	Use pure C
//	Don't use statically allocated variables(use volatile all the time)
//	May not work when too many volatile variables are used at once(register overload)
//	Don't use literal strings/arrays/whatever, numbers might be ok
//To make more complicated injectable functions possible we:
//	Pass all data through our injectiondata struct
//	Pass all kernel32.dll exported function pointers through our injectiondata struct
//    (kernel32.dll resides in a static location in memory even cross-process.
//  Get pointers to functions of other libraries by using the kernel32.dll function GetProcAddress
//  in combination with LoadLibraryW(to get a module handle by loading it)
//  or GetModuleHandleW(to get a module handle by searching for it)

extern "C" __declspec(dllexport) void injected_dll_loader(injectiondata *data){ //(char *path) {
	//Load dll using User32 function LoadLibrary
	volatile HMODULE mylib;
	mylib = data->LoadLibraryW(data->path);

	if (mylib == NULL) {
		return;
	}
	
	//Find Initialization function
	typedef void * (__stdcall *STDCALL_VOID)();

	volatile STDCALL_VOID initialize = (STDCALL_VOID)data->GetProcAddress(mylib, data->name_initialize);
	
	
	if (initialize == NULL) {
		data->FreeLibrary(mylib);
		return;
	}

	//Call Initialization function
	initialize();
}


extern "C" __declspec(dllexport) void injected_dll_unloader(injectiondata *data) { //(char *path) {
																				 //Load dll using User32 function LoadLibrary
	//Find handle to payload dll
	volatile HMODULE mylib;
	mylib = data->GetModuleHandleW(data->path);


	
	if (mylib == NULL) {
		return;
	}

	//Find Unload function using
	typedef void * (__stdcall *STDCALL_VOID)();

	volatile STDCALL_VOID unload = (STDCALL_VOID)data->GetProcAddress(mylib, data->name_unload);


	if (unload == NULL) {
		data->FreeLibrary(mylib);
		return;
	}
	
	//Call Initialization function
	unload();
}



//this function injects a function to be run into a process
void InjectInto(DWORD pId, LPCVOID funct ) {
	//Fill struct with data the injection function will need
	//this will be placed in memory.
	injectiondata mydata = injectiondata();
	wcscpy_s(mydata.path, injected_dll.c_str());
	strcpy_s(mydata.name_initialize, functname_init.c_str());
	strcpy_s(mydata.name_unload, functname_unload.c_str());
	mydata.LoadLibraryW = (FUNCT_LL)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	mydata.GetProcAddress = (FUNCT_GPA)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetProcAddress");
	mydata.FreeLibrary = (FUNCT_FL)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	mydata.GetModuleHandleW = (FUNCT_LL)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetModuleHandleW");

	//Open maplesaga for access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);


	if (hProcess != NULL) {
		//get full path so we know where to copy the dll in the future
		//Allocate some memory to work with and
		//write our function + data to it
		void* pLibRemote = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, pLibRemote, funct, 1024, NULL);

		void* pLibData = VirtualAllocEx(hProcess, NULL, sizeof(injectiondata), MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, pLibData, &mydata, 1024, NULL);

		//Run function inside maplesaga using a pointer to the data
		//we wrote as argument
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLibRemote, pLibData, 0, NULL);

		//Wait for function to exit
		WaitForSingleObject(hThread, 10000);


		//Check errors
		DWORD hLibModule;
		GetExitCodeThread(hThread, &hLibModule);

		//Close thread handle
		CloseHandle(hThread);

		//Clear memory
		VirtualFreeEx(hProcess, pLibRemote, 1024, MEM_RELEASE);
		VirtualFreeEx(hProcess, pLibData, 1024, MEM_RELEASE);

		//Close process handle
		CloseHandle(hProcess);
	}
}

//this function loops through all loaded modules
//in a process to check if our payload is already loaded
//this is used to prevent double loading
//and unloading when the payload isn't loaded.
bool IsInjected(DWORD dwPID) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return(false);
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return(false);
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		std::wstring s(me32.szExePath);

		if (s.compare(s.length() - 15, 15, injected_dll) == 0) {
			return true;
		}

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(false);
}


//this function loops through all processes
//and looks for the executable we want to inject into.
//when found, injects or unloads
//and also checks the executable path but only when
//module_working_path is set to <auto>

void inject_all(bool injecting, bool immediate) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			wchar_t te[MAX_PATH];
			std::mbstowcs(te, target_executable.c_str(), MAX_PATH);
			if (_tcsicmp(entry.szExeFile, te) == 0)
			{
				//Now entry is the object for the executable we are looking for

				//First if our module path is set to <auto>, we want to retrieve it from this executable
				if (module_working_path.compare(L"<auto>") == 0) {
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

					if (hProcess != NULL) {

						LPWSTR path = new WCHAR[MAX_PATH];
						DWORD sz = MAX_PATH;
						QueryFullProcessImageName(hProcess, 0, path, &sz);

						module_working_path = path;
						module_working_path = module_working_path.substr(0, module_working_path.find_last_of('\\'));
						module_working_path = module_working_path.append(L"\\");
						module_working_path = module_working_path.append(injected_dll);

						CloseHandle(hProcess);
					}
				}

				//Next we can try to inject or unload dll's
				if (injecting) {
					if (!IsInjected(entry.th32ProcessID)) {
						if (!immediate) {
							Sleep(1000);
						}
						InjectInto(entry.th32ProcessID, &injected_dll_loader);
						while (!IsInjected(entry.th32ProcessID)) {
							//TODO: count amount of time waiting
							//if >10 seconds, kill maplestory.
							Sleep(500);
						}
						thread_message = "injected process " + std::to_string(entry.th32ProcessID);

						refreshconsole();
					}
				} else {
					//Unloading
					if (IsInjected(entry.th32ProcessID)) {
						InjectInto(entry.th32ProcessID, &injected_dll_unloader);
						while (IsInjected(entry.th32ProcessID)) {
							//TODO: count amount of time waiting
							//if >10 seconds, kill maplestory.
							Sleep(500);
						}
						thread_message = "unloaded process " + std::to_string(entry.th32ProcessID);
						refreshconsole();
					}
				}
			}
		}
	}

	CloseHandle(snapshot);
}



void dll_update_sequence() {
	updating_status = "Killing threads...";
	refreshconsole();

	//kill thread
	loop_stop();

	updating_status = "Unloading dll's...";
	refreshconsole();

	//unload all dll's otherwise we can't overwrite the loaded dll
	inject_all(false, true);


	updating_status = "Copying dll files...";
	refreshconsole();

	bool success = CopyFile(injected_dll.c_str(), module_working_path.c_str(), false);


	updating_status = (success ? "Copying success, " : "Copying failure, ") + std::string("Starting main thread...");
	refreshconsole();

	//now start the main thread again
	loop_start();

	updating_status = "";
	refreshconsole();
}


//This function checks the filetime of our
//payload dll and compares it to the
//last time it checked, calls
//the update function when a newer dll version
//is available.
bool check_new_dll_available() {
	if (module_working_path.length() > 0) {
		char dllpath[MAX_PATH];
		std::wcstombs(dllpath, injected_dll.c_str(), MAX_PATH);


		OFSTRUCT buf;
		HFILE hFile = OpenFile(dllpath, &buf, OF_READWRITE);


		if (hFile == HFILE_ERROR) {
			//errors out when another
			//program is writing to our dll
			//we can just ignore this
			//TODO: show message in console
			//that error accessing file occured
		}else if (hFile != NULL) {
			FILETIME ret;
			GetFileTime((HANDLE)hFile, 0, 0, &ret);

			ULONGLONG ftime;
			ftime = ((((ULONGLONG)ret.dwHighDateTime) << 32) + ret.dwLowDateTime);


			if (dll_last_updatetime < ftime) {
				//not really nice, we create a thread but lose track of it
				//this is the easiest method though, don't expect too many problems.
				//if we directly call dll_update_sequence
				//our program will crash because that function will try
				//to .join() the thread we're running on, which is impossible.
				if (updatethread.joinable()) {
					updatethread.join();
					updatethread.~thread();
				}
				updatethread = std::thread(dll_update_sequence);

			}

			if (dll_last_updatetime != ftime) {
				dll_last_updatetime = ftime;
				refreshconsole();
			}

			CloseHandle((HANDLE)hFile);
		}
	}
	return false;
}


//main loop runs in a seperate thread
//so we can accept input from the user
//while we do stuff
void loop() {
	//loop through all open processes to find maplesaga
	while (running) {
		inject_all(true, false);
		Sleep(500);
		if (auto_update) {
			check_new_dll_available();
		}
	}
}

void loop_start() {
	if (!running) {
		running = true;
		mt = std::thread(loop);
	}
}

void loop_stop() {
	running = false;
	if (mt.joinable()) {
		mt.join();
		mt.~thread();
	}
}


int main()
{
	
	//Enables debug privileges
	EnableDebugPriv();
 

	loop_start();

	std::string input;

	refreshconsole();

	while (true) {
		std::getline(std::cin, input); 
		if (input.compare("exit") == 0) {
			running = false;
			thread_message = "Aborting all operations...";
			refreshconsole();
			loop_stop();
			break;
		} else if (input.compare("autoupdate") == 0) {
			auto_update = !auto_update;
			refreshconsole();
		} else if (input.compare("forceupdate") == 0) {
			dll_update_sequence();
		}
	}


	return 0;

}

