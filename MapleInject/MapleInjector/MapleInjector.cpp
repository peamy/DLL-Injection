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

#define MODULE_NAME L"MapleInject.dll"
#define MODULE_NAME_s "MapleInject.dll"
#define MODULE_INIT "Initialize"
#define MODULE_UNLOAD "Unload"
#define EXEC_NAME	"MapleSaga.exe"

std::wstring module_working_path(L"");


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


//This function will get injected into another program
//C will work fine as long as we:
//	Use pure C
//	Don't use statically allocated variables(use volatile all the time)
//	May not work when too many volatile variables are used at once(register overload)
//	Don't use literal strings/arrays/whatever, numbers might be ok
//	  pass all data through our injectiondata struct

extern "C" __declspec(dllexport) void injected_dll_loader(injectiondata *data){ //(char *path) {
	//Load dll using User32 function LoadLibrary
	volatile HMODULE mylib;
	mylib = data->LoadLibraryW(data->path);


	if (mylib == NULL) {
		return;
	}
	
	//Find Initialization function using User32 function GetProcAddress
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
	volatile HMODULE mylib;
	mylib = data->GetModuleHandleW(data->path);


	
	if (mylib == NULL) {
		return;
	}

	//Find Initialization function using User32 function GetProcAddress
	typedef void * (__stdcall *STDCALL_VOID)();

	volatile STDCALL_VOID unload = (STDCALL_VOID)data->GetProcAddress(mylib, data->name_unload);


	if (unload == NULL) {
		data->FreeLibrary(mylib);
		return;
	}
	
	//Call Initialization function
	unload();
}




void InjectInto(DWORD pId, LPCVOID funct ) {
	//Fill struct with data the injection function will need
	//this will be placed in memory.
	injectiondata mydata = injectiondata();
	wcscpy_s(mydata.path, MODULE_NAME);
	strcpy_s(mydata.name_initialize, MODULE_INIT);
	strcpy_s(mydata.name_unload, MODULE_UNLOAD);
	mydata.LoadLibraryW = (FUNCT_LL)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	mydata.GetProcAddress = (FUNCT_GPA)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetProcAddress");
	mydata.FreeLibrary = (FUNCT_FL)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	mydata.GetModuleHandleW = (FUNCT_LL)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetModuleHandleW");

	//Open maplesaga for access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);


	if (hProcess != NULL) {
		//get full path so we know where to copy the dll in the future
		LPWSTR path = new WCHAR[MAX_PATH];
		DWORD sz = MAX_PATH;
		QueryFullProcessImageName(hProcess, 0, path, &sz);

		module_working_path = path;
		module_working_path = module_working_path.substr(0, module_working_path.find_last_of('\\'));
		module_working_path = module_working_path.append(L"\\");
		module_working_path = module_working_path.append(MODULE_NAME);

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

		if (s.compare(s.length() - 15, 15, MODULE_NAME) == 0) {
			return true;
		}

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(false);
}



void inject_all(bool injecting) {
	bool didsomething = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_tcsicmp(entry.szExeFile, _T(EXEC_NAME)) == 0)
			{
				if (injecting) {
					if (!IsInjected(entry.th32ProcessID)) {
						std::cout << "Injecting into " << entry.th32ProcessID << "!\n";
						InjectInto(entry.th32ProcessID, &injected_dll_loader);
						didsomething = true;
					}
				} else {
					if (IsInjected(entry.th32ProcessID)) {
						std::cout << "Injecting into " << entry.th32ProcessID << "!\n";
						InjectInto(entry.th32ProcessID, &injected_dll_unloader);
						didsomething = true;
					}
				}
			}
		}
	}

	CloseHandle(snapshot);
	if (didsomething) {
		Sleep(3000);
	}
}

bool is_new_dll_available() {
	if (module_working_path.length() > 0) {
			char newpath[255];
			std::wcstombs(newpath, module_working_path.c_str(), 255);

			//TODO: compare filetime of "MODULE_NAME" and "newpath"
			//return true if different.
	}
	return false;
}


bool running;
void loop() {
	//loop through all open processes to find maplesaga
	while (running) {
		inject_all(true);
		Sleep(500);
	}
}


int main()
{
	std::cout << "Welcome to MapleStory autoinjector!\n";

	//Enables debug privileges
	EnableDebugPriv();
 
	running = true;

	std::thread mt(loop);
	std::string input;

	while (true) {
		std::cout << "> ";
		std::getline(std::cin, input); //freezes, but passes when console window is freed.
		if (input.compare("exit") == 0) {
			running = false;
			break;
		}
		else if (input.compare("update") == 0) {
			//kill thread
			running = false;
			mt.join();
			mt.~thread();

			std::cout << "Killed threads!\n";
			
			//unload all dll's otherwise we can't overwrite the loaded dll
			inject_all(false);
			std::cout << "Unloaded all!\n";


			std::wcout << L"Copying \"" << MODULE_NAME << L"\" to \"" << module_working_path.c_str() << L"\"\n";

			//wait a moment before copying, so we are sure everything is unloaded
			Sleep(2000);
			CopyFile(MODULE_NAME, module_working_path.c_str(), false);


			std::cout << "Copied files!\n";

			//now start the main thread again
			running = true;
			mt = std::thread(loop);
			std::cout << "Starting threads again!\n";
		}
	}

	mt.join();


	std::cout << "Press any key to continue...";
	std::cin.get();
	return 0;

}

