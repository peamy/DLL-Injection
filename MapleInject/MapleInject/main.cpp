// MapleInject.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "main.h"
#include "hooks.h"


//Call this function to start running the dll main function
extern "C" __declspec(dllexport) void Initialize()
{
	//Try open console window
	if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
		if (!AllocConsole()) {
			//failed to create console window...
		}
	}

	SetConsoleTitle(L"MapleInject");

	//Connect stdin, stdout and stderr to the new console window
	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	freopen_s(&fp, "CONIN$", "r", stdin);
	freopen_s(&fp, "CONERR$", "w", stderr);

	//Clear console window
	std::cout.clear();

	//Start main thread
	running = true;
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Main, 0, 0, &this_threadid);
}


//Call this function to unload this dll from memory
extern "C" __declspec(dllexport) void Unload()
{
	running = false;

	//Hide console window
	FreeConsole();
}




void Main() {
	std::string input;

	//std::cout << "Waiting 5 seconds...\n";
	//Sleep(200);
	//std::cout << "Loading hooks...\n";
	//Sleep(2000);
	HookLoader hl;

	//std::cout << "Hooks loaded!\n";
	std::cout << "Welcome to MapleInject!\n";
	std::cout << "unload\tUnload dll from memory\n";
	std::cout << "------------------------------\n";

	//Don't put freezing code in this loop that doesn't check for running==true
	while (running) {
		std::cout << "> ";
		getline(std::cin, input); //freezes, but passes when console window is freed.
		if (input.compare("unload") == 0) {
			std::cout << "Unloading dll now.....\n";
			Unload();
		} 

	}

	hl.Unload();

	//Finished, unload dll
	FreeLibraryAndExitThread(this_hmodule, 0);
}

