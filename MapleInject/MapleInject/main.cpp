// MapleInject.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "main.h"


//Call this function to start running the dll main function
extern "C" __declspec(dllexport) void Initialize()
{
	//Try open console window
	if (!AllocConsole())
		MessageBox(NULL, L"Error creating console window", NULL, MB_ICONEXCLAMATION);

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
	//Hide console window
	FreeConsole();

	//Give running threads a way to know we are unloading
	running = false;

	//Exit current thread and unload dll
	FreeLibraryAndExitThread(this_hmodule, 0);
}





void Main() {
	std::string input;

	std::cout << "Welcome to MapleInject!\n";
	std::cout << "exit\tUnload dll from memory\n";
	std::cout << "------------------------------\n";

	while (true) {
		std::cout << "> ";
		getline(std::cin, input);
		if (input.compare("exit") == 0) {
			std::cout << "Unloading dll now.....\n";
			Unload();
		}
	}
}

