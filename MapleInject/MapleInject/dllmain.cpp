// dllmain.cpp : Defines the entry point for the DLL application.


#include "stdafx.h"
#include "main.h"



HMODULE this_hmodule; //preserve our handle to our dll, we use this for unloading
DWORD this_threadid; //preserve our main thread handle
bool running; //used by main thread to check if we are still in business


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	if (hModule != 0) {
		this_hmodule = hModule;
	}
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//Prevent DLL_THREAD_ATTACH and DLL_THREAD_DETACH to our dll,
		//this enables unloading this dll.
		DisableThreadLibraryCalls(this_hmodule);
		break;
	case DLL_PROCESS_DETACH:
		running = false; //make threads stop.
		break;
	}

	return TRUE;
}




