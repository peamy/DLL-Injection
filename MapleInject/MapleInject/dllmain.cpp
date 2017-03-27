// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "stdio.h"
#include "windows.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	FILE *file;
	fopen_s(&file, "C:\\temp.txt", "a+");

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		fprintf(file, "DLL attach function called.\n");
		break;
	case DLL_PROCESS_DETACH:
		fprintf(file, "DLL detach function called.\n");
		break;
	case DLL_THREAD_ATTACH:
		fprintf(file, "DLL thread attach function called.\n");
		break;
	case DLL_THREAD_DETACH:
		fprintf(file, "DLL thread detach function called.\n");
		break;
	}

	/* close file */
	fclose(file);
	return TRUE;
}


