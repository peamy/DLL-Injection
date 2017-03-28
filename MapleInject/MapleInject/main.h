#pragma once


extern HMODULE this_hmodule;
extern DWORD this_threadid;
extern bool running;


void Main();
extern "C" __declspec(dllexport) void Initialize();
extern "C" __declspec(dllexport) void Unload();
BOOL WINAPI CtrlHandler(DWORD dwType);