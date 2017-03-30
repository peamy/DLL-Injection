#include "stdafx.h"


//This file will contain functions to translate
//strings into pointers to addresses

//Examples:
// [[AOB("4F 89 C7 3D 24 7B 29 A9 ??")+4]+16]
// FUNCT("Kernel32.dll", "LoadLibraryW")
// [LIB("MapleSaga.exe")+387473]
// [LIB("MapleSaga.exe")+0x100]

//send packets: 4751B2, AOB("B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 53 56 8B F1 8D 5E ??")
//send packets ? : 45DB2F
//recv packets : 60124E, AOB("?? ?? ?? ?? ?? 00 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 0C 53 56 57 33 FF 8B F1")


class WildPointer{
private:
	char arg[256];
	void *ptr;

public:
	WildPointer(char *arg) {

	}

	bool dereference() {
		return false;
	}

	void *get_pointer() {

	}
};