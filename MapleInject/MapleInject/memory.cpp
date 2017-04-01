#include "stdafx.h"
#include "memory.h"


Locator::Locator(char * loc_str) : locstr("") {
	locstr.append(loc_str);
}

bool Locator::Resolve() {
	//TODO:
	//this function should be able to resolve complex
	//string patterns safely into a pointer
	//and return false, set Address to zero when it fails
	//Examples:
	// 4F89C724 <- should be parsed as a number
	// [4F89C724] <- should dereference 4F89C724 and return the DWORD at that location in memory
	// AOB("4F 89 C7 3D 24 7B 29 A9 ??") <- should search entire memory for AOB taking care of wildcards
	// FUNCT("Kernel32.dll", "LoadLibraryW") <- should return the pointer to LoadLibraryW inside of Kernel32.dll
	// LIB("MapleSaga.exe") <- should return the base address pointer of the library
	//
	// Combinations should be possible, for example:
	// [[4F89C724]+[83AA9B3F]*4]
	// [[AOB("4F 89 C7 3D 24 7B 29 A9 ??")+4]+16]
	// FUNCT("Kernel32.dll", "LoadLibraryW")
	// [LIB("MapleSaga.exe")+387473]
	// [LIB("MapleSaga.exe")+0x100]

	std::string temp;
	temp = "0x" + locstr;
	Address = strtol(temp.c_str(), 0, 0);
	return true;
}

