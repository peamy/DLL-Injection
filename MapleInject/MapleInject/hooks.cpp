#include "stdafx.h"
#include "hooks.h"

//This file handles hooking and unhooking functions
//all active hooks are saved in a global variable hooktable
//all hooks have their own class, that hooks and unhooks using their constructor and destructor


//magic numbers are used to find pieces
//of asm code we want to modify while running
#define db __asm __emit

#define MAGNUM_LENGTH 8

#define magic_return_jump __asm{db 0x70 db 0x61 db 0xAF db 0x55 db 0x84 db 0x79 db 0x96 db 0x73}

static char magnum_return_jump[MAGNUM_LENGTH] = { 0x70, 0x61, 0xAF, 0x55, 0x84, 0x79, 0x96, 0x73 };


struct hookstate {
	DWORD ret_ptr;
	DWORD hook_ptr;
	unsigned int nopcount;
	DWORD callback_ptr;
	char original_opcodes[5];
};

hookstate hooktable[128] = {0};


DWORD find_magic(char* loc, char* magic_number, int max_offset) {
	int j = 0;
	for (int i = 0; i < max_offset; i++) {
		if (loc[i] == magic_number[j]) {
			j++;
		}
		else {
			j = 0;
		}
		if (j == MAGNUM_LENGTH) {
			return (DWORD)loc + (i - j) + 1;
		}
	}

}



//our hook function
int hook(DWORD loc, DWORD ret, VOID *callback, bool copyopcodes) {
	int i = -1;
	
	//find empty hooktable
	for (int j = 0; j <= 127; i++) {
		if (hooktable[j].hook_ptr == NULL) {
			i = j;
			break;
		}
	}
	
	if (i > -1) {

		hooktable[i].hook_ptr = loc;
		hooktable[i].callback_ptr = (DWORD)callback;
		hooktable[i].ret_ptr = ret;


		unsigned char buf[16] = { 0 };
		DWORD temp1;
		DWORD temp2;
		DWORD dwProtect;

		//store the opcodes we will overwrite with jmp
		memcpy(hooktable[i].original_opcodes, (void*)loc, 5);



		//search for magic jump
		memset(buf, 0x90, MAGNUM_LENGTH); //fill whole buffer with nops
		buf[0] = 0xE9; //opcode for farjump
		temp1 = find_magic((char *)callback, magnum_return_jump, 512); //find magic position in callbackfunction where we want to insert magic return
		temp2 = (DWORD)ret - temp1 - 5; //calculate jump distance
		memcpy(&buf[1], &temp2, 4); //copy into buffer

		//write jump command into magic jump position
		VirtualProtect(callback, MAGNUM_LENGTH, PAGE_EXECUTE_READWRITE, &dwProtect);
		memcpy((void *)temp1, buf, 5); //copy into callback function
		VirtualProtect(callback, MAGNUM_LENGTH, dwProtect, &dwProtect);

		
		std::cout << "\n";
		std::cout << "loc=";
		std::cout << (DWORD)loc << "\n";
		std::cout << "callback=";
		std::cout << (DWORD)callback << "\n";
		std::cout << "magnum=";
		std::cout << (DWORD)temp1 << "\n";


		//place hook
		buf[0] = 0xE9; //opcode for farjump
		temp1 = (DWORD)callback - (DWORD)loc -5;
		memcpy(&buf[1], &temp1, 4);

		VirtualProtect((void*)loc, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
		memcpy((void*)loc, buf, 5);
		VirtualProtect((void*)loc, 5, dwProtect, &dwProtect);

	}

	
	return i;
}

void unhook(DWORD loc) {
}


//--------------------------------------------------------


void __stdcall filter_sendpacket(unsigned char* packet) {
	std::cout << "> " << +packet[0] << ", " << +packet[1] << ", " << +packet[2] << ", " << +packet[3] << "\n";
}

__declspec(naked) void callback_sendpacket()
{
	__asm {
		pushad;
		nop;
		nop;
		nop;
		mov eax, esp;
		add eax, 0x14;
		push eax;
		call filter_sendpacket
		popad;
		mov eax, 0x00896984;
		magic_return_jump;
	}

}





//------------------------------------------------------------------------
void LoadHooks() {
	hook(0x4751B2, 0x4751B2+5, callback_sendpacket, true);
}

void UnloadHooks() {

}