#include "stdafx.h"


//This file handles hooking and unhooking functions
//all active hooks are saved in a global variable hooktable
//all hooks have their own class, that hooks and unhooks using their constructor and destructor


#define db __asm __emit
//some magic numbers, we can search for them and replace them with working code
#define magic_original __asm {db 0x34 db 0x83 }
#define magic_return __asm {db 0x34 db 0x83 }



struct hookstate {
	DWORD hook_ptr;
	unsigned int nopcount;
	DWORD callback_ptr;
	DWORD ret_ptr;
	char original_opcodes[5];
	//DWORD opcodecopy_ptr; TODO: add possibility to copy in original opcodes into callback function
};

hookstate hooktable[128] = {0};


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


		char buf[5];

		//store the opcodes we will overwrite with jmp
		memcpy(hooktable[i].original_opcodes, (void*)loc, 5);

		//update callback function using:

		//copy bytes loc to loc+5+nopcount

		//return to loc+5+nopcount

		//push hookstate variable onto stack in our callback function
		buf[0] = 0x68; //opcode for farjump
		memcpy(&buf[1], &hooktable[i], 4);
		memcpy(callback, buf, 5);


		//place hook
		buf[0] = 0xEA; //opcode for farjump
		memcpy(&buf[1], &callback, 4);
		memcpy((void*)loc, buf, 5);

	}

	return i;
}

void unhook(DWORD loc) {
}


//---------------------------------------------------------------------------
//start individual hook classes here



__declspec(naked) void callback_sendpacket(volatile hookstate hs)
{
	__asm {
		pushad;
		add esi, 8 * 4;
		pop hs;


		dec esi, 9 * 4
			popad;
		jmp hs.ret_ptr; //return after original jump
	}

}


class hook_sendpacket {
private:
	DWORD hook_location = 0x4751B2; //later on we will work with AOB's

public:

	hook_sendpacket() {
		hook(hook_location, 1, callback_sendpacket, true);
	};

	~hook_sendpacket() {
		unhook(hook_location);
	};


};



