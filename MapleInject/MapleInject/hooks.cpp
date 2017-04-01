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
	//DWORD ret_ptr;
	DWORD hook_ptr;
	//unsigned int nopcount;
	//DWORD callback_ptr;
	unsigned char original_opcodes[5];
	DWORD magnum_return;
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
	return 0;
}

void couthex(void * loc, unsigned int size) {
	char hex[17] = "0123456789ABCDEF";

	for (int i = 0; i < size; i++) {
		std::cout << hex[((unsigned char *)loc)[i] / 16];
		std::cout << hex[((unsigned char *)loc)[i] & 0x0F];
		std::cout << " ";
	}
}





//our hook function
int hook(DWORD loc, DWORD ret, VOID *callback, bool copyopcodes) {
	int i = -1;
	
	//find empty hooktable
	for (int j = 0; j <= 127; j++) {
		if (hooktable[j].hook_ptr == NULL) {
			i = j;
			break;
		}
	}
	
	if (i > -1) {

		hooktable[i].hook_ptr = loc;
		//hooktable[i].callback_ptr = (DWORD)callback;
		//hooktable[i].ret_ptr = ret;


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
		hooktable[i].magnum_return = (DWORD)temp1;
		if (temp1 != NULL) {
			temp2 = (DWORD)ret - temp1 - 5; //calculate jump distance
			memcpy(&buf[1], &temp2, 4); //copy into buffer

			//write jump command into magic jump position
			VirtualProtect(callback, MAGNUM_LENGTH, PAGE_EXECUTE_READWRITE, &dwProtect);
			memcpy((void *)temp1, buf, 5); //copy into callback function
			VirtualProtect(callback, MAGNUM_LENGTH, dwProtect, &dwProtect);
		}
		
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

bool unhook(DWORD loc) {
	int i = -1;

	for (int j = 0; j <= 127; j++) {
		if (hooktable[j].hook_ptr == loc) {
			i = j;
			break;
		}
	}

	if (i == -1) {
		return false;
	}


	DWORD dwProtect;

	VirtualProtect((void*)loc, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
	memcpy((void*)loc, hooktable[i].original_opcodes, 5);
	VirtualProtect((void*)loc, 5, dwProtect, &dwProtect);

	Sleep(20); //thread may still execute inside our hook function

	//restore magic number 
	if (hooktable[i].magnum_return != NULL) {
		VirtualProtect((void*)hooktable[i].magnum_return, MAGNUM_LENGTH, PAGE_EXECUTE_READWRITE, &dwProtect);
		memcpy((void *)hooktable[i].magnum_return, magnum_return_jump, MAGNUM_LENGTH);
		VirtualProtect((void*)hooktable[i].magnum_return, MAGNUM_LENGTH, dwProtect, &dwProtect);
	}

	hooktable[i].hook_ptr = 0;

}


//--------------------------------------------------------


void __stdcall filter_sendpacket(unsigned int size, unsigned char *packet) {
	unsigned short cmd;
	cmd = *(unsigned short *)packet;
	cmd = _byteswap_ushort(cmd);

	switch (cmd) {
	case 0x2E00:
		std::cout << "> Send chatmessage: ";
		std::cout << (packet + 4); //hackish method to print message out
		std::cout << "\n";
		break; 
	case 0x6C00:
		std::cout << "> Whisper to: ";
		std::cout << (packet + 5); //hackish method to print message out
		std::cout << "\n";
		break;
	case 0x5000: 
		std::cout << "> Use ability point\n";
		break;
	case 0x0100:
		std::cout << "> Login(username, password, somedata)\n";
		break;
	case 0x5200:
		std::cout << "> Use skill point\n";
		break;
	case 0x5900:
		std::cout << "> View other player's profile\n";
		break;
	case 0x5D00:
		std::cout << "> Local teleport\n";
		break;
	case 0x7B00:
		std::cout << "> Open pet inventory\n";
		break;
	case 0x2300:
		std::cout << "> Map teleport(inside free market)\n";
		break;
	case 0x2600:
		std::cout << "> Update player position/state\n";
		break;
	case 0x2700:
		std::cout << "> Leave chair(relaxer)\n";
		break;
	case 0x2800:
		std::cout << "> Sit on chair(relaxer)\n";
		break;
	case 0x2900:
		std::cout << "> Attack/skill\n";
		break;
	case 0x3000:
		std::cout << "> Send emotion\n";
		break;
	case 0x3600:
		std::cout << "> Open NPC menu\n";
		break;
	case 0x3800:
		std::cout << "> Choose NPC menu option\n";
		break;
	case 0x3A00:
		std::cout << "> Move items/money using banker NPC\n";
		break;
	case 0x4200:
		std::cout << "> Move/equip/drop item\n";
		break;
	case 0x4300:
		std::cout << "> Use item(e.g. potions)\n";
		break;
	case 0x5600:
		std::cout << "> Drop money\n";
		break;
	case 0x6F00:
		std::cout << "> Playerstore->\n";
		break;
	case 0xA600:
		//std::cout << "> Keepalive\n";
		break;
	case 0xAB00:
		std::cout << "> Pickup item\n";
		break;
	case 0xC000:
		std::cout << "> Confirm map is loaded\n";
		break;
	case 0x9D00:
		//too much noise when we print this
		//std::cout << "> Update enemy position?\n";
		break;
	case 0x0600:
		std::cout << "> Server select\n";
		break;
	case 0x0500:
		std::cout << "> Channel select\n";
		break; 
	case 0x0B00:
		std::cout << "> Request channel info\n";
		break;

	case 0x2400:
		std::cout << "> Change channel\n";
		break;
	case 0x1800:
		std::cout << "> Pong(loginscreen)\n";
		break;
	case 0x1500:
		std::cout << "> Check name available\n";
		break;
	case 0x1600:
		std::cout << "> Create character\n";
		break;
	case 0x1700:
		std::cout << "> Delete character\n";
		break;
	case 0x1C00:
		std::cout << "> Quit game\n";
		break;

	default:
		std::cout << "> ";
		couthex(packet, size);
		std::cout << "\n";
	}
}

void __stdcall filter_recvpacket(unsigned int size, unsigned char *packet) {
	//unsigned short cmd;
	//cmd = *(unsigned short *)packet;
	//cmd = _byteswap_ushort(cmd);
	unsigned short cmd;
	cmd = *(unsigned short *)packet;
	cmd = _byteswap_ushort(cmd);

	switch (cmd) {
	case 0x0000:
		std::cout << "< Login response\n";
		break;
	case 0x0300:
		std::cout << "< Server select response\n";
		break;
	case 0x1100:
		std::cout << "< Ping(loginscreen)\n";
		break;
	case 0x0A00:
		std::cout << "< Channel info)\n";
		break;
	case 0x0B00:
		std::cout << "< Character login screen info)\n";
		break;
	case 0x0D00:
		std::cout << "< Name availability info\n";
		break;
	case 0x0F00:
		std::cout << "< Confirm delete character\n";
		break;
	case 0x1600:
		std::cout << "> Quit game response\n";
		break;
	case 0x1A00:
		std::cout << "> Moveitem(itemid, lastslot, newslot)\n";
		break;
	case 0x1C00:
		std::cout << "< Multifunction confirm response\n";
		break;
	case 0x2100:
		std::cout << "< Skill level update\n";
		break;
	case 0x2400:
		std::cout << "< Receive item in inventory\n";
		break;
	case 0x3A00:
		std::cout << "< Player profile data\n";
		break;
	case 0x4100:
		std::cout << "< Chat notice\n";
		break;
	case 0x4A00:
		std::cout << "< Reminder notice\n";
		break;
	case 0x5400:
		std::cout << "< Cloud player message\n";
		break;
	case 0x7800:
		std::cout << "< Character info(when appearing)\n";
		break;
	case 0x7900:
		std::cout << "< Character disappears\n";
		break;
	case 0x7A00:
		std::cout << "< Chatmessage\n";
		break;
	case 0x8D00:
		std::cout << "< Other player position/state update\n";
		break;
	case 0x8E00:
		std::cout << "< Other player using attack/skill\n";
		break;
	case 0x9500:
		std::cout << "< Other player show emote\n";
		break;
	case 0x9800:
		std::cout << "< Other player change equipment\n";
		break;
	case 0x9900:
		std::cout << "< Other player level up\n";
		break;
	case 0xA000:
		std::cout << "< Leave chair response\n";
		break;
	case 0xA900:
		std::cout << "< Character balloon message(e.g. you haven't voted...)\n";
		break;
	case 0xAF00:
		//std::cout << "< ???\n";
		break;
	case 0xB000:
		//std::cout << "< Enemy dead/alive update\n";
		break;
	case 0xB200:
		//std::cout << "< Enemy position/state update\n";
		break;
	case 0xB300:
		//std::cout << "< Enemy clock? update\n";
		break;
	case 0xBD00:
		std::cout << "< Enemy health update\n";
		break;
	case 0xC500:
	    //std::cout << "< Keepalive\n";
		break;
	case 0xCE00:
		std::cout << "< Player picks up item\n";
		break;
	case 0xCD00:
		std::cout << "< Item drops\n";
		break;
	case 0xED00:
		std::cout << "< NPC menu data\n";
		break;
	case 0xF500:
		std::cout << "< Playerstore->\n";
		break;
	default:
		std::cout << "< ";
		couthex(packet, size);
		std::cout << "\n";
	}
}


__declspec(naked) void callback_sendpacket()
{
	__asm {
		pushad;
		nop;
		nop;
		nop;
		mov eax, esp;
		add eax, 0x20;  //restore to original esp
		mov eax, [eax + 0x4]
		push [eax + 0x4];
		push [eax + 0x8]
		call filter_sendpacket
		popad;
		mov eax, 0x00896984;
		magic_return_jump;
	}

}



__declspec(naked) void callback_recvpacket()
{
	__asm {
		pushad;
		nop;
		nop;
		nop;
		mov eax, esp;
		add eax, 0x20;  //restore to original esp
		push[eax + 0x8];
		push[eax + 0xC];
		call filter_recvpacket;
		popad;
		
		//original code
		pop esi;
		pop ebx;
		leave;
		retn 4;
	}

}



//------------------------------------------------------------------------

HookLoader::HookLoader() : locSendPacket("4751B2"),  
					locRecvPacket("60124E")
{
	if (locSendPacket.Resolve()) {
		hook(locSendPacket.Address, locSendPacket.Address + 5, callback_sendpacket, true);
	}

	if (locRecvPacket.Resolve()) {
		hook(locRecvPacket.Address, 0, callback_recvpacket, true);
	}
};

void HookLoader::Unload() {
	if (locSendPacket.Address != NULL) {
		unhook(locSendPacket.Address);
	}

	if (locRecvPacket.Address != NULL) {
		unhook(locRecvPacket.Address);
	}
};