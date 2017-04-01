#pragma once

#include "memory.h"


class HookLoader {
private:
	Locator locSendPacket;
	Locator locRecvPacket;
public:
	HookLoader();
	void Unload();
};
