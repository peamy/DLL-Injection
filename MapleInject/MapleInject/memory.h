#pragma once

#include "stdafx.h"

class Locator {
private:
	std::string locstr;

public:
	DWORD Address;
	Locator(char * loc_str);
	bool Resolve();
};
