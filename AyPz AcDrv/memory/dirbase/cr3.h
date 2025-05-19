#pragma once
#include "../../includes.h"

class cr3
{
	public:
		PVOID GetProcessCr3(const PEPROCESS hprocess);
};

inline cr3* cr3_instance;

