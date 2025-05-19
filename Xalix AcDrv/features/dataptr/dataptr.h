#pragma once
#include "../../includes.h"

class dataptr
{
private:
		
	const char* DataPtrPattern[1] = 
	{
		"48 8B 05 ? ? ? ? 45 8B D9 85 C0 74 ? 4C 8B 4C 24 ? 44 8B 94",
	};

	public:

		bool IsAddressInsideModule(PVOID address, PVOID module_base, SIZE_T module_size);
		bool DetectDataPtr(const char* module, const char* pattern);
		bool Loop_DetectDataPtr(const char* module);

};
inline dataptr* dataptr_instance;