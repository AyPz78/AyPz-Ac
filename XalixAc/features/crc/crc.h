#pragma once
#include "../../includes.h"
class crc
{
	public:
	bool check_text_integrity(const wchar_t* moduleName);
	bool is_function_hooked(uintptr_t modulebase,uintptr_t function);
};
inline crc* crc_tool;

