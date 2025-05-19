#pragma once
#include "../includes.h"
class memory
{
	public:
	HANDLE hProcess = nullptr;
	DWORD processId = 0;
	uintptr_t baseAddress = 0;

	//find process id
	inline DWORD GetProcessId(const wchar_t* processName);

	//scanning
	inline std::vector<int> PatternToBytes(const char* pattern);
	inline uintptr_t FindPattern(const wchar_t* moduleName, const char* pattern);
};

