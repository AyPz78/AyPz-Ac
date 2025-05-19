#pragma once
#include "../../includes.h"
class scan
{
public:
	PBYTE PatternScanEx(PVOID Module, DWORD Size, LPCSTR Pattern, LPCSTR Mask);
	PBYTE PatternScan(PVOID Module, LPCSTR Pattern, LPCSTR Mask);
	void ParseIdaSig(const char* idaSig, PUCHAR pattern, PUCHAR mask, size_t& outLen);
	PBYTE PatternScanIDA(PVOID Base, DWORD Size, const char* idaSig);
	PBYTE FindPattern(PVOID ModuleBase, const char* idaSig);
};
inline scan* scan_instance;

