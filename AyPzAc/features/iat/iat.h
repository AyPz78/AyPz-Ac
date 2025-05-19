#pragma once
#include "../../includes.h"

class IAT
{
public:
	static LPVOID Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction, LPCSTR lpTargetModuleName);
	static LPVOID Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction);
private:
	static LPVOID GetCurrentProcessModule();
};
inline IAT* iat_tool;

