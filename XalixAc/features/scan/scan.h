#pragma once
#include "../../includes.h"
class scan
{
	private:
		//we can push this from server
		const char* SuspicousSig[2] =
		{
			"",
			"",
		};

	public:
		inline std::vector<int> PatternToBytes(const char* pattern);
		inline BYTE getByte(const char* pattern);
		inline uintptr_t FindPattern(const wchar_t* moduleName, const char* pattern);
		inline PVOID  FindPatternInRange(uintptr_t start, uintptr_t end, const char* pattern);
		inline bool Check_Suspicous(uintptr_t start, uintptr_t end);
};

