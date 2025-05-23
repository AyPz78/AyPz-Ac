#include "iat.h"
#include <Psapi.h>
#include <strsafe.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
LPVOID IAT::GetCurrentProcessModule()
{
	char lpCurrentModuleName[MAX_PATH];

	char lpImageName[MAX_PATH];

	GetProcessImageFileNameA(GetCurrentProcess(), lpImageName, MAX_PATH);

	MODULEENTRY32 ModuleList{};
	ModuleList.dwSize = sizeof(ModuleList);

	const HANDLE hProcList = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if (hProcList == INVALID_HANDLE_VALUE)
		return nullptr;

	if (!Module32First(hProcList, &ModuleList))
		return nullptr;

	wcstombs_s(nullptr, lpCurrentModuleName, ModuleList.szModule, MAX_PATH);
	lpCurrentModuleName[MAX_PATH - 1] = '\0';

	if (StrStrIA(lpImageName, lpCurrentModuleName) != nullptr)
		return ModuleList.hModule;

	while (Module32Next(hProcList, &ModuleList))
	{
		wcstombs_s(nullptr, lpCurrentModuleName, ModuleList.szModule, MAX_PATH);
		lpCurrentModuleName[MAX_PATH - 1] = '\0';

		if (StrStrIA(lpImageName, lpCurrentModuleName) != nullptr)
			return ModuleList.hModule;
	}

	return nullptr;
}


LPVOID IAT::Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction, LPCSTR lpTargetModuleName)
{
	const HANDLE hModule = GetModuleHandleA(lpTargetModuleName);
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hModule);
	if (lpImageDOSHeader == nullptr)
		return nullptr;

	const auto lpImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	const IMAGE_DATA_DIRECTORY ImportDataDirectory = lpImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + ImportDataDirectory.VirtualAddress);

	while (lpImageImportDescriptor->Characteristics != 0)
	{
		const auto lpCurrentModuleName = (LPSTR)((DWORD_PTR)lpImageDOSHeader + lpImageImportDescriptor->Name);
		if (_stricmp(lpCurrentModuleName, lpModuleName) != 0)
		{
			lpImageImportDescriptor++;
			continue;
		}

		auto lpImageOrgThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImageDOSHeader + lpImageImportDescriptor->OriginalFirstThunk);
		auto lpImageThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImageDOSHeader + lpImageImportDescriptor->FirstThunk);

		while (lpImageOrgThunkData->u1.AddressOfData != 0)
		{
			if (lpImageOrgThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				lpImageThunkData++;
				lpImageOrgThunkData++;
				continue;
			}

			const auto lpImportData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImageDOSHeader + lpImageOrgThunkData->u1.AddressOfData);

			if (strcmp(lpFunctionName, lpImportData->Name) == 0)
			{
				DWORD dwJunk = 0;
				MEMORY_BASIC_INFORMATION mbi;

				VirtualQuery(lpImageThunkData, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
					return nullptr;

				const auto lpOrgFunction = (LPVOID)lpImageThunkData->u1.Function;

#if defined _M_IX86
				lpImageThunkData->u1.Function = (DWORD_PTR)lpFunction;
#elif defined _M_X64
				lpImageThunkData->u1.Function = (DWORD_PTR)lpFunction;
#endif

				if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwJunk))
					return lpOrgFunction;
			}

			lpImageThunkData++;
			lpImageOrgThunkData++;
		}

		lpImageImportDescriptor++;
	}

	return nullptr;
}


LPVOID IAT::Hook(LPCSTR lpModuleName, LPCSTR lpFunctionName, const LPVOID lpFunction)
{
	const LPVOID hModule = GetCurrentProcessModule();
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hModule);
	if (lpImageDOSHeader == nullptr)
		return nullptr;
	printf("[+] IAT::Hook : %s\n", lpModuleName);
	const auto lpImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	printf("[+] IAT::Hook : %s\n", lpImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	const IMAGE_DATA_DIRECTORY ImportDataDirectory = lpImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + ImportDataDirectory.VirtualAddress);
	printf("[+] IAT::Hook : %s\n", lpImageImportDescriptor->Characteristics);

	while (lpImageImportDescriptor->Characteristics != 0)
	{
		const auto lpCurrentModuleName = (LPSTR)((DWORD_PTR)lpImageDOSHeader + lpImageImportDescriptor->Name);
		printf("[+] IAT::Hook : %s\n", lpCurrentModuleName);
		if (_stricmp(lpCurrentModuleName, lpModuleName) != 0)
		{
			lpImageImportDescriptor++;
			continue;
		}

		auto lpImageOrgThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImageDOSHeader + lpImageImportDescriptor->OriginalFirstThunk);
		auto lpImageThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImageDOSHeader + lpImageImportDescriptor->FirstThunk);
		printf("[+] IAT::Hook : %s\n", lpImageOrgThunkData->u1.AddressOfData);
		while (lpImageOrgThunkData->u1.AddressOfData != 0)
		{
			if (lpImageOrgThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				lpImageThunkData++;
				lpImageOrgThunkData++;
				continue;
			}

			const auto lpImportData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImageDOSHeader + lpImageOrgThunkData->u1.AddressOfData);

			if (strcmp(lpFunctionName, lpImportData->Name) == 0)
			{
				DWORD dwJunk = 0;
				MEMORY_BASIC_INFORMATION mbi;

				VirtualQuery(lpImageThunkData, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
					return nullptr;

				const auto lpOrgFunction = (LPVOID)lpImageThunkData->u1.Function;

#if defined _M_IX86
				lpImageThunkData->u1.Function = (DWORD_PTR)lpFunction;
#elif defined _M_X64
				lpImageThunkData->u1.Function = (DWORD_PTR)lpFunction;
#endif

				if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwJunk))
					return lpOrgFunction;
			}

			lpImageThunkData++;
			lpImageOrgThunkData++;
		}

		lpImageImportDescriptor++;
	}

	return nullptr;
}