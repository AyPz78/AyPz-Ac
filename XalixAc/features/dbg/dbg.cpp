#include "dbg.h"

bool dbg::dtc_peb()
{
    if (auto peb = reinterpret_cast<PEB*>(reinterpret_cast<TEB*> (__readgsqword(0x30))->ProcessEnvironmentBlock)->BeingDebugged)
    {
        return true;

    }
    return false;
}
bool dbg::rwx_check()
{
    MEMORY_BASIC_INFORMATION mbi;//use this class to get more information to avoid fake positives
    unsigned char* address = nullptr;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) //I will advise you to add some check ^^
        {
            return true;
        }
        address += mbi.RegionSize;
    }
    return false;
}
bool dbg::suspicious_dll()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;
	MODULEENTRY32W moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);
	if (Module32FirstW(hSnapshot, &moduleEntry))
	{
		do
		{
			for (const auto& dll : suspicious_dlls)
			{
				if (_wcsicmp(moduleEntry.szModule, std::wstring(dll.begin(), dll.end()).c_str()) == 0)
				{
					CloseHandle(hSnapshot);
					return true;
				}
			}
		} while (Module32NextW(hSnapshot, &moduleEntry));
	}
	CloseHandle(hSnapshot);
	return false;
}
bool dbg::detect_plaintext_strings()
{
 
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    unsigned char* addr = reinterpret_cast<unsigned char*>(sysInfo.lpMinimumApplicationAddress);
    unsigned char* maxAddr = reinterpret_cast<unsigned char*>(sysInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < maxAddr)
    {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)))
        {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                try
                {
                    for (size_t i = 0; i < mbi.RegionSize - 256; ++i) // scan par blocs de 256 octets
                    {
                        char* region = reinterpret_cast<char*>(addr + i);

                        for (const auto& keyword : suspicious_strings)
                        {
                            if (memcmp(region, keyword.c_str(), keyword.size()) == 0)
                            {
                                std::cout << "[!] Suspicious string found: " << keyword << " at 0x" << std::hex << (uintptr_t)(region) << "\n";
                                return true;
                            }
                        }
                    }
                }
                catch (...) {
                    // Ignore pages protégées illisibles
                }
            }

            addr += mbi.RegionSize;
        }
        else {
            addr += 0x1000;
        }
    }

    return false;
}


