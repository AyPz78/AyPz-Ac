#include "../includes.h"


void MainThread()
{
    if (mem::find_driver())
    {
		std::cout << "[+] Driver Found\n";
	}
    else
    {
        std::cout << "[+] Driver Not Found\n";
        
    }
    mem::process_id = GetCurrentProcessId();
	printf("[+] Process ID: %d\n", mem::process_id);

	uintptr_t base = mem::find_image("RustClient.exe");
	printf("[+] Base Address: %p\n", base);

	uintptr_t test_read = driver.rpm<uintptr_t>(base);
	printf("[+] Read Base Address: %p\n", test_read);

	uintptr_t system_base = mem::GetSystemModuleBase("win32kbase.sys");
	printf("[+] System Base Address: %p\n", system_base);
	mem::protect_process(mem::process_id);


    while (true)
    {
        if (dbg_tool->dtc_peb())
        {
			printf("[+] Debugger Detected By Peb\n");
			Sleep(1000);
		}
        if (dbg_tool->rwx_check())
        {
			printf("[+] RWX Memory Detected\n");
			Sleep(1000);
        }
       
		if (crc_tool->check_text_integrity(L"RustClient.exe"))
		{
			printf("[+] .text section has been modified!\n");
			Sleep(1000);
		}

    }
	
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD AttachReason, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);
    if (AttachReason != DLL_PROCESS_ATTACH)
        return FALSE;

    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    std::cout << "[+] Xalix Ac Loaded\n";

	CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, nullptr, 0, nullptr);

    return TRUE;
}