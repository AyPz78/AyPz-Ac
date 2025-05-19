#include "../includes.h"


void MainThread()
{
    if (mem::find_driver()) std::cout << "[+] Driver Found\n";
	else std::cout << "[+] Driver Not Found\n";
        
    mem::process_id = GetCurrentProcessId();
	printf("[+] Process ID: %d\n", mem::process_id);

	uintptr_t base = mem::find_image("RustClient.exe");//in this function if you want to do something with another function change the process id cuz we use the process where we are located
	printf("[+] Base Address: %p\n", base);

	uintptr_t test_read = driver.rpm<uintptr_t>(base);
	printf("[+] Read Base Address: %p\n", test_read);

	uintptr_t system_base = mem::GetSystemModuleBase("win32kbase.sys");
	printf("[+] System Base Address: %p\n", system_base);

	mem::protect_process(mem::process_id);//this function will avoid HANDLE with PROCESS_ALL_ACCESS


    //we can easily add ++count of flags 
    while (true)
    {
        if (dbg_tool->dtc_peb())//can be useless if manual mapping but some retard can use this 
        {
			printf("[+] Debugger Detected By Peb\n");
			Sleep(1000);
		}
        if (dbg_tool->rwx_check())//so can be cool if i add some check
        {
			printf("[+] RWX Memory Detected\n");
			Sleep(1000);
        }
       
		if (crc_tool->check_text_integrity(L"RustClient.exe"))// can be used to detect some hook of external overlay they dont do shadow  vmt hook so..
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
    printf("Xalix Ac Loaded \n");

	CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, nullptr, 0, nullptr);

    return TRUE;
}