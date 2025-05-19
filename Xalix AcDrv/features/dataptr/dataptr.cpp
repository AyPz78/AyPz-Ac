#include "dataptr.h"


bool dataptr::IsAddressInsideModule(PVOID address, PVOID module_base, SIZE_T module_size) 
{
    return (reinterpret_cast<uint64_t>(address) >= reinterpret_cast<uint64_t>(module_base)) &&
        (reinterpret_cast<uint64_t>(address) < reinterpret_cast<uint64_t>(module_base) + module_size);
}

bool dataptr::DetectDataPtr(const char* module, const char* pattern)
{
    PVOID  module_base = (PVOID)module_instance->Internal_GetSystemModuleBase(module);
    if (!module_base) {
	    return false;
    }

   SIZE_T module_size = module_instance->Internal_GetSystemModuleSize(module);
   
   PVOID address =  scan_instance->FindPattern((PVOID)module_base, pattern);
   if (!address) {
       return false;
   }

    if (!IsAddressInsideModule((PVOID)address, module_base, module_size)) {
        DbgPrintEx(0, 0, "[!] Suspicious function pointer detected! Address outside Module: %p\n", (void*)address);
		return true;
    }
    else {
        DbgPrintEx(0, 0, "[+] Function pointer is valid.\n");
    }

	return false;
}

bool dataptr::Loop_DetectDataPtr(const char* module)
{
    for (int i = 0; i < sizeof(DataPtrPattern) / sizeof(DataPtrPattern[0]); i++)
    {


        if (DetectDataPtr(module, DataPtrPattern[i]))
        {
            DbgPrintEx(0, 0, "[!] Data pointer detected!\n");
            return true;
        }

    }
	return false;
}