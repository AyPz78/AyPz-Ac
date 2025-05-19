#include "module.h"

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    // Autres champs...
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    void* Section;
    void* MappedBase;
    void* ImageBase;
    unsigned long ImageSize;
    unsigned long Flags;
    unsigned short LoadOrderIndex;
    unsigned short InitOrderIndex;
    unsigned short LoadCount;
    unsigned short OffsetToFileName;
    unsigned char  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
    unsigned long NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

NTSTATUS module::GetPeb(ppeb request, PVOID* peb_address) {
    PEPROCESS target_process;

    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)request->proc_id, &target_process);
    if (NT_SUCCESS(status)) {
        *peb_address = (PVOID)PsGetProcessPeb(target_process);
        ObDereferenceObject(target_process);
        return STATUS_SUCCESS;
    }
    else {
        return status;
    }
}

void* module::GetProcessModuleBase(PEPROCESS process, UNICODE_STRING module_name)
{
    if (!process)
        return nullptr;

    PPEB ppeb = PsGetProcessPeb(process);
    if (!ppeb)
        return nullptr;

    KAPC_STATE state;
    KeStackAttachProcess(process, &state);
    PPEB_LDR_DATA pldr = ppeb->Ldr;

    if (!pldr)
    {
        KeUnstackDetachProcess(&state);
        return nullptr;
    }

    PVOID result = nullptr;
    for (PLIST_ENTRY p_list_entry = pldr->InLoadOrderModuleList.Flink; p_list_entry != &pldr->InLoadOrderModuleList; p_list_entry = p_list_entry->Flink)
    {
        if (!p_list_entry)
            continue;

        PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(p_list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (RtlCompareUnicodeString(&module_entry->BaseDllName, &module_name, TRUE) == 0)
        {
            result = module_entry->DllBase;
            break;
        }
    }

    KeUnstackDetachProcess(&state);
    return result;
}

NTSTATUS module::FindBaseAddress(pba x)
{
  
    if (x->security != CODE_SECURITY)
        return STATUS_UNSUCCESSFUL;

    if (!x->process_id)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS target_process;

    ANSI_STRING ansi_string;
    UNICODE_STRING module_name;

    RtlInitAnsiString(&ansi_string, x->module_name);
    NTSTATUS status = RtlAnsiStringToUnicodeString(&module_name, &ansi_string, TRUE);
    if (!NT_SUCCESS(status)) {

        return status;
    }

    status = PsLookupProcessByProcessId((HANDLE)x->process_id, &target_process);
    if (!NT_SUCCESS(status)) {

        RtlFreeUnicodeString(&module_name);
        return status;
    }

    PVOID image_base = GetProcessModuleBase(target_process, module_name);
    if (!image_base) {

        ObDereferenceObject(target_process);
        RtlFreeUnicodeString(&module_name);
        return STATUS_UNSUCCESSFUL;
    }

    RtlCopyMemory(x->address, &image_base, sizeof(image_base));
    ObDereferenceObject(target_process);
    RtlFreeUnicodeString(&module_name);

    return STATUS_SUCCESS;
}


auto get_system_information(const SYSTEM_INFORMATION_CLASS information_class) -> const void*
{
    unsigned long size = 32;
    char buffer[32];

    ZwQuerySystemInformation(information_class, buffer, size, &size);

    const auto info = ExAllocatePool(NonPagedPool, size);

    if (!info)
    {
        return nullptr;
    }

    if (ZwQuerySystemInformation(information_class, info, size, &size) != STATUS_SUCCESS)
    {
        ExFreePool(info);
        return nullptr;
    }

    return info;
}
unsigned long long module::GetSystemModuleBase(PMODULE request)
{
    unsigned long info = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);
    if (!info)
        return 0;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 'tran');
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);
    if (!NT_SUCCESS(status))
        return 0;

    void* module_base = 0;
    PRTL_PROCESS_MODULE_INFORMATION current_module = modules->Modules;
    if (modules->NumberOfModules > 0)
    {
        if (request->module_name)
        {
            for (auto i = 0; i < modules->NumberOfModules; i++)
            {
                if (!strcmp((CHAR*)current_module[i].FullPathName, request->module_name))
                    module_base = current_module[i].ImageBase;
            }
        }
        else
        {
            module_base = modules->Modules[0].ImageBase;
        }
    }
    if (modules)
        ExFreePoolWithTag(modules, 'tran');

    return (unsigned long long)module_base;
}

unsigned long long module::Internal_GetSystemModuleBase(const char* module_name)
{
    unsigned long info = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);
    if (!info)
        return 0;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 'tran');
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);
    if (!NT_SUCCESS(status))
        return 0;

    void* module_base = 0;
    PRTL_PROCESS_MODULE_INFORMATION current_module = modules->Modules;
    if (modules->NumberOfModules > 0)
    {
        if (module_name)
        {
            for (auto i = 0; i < modules->NumberOfModules; i++)
            {
                if (!strcmp((CHAR*)current_module[i].FullPathName,module_name))
                    module_base = current_module[i].ImageBase;
            }
        }
        else
        {
            module_base = modules->Modules[0].ImageBase;
        }
    }
    if (modules)
        ExFreePoolWithTag(modules, 'tran');

    return (unsigned long long)module_base;
}

SIZE_T module::Internal_GetSystemModuleSize(const char* module_name)
{
	unsigned long info = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);
	if (!info)
		return 0;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 'tran');

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);
	if (!NT_SUCCESS(status))
		return 0;

	size_t module_size = 0;
	PRTL_PROCESS_MODULE_INFORMATION current_module = modules->Modules;
	if (modules->NumberOfModules > 0)
	{
		if (module_name)
		{
			for (auto i = 0; i < modules->NumberOfModules; i++)
			{
				if (!strcmp((CHAR*)current_module[i].FullPathName, module_name))
					module_size = current_module[i].ImageSize;
			}
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, 'tran');
    
    return module_size;
}
